# -*- coding: utf-8 -*-
r"""
Manage Local Policy Group Policy Objects on Windows.

This module uses ``Apply_LGPO_Delta.exe``, the license for which restricts it
from being distributed by a third-party application. According to Microsoft[1],
users must obtain it from the site below[2] and may then distribute it within
their own organization.

[1] https://blogs.technet.microsoft.com/fdcc/2010/03/24/sample-files-for
-apply_lgpo_delta/#comment-163
[2] https://blogs.technet.microsoft.com/fdcc/2010/01/15/updated-lgpo-utility
-sources/

:maintainer: Loren Gordon <loren.gordon@plus3it.com>
:depends:    Apply_LGPO_Delta.exe in %SystemRoot%\System32\
:platform:   Windows
"""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals, with_statement)

import collections
import logging
import io
import os
import re

from salt.exceptions import CommandExecutionError, SaltInvocationError
from salt.modules.win_lgpo import HAS_WINDOWS_MODULES

try:
    from salt.utils.files import mkstemp
except ImportError:
    from salt.utils import mkstemp

try:
    from salt.utils.platform import is_windows
except ImportError:
    from salt.utils import is_windows

log = logging.getLogger(__name__)
__virtualname__ = 'ash_lgpo'

if HAS_WINDOWS_MODULES:
    import struct
    import win32security

    import salt.utils.files

    from salt.modules.win_lgpo import (
        _policy_info, _transform_value, _read_regpol_file, _write_regpol_data,
        _regexSearchRegPolData,
    )

    from salt.ext import six
    from salt.utils.functools import namespaced_function as _namespaced_function
    from salt.utils.stringutils import to_num
    from salt.utils.win_reg import Registry

    POLICY_INFO = _policy_info()
    REGPOL_MACHINE = POLICY_INFO.admx_registry_classes['Machine']['policy_path']
    REGPOL_USER = POLICY_INFO.admx_registry_classes['User']['policy_path']


class PolicyHelper(object):
    """Helper class to manage Local Group Policy Objects."""

    def __init__(self):
        """Initialize PolicyHelper class."""
        self.LGPO_VTYPE_KEYS = ['key', 'value', 'vtype']
        self.LGPO_ACTION_KEYS = ['key', 'action']
        self.LGPO_SECEDIT_KEYS = ['name', 'value']
        self.REGISTRY_MAP = {
            'actions': {
                'DELETE': 'DELETE',
            },
            'vtypes': {
                'DWORD': 'REG_DWORD',
                'REG_DWORD': 'REG_DWORD',
                'SZ': 'REG_SZ',
                'REG_SZ': 'REG_SZ',
            },
            'hives': {
                'COMPUTER': 'Machine',
                'HKLM': 'Machine',
                'MACHINE': 'Machine',
                'HKEY_LOCAL_MACHINE': 'Machine',
                'USER': 'User',
                'HKCU': 'User',
                'HKEY_CURRENT_USER': 'User',
            },
        }
        self.SECEDIT_MAP = {
            'MINIMUMPASSWORDAGE': {
                'type': 'NetUserModal',
                'name': 'MinPasswordAge',
            },
            'MAXIMUMPASSWORDAGE': {
                'type': 'NetUserModal',
                'name': 'MaxPasswordAge',
            },
            'MINIMUMPASSWORDLENGTH': {
                'type': 'NetUserModal',
                'name': 'MinPasswordLen',
            },
            'PASSWORDHISTORYSIZE': {
                'type': 'NetUserModal',
                'name': 'PasswordHistory',
            },
            'LOCKOUTBADCOUNT': {
                'type': 'NetUserModal',
                'name': 'LockoutThreshold',
            },
            'RESETLOCKOUTCOUNT': {
                'type': 'NetUserModal',
                'name': 'LockoutWindow',
            },
            'LOCKOUTDURATION': {
                'type': 'NetUserModal',
                'name': 'LockoutDuration',
            },
        }
        self.SECEDIT_POLICIES = {
            policy: details for policy, details
            in POLICY_INFO.policies['Machine']['policies'].items()
            if 'Registry' not in details
            and 'Registry Values' != details.get('Secedit', {}).get('Section')
        }
        self.SECEDIT_POLICY_KEYS = {
            key.upper(): key for key in self.SECEDIT_POLICIES
        }

    def _regpol_hive(self, hive):
        try:
            return self.REGISTRY_MAP['hives'][hive.upper()]
        except KeyError:
            pass
        return None

    def _regpol_key(self, key):
        try:
            pattern = re.compile(r'\\+(?=(?:[^"]*"[^"]*")*[^"]*$)')
            key_ = pattern.split(key)
            hive = self._regpol_hive(key_[0])
            key_path = '\\'.join(key_[1:-1])
            vname = key_[-1].strip('"')
            return hive, key_path, vname
        except AttributeError:
            pass
        return None, None, None

    def _regpol_vtype(self, vtype):
        try:
            return self.REGISTRY_MAP['vtypes'][vtype.upper()]
        except KeyError:
            pass
        return None

    def _regpol_action(self, action):
        try:
            return self.REGISTRY_MAP['actions'][action.upper()]
        except KeyError:
            pass
        return None

    def _key_path_picker(self, key_path, vname, action):
        if not action or action in ['DELETE']:
            # Action is setvalue or delete
            return key_path
        # Action is deleteallkeys or createkey
        return '\\'.join([key_path, vname])

    def _vname_picker(self, vname, action):
        if not action or action in ['DELETE']:
            # Action is setvalue or delete
            return vname
        # Action is deleteallkeys or createkey
        return '*'

    def _action_picker(self, vtype, value, action):
        return action if action else '{0}:{1}'.format(vtype, value)

    def validate_regpol(self, policy):
        """Validate regpol policy."""
        if (
            not all(key in policy for key in self.LGPO_VTYPE_KEYS) and
            not all(key in policy for key in self.LGPO_ACTION_KEYS)
        ):
            return False, 'Registry policy dictionary is malformed'
        hive, key_path, vname = self._regpol_key(policy.get('key', ''))
        value = str(policy.get('value', '')).replace('\\\\', '\\')
        vtype = self._regpol_vtype(policy.get('vtype', ''))
        action = self._regpol_action(policy.get('action', ''))
        if not key_path:
            return (False, 'Value of "key" is malformed, it must contain the '
                           '"hive" and the path to the registry key or '
                           'registry value')
        if not hive:
            return (False, 'Value of "hive" (the first token in "key") is '
                           'invalid')
        if policy.get('vtype') and not vtype:
            return False, 'Value of "vtype" is invalid'
        if policy.get('action') and not action:
            return False, 'Value of "action" is invalid'
        if vtype and action:
            return (False, 'Detected both "vtype" and "action", ensure only '
                           'one is present')
        return (
            {
                'hive': hive,
                'key_path': self._key_path_picker(key_path, vname, action),
                'vname': self._vname_picker(vname, action),
                'action': self._action_picker(vtype, value, action),
            },
            ''
        )

    def _secedit_transform(self, name, value):
        BAD_TRANSFORM_VALUES = ['Invalid Value']

        log.debug('secedit name [initial] = "%s"', name)
        log.debug('secedit value [initial] = "%s"; type = "%s"', value, type(value))

        if name.upper() in self.SECEDIT_MAP:
            # Transform GPO ini names to salt lgpo names
            name = self.SECEDIT_MAP[name.upper()]['name']
            log.debug('secedit name [transformed] = "%s"', name)
        elif name not in self.SECEDIT_POLICIES:
            # name is not an exact match
            if name.upper() in self.SECEDIT_POLICY_KEYS:
                # name is just a different case, transform to lgpo case
                name = self.SECEDIT_POLICY_KEYS[name.upper()]
                log.debug('secedit name [transformed] = "%s"', name)
            else:
                # search for name in secedit options of lgpo policy details
                for key, policy in self.SECEDIT_POLICIES.items():
                    if (
                        name.upper() == policy.get(
                            'Secedit', {}).get('Option', '').upper()
                    ):
                        # found it, set name to lgpo policy name
                        name = key
                        log.debug('secedit name [transformed] = "%s"', name)
                        break
                else:
                    # name is invalid, return none
                    return None, None

        # Get the value transform
        policy = self.SECEDIT_POLICIES[name]

        if 'NetUserModal' in policy:
            value = to_num(value)
            value = 0 if value == -1 else value
            log.debug(
                'secedit value [coerced] = "%s"; type = "%s"',
                value,
                type(value)
            )
        else:
            if 'LsaRights' in policy:
                try:
                    # Convert String SID to SID object
                    value = [
                        win32security.ConvertStringSidToSid(sid.lstrip('*'))
                        for sid in value.split(',') if sid
                    ]
                except win32security.error:
                    # Convert account name to SID object
                    value = [
                        win32security.LookupAccountName('', account)[0]
                        for account in value.split(',') if account
                    ]
                log.debug(
                    'secedit value [coerced] = "%s"; type = "%s"',
                    value,
                    type(value)
                )

            value_ = _transform_value(
                value,
                policy,
                transform_type='Get',
            )
            value = value_ if value_ not in BAD_TRANSFORM_VALUES else value
            log.debug(
                'secedit value [transformed] = "%s"; type = "%s"',
                value,
                type(value)
            )

        return name, value

    def validate_secedit(self, policy):
        """Validate secedit policy."""
        if not all(key in policy for key in self.LGPO_SECEDIT_KEYS):
            return False, 'Secedit policy dictionary is malformed'
        name, value = self._secedit_transform(
            name=policy.get('name', ''),
            value=policy.get('value', ''),
        )
        if not name:
            return (
                False,
                'Secedit policy name "{0}" is unknown'
                .format(policy.get('name'))
            )
        return (
            {
                'name': name,
                'value': value
            },
            ''
        )

    def _reg_to_pol(self, policy, regpol):
        action = policy['action'].split(':')
        vtype, vdata = action[0], ':'.join(action[1:])

        kwargs = {
            'reg_key': policy['key_path'],
            'reg_valueName': policy['vname'],
            'reg_vtype': vtype,
            'reg_data': None if vdata == '' else vdata,
            'check_deleted': vtype == 'DELETE'
        }

        log.debug('converting policy to regpol search string = %s', kwargs)
        setting = _buildKnownDataSearchString(**kwargs)

        return _policyFileReplaceOrAppend(setting, regpol)

    def policy_object_regpol(self, policies, **kwargs):
        """Return a regpol policy object."""
        overwrite_regpol = kwargs.pop('overwrite_regpol', True)
        machine_regpol = b''
        user_regpol = b''

        if not overwrite_regpol:
            machine_regpol = _read_regpol_file(REGPOL_MACHINE) or b''

        if not overwrite_regpol:
            user_regpol = _read_regpol_file(REGPOL_USER) or b''

        policy_objects = {
            'Machine': machine_regpol,
            'User': user_regpol,
        }

        for policy in policies:
            policy_objects[policy['hive']] = self._reg_to_pol(
                policy,
                policy_objects[policy['hive']],
            )

        return policy_objects

    def policy_object_secedit(self, policies, **kwargs):
        """Return a secedit policy object."""
        return { policy['name']: policy['value'] for policy in policies }

def __virtual__():
    """Load only on Windows and only if Apply_LGPO_Delta is present."""
    if not is_windows():
        return False
    if not HAS_WINDOWS_MODULES:
        return (
            False,
            '{0}: Required modules failed to load'
            .format(__virtualname__)
        )

    global _write_regpol_data
    _write_regpol_data = _namespaced_function(_write_regpol_data, globals())

    return __virtualname__


def _policyFileReplaceOrAppend(policy, policy_data, append=True):
    '''
    helper function to take a ADMX policy string for registry.pol file data and
    update existing string or append the string to the data

    Cut from win_lgpo.py due to bugs when there are DELETE policies
    '''
    # token to match policy start = encoded [
    policy_start = re.escape('['.encode('utf-16-le'))

    # token to match policy end = encoded ]
    policy_end = re.escape(']'.encode('utf-16-le'))

    # token to match policy delimiter = encoded null + encoded semicolon
    policy_delimiter = b''.join([
        chr(0).encode('utf-16-le'),
        ';'.encode('utf-16-le'),
    ])

    # pattern group to OPTIONALLY match delete instructions in value token
    policy_pattern_del = b''.join([
        b'(',
        re.escape('**Del.'.encode('utf-16-le')),
        b'|',
        re.escape('**DelVals.'.encode('utf-16-le')),
        b'){0,1}',
    ])

    # pattern group to match one delimited token in a policy
    policy_token = b''.join([
        b'(',
        b'.*?',  # non-greedy match, up to next policy delimiter
        policy_delimiter,
        b')',
    ])

    # pattern to capture the key and value tokens from `policy`
    policy_pattern = b''.join([
        policy_start,
        policy_token, # this is the registry key
        policy_pattern_del,
        policy_token, # this is the value
        b'.*?',        # this is the remainder of the policy tokens
        policy_end,
    ])

    # parse the tokens from `policy`
    policy_match = re.search(
        policy_pattern,
        policy,
        flags=re.IGNORECASE|re.DOTALL,
    )

    # pattern to match `policy` in `policy_data`
    policy_match_groups = policy_match.groups()
    policy_data_pattern = b''.join([
        policy_start,
        re.escape(policy_match_groups[0]),  # key
        policy_pattern_del,
        re.escape(policy_match_groups[2]),  # value
        b'.*?',
        policy_end,
    ])

    # search for `policy` in `policy_data`
    policy_data_match = re.search(
        policy_data_pattern,
        policy_data,
        flags=re.IGNORECASE|re.DOTALL,
    )

    if policy_data_match:
        # replace a match with the policy
        policy_repl = policy_data_match.group()
        log.debug('replacing "%s" with "%s"', policy_repl, policy)
        return policy_data.replace(policy_repl, policy)
    elif append:
        # append the policy
        log.debug('appending "%s"', policy)
        return b''.join([policy_data, policy])
    else:
        # no match, no append, just return what we were given
        return policy_data


def _encode_string(value):
    '''Cut from win_lgpo.py due to bugs in _buildKnownDataSearchString.'''
    encoded_null = chr(0).encode('utf-16-le')
    if value is None:
        return encoded_null
    elif not isinstance(value, six.string_types):
        # Should we raise an error here, or attempt to cast to a string
        raise TypeError('Value {0} is not a string type\n'
                        'Type: {1}'.format(repr(value), type(value)))
    return b''.join([value.encode('utf-16-le'), encoded_null])


def _buildKnownDataSearchString(
    reg_key,
    reg_valueName,
    reg_vtype,
    reg_data,
    check_deleted=False
):
    '''
    Helper function to build a search string for a known key/value/type/data.

    Cut from win_lgpo.py due to bugs in empty reg_data values.
    '''
    registry = Registry()
    encoded_semicolon = ';'.encode('utf-16-le')
    encoded_null = chr(0).encode('utf-16-le')
    this_element_value = encoded_null
    if reg_key:
        reg_key = reg_key.encode('utf-16-le')
    if reg_valueName:
        reg_valueName = reg_valueName.encode('utf-16-le')
    if not check_deleted:
        if reg_vtype == 'REG_DWORD':
            this_element_value = struct.pack(b'I', int(reg_data))
        elif reg_vtype == "REG_QWORD":
            this_element_value = struct.pack(b'Q', int(reg_data))
        elif reg_vtype == 'REG_SZ':
            this_element_value = _encode_string(reg_data)
        return b''.join(['['.encode('utf-16-le'),
                                    reg_key,
                                    encoded_null,
                                    encoded_semicolon,
                                    reg_valueName,
                                    encoded_null,
                                    encoded_semicolon,
                                    chr(registry.vtype[reg_vtype]).encode('utf-32-le'),
                                    encoded_semicolon,
                                    six.unichr(len(this_element_value)).encode('utf-32-le'),
                                    encoded_semicolon,
                                    this_element_value,
                                    ']'.encode('utf-16-le')])
    else:
        reg_vtype = 'REG_SZ'
        return b''.join(['['.encode('utf-16-le'),
                                    reg_key,
                                    encoded_null,
                                    encoded_semicolon,
                                    '**Del.'.encode('utf-16-le'),
                                    reg_valueName,
                                    encoded_null,
                                    encoded_semicolon,
                                    chr(registry.vtype[reg_vtype]).encode('utf-32-le'),
                                    encoded_semicolon,
                                    six.unichr(len(' {0}'.format(chr(0)).encode('utf-16-le'))).encode('utf-32-le'),
                                    encoded_semicolon,
                                    ' '.encode('utf-16-le'),
                                    encoded_null,
                                    ']'.encode('utf-16-le')])


def validate_policies(policies):
    r"""
    Validate a policy to manage Local Group Policy Objects.

    Returns a tuple of (valid_policies, reason, policy).

    If any policy is invalid, ``valid_policies`` is ``False``, ``reason``
    contains a string explaining why the policy is invalid, and ``policy``
    contains the policy that failed validation.

    If all policies are valid, ``valid_policies`` is a dictionary of policy
    types, where each ``policy_type`` key contains a list of policy
    dictionaries that an be easily written to a file and executed with
    Apply_LGPO_Delta.exe. `reason`` will be an empty string, and ``policy``
    will be an empty dictionary.

    :param policies:
        A policy dictionary, or a list of policy dictionaries. Each policy
        dictionary must be of one of the forms below:
            {
                'policy_type' : 'regpol',
                'key'    : '<hive>\path\to\registry\key\value_name',
                'value'  : 'value of the registry key',
                'vtype'  : 'DWORD' | 'SZ'
            }
        -OR-
            {
                'policy_type' : 'regpol',
                'key'    : '<hive>\path\to\registry\key\name',
                'action' : 'DELETE'
            }
        -OR-
            {
                'policy_type' : 'secedit',
                'name'   : 'name of the secedit inf setting',
                'value'  : 'value to apply to the setting'
            }
        Policy dictionaries support the same aliases as the individual policy
        parameters. See ``ash_lgpo.set_registry_value`` for the aliases.

    CLI Examples:

    .. code-block:: bash

        policies="[{'policy_type':'regpol', \
            'key':'HKLM\Software\Salt\Policies\Foo', \
            'value':'0', \
            'vtype':'DWORD'}]"
        salt '*' ash_lgpo.validate_policies policies="${policies}"
    """
    ret = {}
    policy_helper = PolicyHelper()
    if not isinstance(policies, collections.Sequence):
        policies = [policies]
    for policy in policies:
        if not isinstance(policy, collections.Mapping):
            return False, 'Policy is not a dictionary object', policy
        policy_type = policy.get('policy_type', '').lower()
        try:
            result, reason = getattr(policy_helper, 'validate_{0}'
                                        .format(policy_type))(policy)
        except AttributeError:
            return (False,
                    '`policy_type` is missing or the value "{0}" is invalid'
                    .format(policy_type),
                    policy)
        if not result:
            return False, reason, policy
        try:
            ret[policy_type].append(result)
        except KeyError:
            ret[policy_type] = [result]
    return ret, '', {}


def _get_policy_objects(policies, **kwargs):
    policy_objects = {}
    policy_helper = PolicyHelper()
    for policy_type, policy_data in policies.items():
        policy_objects[policy_type] = getattr(
            policy_helper,
            'policy_object_{0}'.format(policy_type))(policy_data, **kwargs)
    return policy_objects


def apply_policies(policies, overwrite_regpol=False):
    r"""
    Apply a policy that manages Local Group Policy Objects.

    :param policies:
        A policy dictionary, or a list of policy dictionaries. Each policy
        dictionary must be of one of the forms below:
            {
                'policy_type' : 'regpol',
                'key'    : '<hive>\path\to\registry\key\value_name',
                'value'  : 'value of the registry key',
                'vtype'  : 'DWORD' | 'SZ'
            }
        -OR-
            {
                'policy_type' : 'secedit',
                'name'   : 'name of the secedit inf setting',
                'value'  : 'value to apply to the setting'
            }
        Policy dictionaries support the same aliases as the individual policy
        parameters. See ``ash_lgpo.set_registry_value`` for the aliases.

    :param overwrite_regpol:
        When ``False`` (the default), read the registry.pol if it exists
        and update it with the specified policies. When ``True``, specified
        policies will wholly overwrite an existing registry.pol file.

    CLI Examples:

    .. code-block:: bash

        policies="[{'policy_type':'regpol', \
            'key':'HKLM\Software\Salt\Policies\Foo', \
            'value':'0', \
            'vtype':'DWORD'}]"
        salt '*' ash_lgpo.apply_policies policies="${policies}"
    """
    valid_policies, reason, policy = validate_policies(policies)
    if not valid_policies:
        raise SaltInvocationError('{0}; policy={1}'.format(reason, policy))

    policy_objects = _get_policy_objects(
        valid_policies,
        overwrite_regpol=overwrite_regpol
    )

    # Apply regpol policies
    has_regpol = False
    for regclass, regpol in policy_objects.get('regpol', {}).items():
        _write_regpol_data(
            regpol,
            POLICY_INFO.admx_registry_classes[regclass]['policy_path'],
            POLICY_INFO.gpt_ini_path,
            POLICY_INFO.admx_registry_classes[regclass]['gpt_extension_location'],
            POLICY_INFO.admx_registry_classes[regclass]['gpt_extension_guid']
        )
        has_regpol = True if regpol else has_regpol

    # Apply secedit policies
    __salt__['lgpo.set'](
        computer_policy=policy_objects.get('secedit', {}),
        cumulative_rights_assignments=False,
    )

    # Trigger gpupdate to create registry entries from regpol
    if has_regpol:
        _ = __salt__['cmd.retcode']('gpupdate')

    return valid_policies


def construct_policy(mode, name, value='', vtype=''):
    """Map the mode and return a list containing the policy dictionary."""
    default = {
        'policy_type': 'unknown'
    }
    policy_map = {
        'set_reg_value': {
            'policy_type': 'regpol',
        },
        'delete_reg_value': {
            'policy_type': 'regpol',
            'action': 'DELETE'
        },
        'set_secedit_value': {
            'policy_type': 'secedit',
        },
    }
    mapped = policy_map.get(mode, default)
    mapped['key'] = name
    mapped['name'] = name
    mapped['value'] = value
    mapped['vtype'] = vtype
    return [mapped]


def set_reg_value(key, value, vtype):
    r"""
    Use a Local Group Policy Object to set to a registry value.

    If the key does not exist, it is created.

    :param key:
        Path to the registry setting managed by the policy. The path must be
        in the form: ``<hive>\path\to\registry\key\value_name``. ``<hive>``
        may be one of ``Computer`` or ``User``. ``<hive>`` also supports
        aliases the following aliases:
            'Computer'  : ['COMPUTER', 'HKLM', 'MACHINE', 'HKEY_LOCAL_MACHINE']
            'User'      : ['USER', 'HKCU', 'HKEY_CURRENT_USER']
        ``<hive>`` is case insensitive.
    :param value:
        Value to apply to the ``key``.
    :param vtype:
        Type of registry entry required for this policy. Valid types include
        ``DWORD``, or ``SZ``. These types also support the following
        aliases:
            'DWORD'     : ['DWORD', 'REGDWORD', 'REG_DWORD']
            'SZ'        : ['SZ', 'REGSZ', 'REG_SZ']
        ``vtype`` is case insensitive.

    CLI Examples:

    .. code-block:: bash

        salt '*' ash_lgpo.set_reg_value \
            key='HKLM\Software\Salt\Policies\Foo' \
            value='0' \
            vtype='DWORD'
        salt '*' ash_lgpo.set_reg_value \
            key='HKLM\Software\Salt\Policies\Bar' \
            value='baz' \
            vtype='SZ'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='set_reg_value',
            name=key,
            value=value,
            vtype=vtype
        ),
        overwrite_regpol=False,
    ))


def delete_reg_value(key):
    r"""
    Use a Local Group Policy Object to delete to a registry value.
    :param key:
        Path to the registry value to be removed by the policy. The path must
        be in the form: ``<hive>\path\to\registry\key\value_name``. ``<hive>``
        may be one of ``Computer`` or ``User``. ``<hive>`` also supports
        aliases the following aliases:
            'Computer'  : ['COMPUTER', 'HKLM', 'MACHINE', 'HKEY_LOCAL_MACHINE']
            'User'      : ['USER', 'HKCU', 'HKEY_CURRENT_USER']
        ``<hive>`` is case insensitive.
    CLI Examples:
    .. code-block:: bash
        salt '*' lgpo.delete_reg_value key='HKLM\Software\Salt\Policies\Foo'
        salt '*' lgpo.delete_reg_value key='HKLM\Software\Salt\Policies\Bar'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='delete_reg_value',
            name=key
        ),
    ))


def set_secedit_value(name, value):
    r"""
    Modify a "System Access" or "Privilege Rights" security policy.

    :param name:
        Name of the "System Access" or "Privilege Rights" policy to modify.
        Parameter is case-insensitive. To get a list of known policy names,
        use ``ash_lgpo.get_secedit_names``.
    :param value:
        Value to apply to the policy.

    CLI Examples:

    .. code-block:: bash

        salt '*' ash_lgpo.set_secedit_value name=MaximumPasswordAge value=60
        salt '*' ash_lgpo.set_secedit_value name=SeDenyServiceLogonRight \
            value=Guests
        salt '*' ash_lgpo.set_secedit_value name=SeDenyNetworkLogonRight \
            value='*S-1-5-32-546'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='set_secedit_value',
            name=name,
            value=value,
        ),
    ))


def list_secedit_policies(names=None, types=None, show_details=False):
    """
    Return all valid secedit policies by type and name.

    :param names:
        Names of the policies to output. If not provided, all valid policies
        will be listed.
    :param types:
        Types of policies to output. If not provided, all valid types will be
        listed.
    :param show_details:
        When ``False`` (the default), only policy names will be output. When
        ``True``, all policy details will be output. This can be helpful in
        determining what values a policy accepts.

    CLI Examples:

    .. code-block:: bash

        salt '*' ash_lgpo.list_secedit_policies
        salt '*' ash_lgpo.list_secedit_policies \
            names=AdminAccountStatus,SeDenyNetworkLogonRight
        salt '*' ash_lgpo.list_secedit_policies \
            types=Secedit,LsaRights
    """
    policies = {
        'Secedit': {
            'policy_keys': [
                'Secedit',
                'NetUserModal',
            ],
            'policies': [],
            'display_name': 'System Access',
        },
        'AdvAudit': {
            'policy_keys': [
                'AdvAudit',
            ],
            'policies': [],
            'display_name': 'Advanced Audit',
        },
        'LsaRights': {
            'policy_keys': [
                'LsaRights',
            ],
            'policies': [],
            'display_name': 'Privilege Rights',
        },
        'NetSH': {
            'policy_keys': [
                'NetSH',
            ],
            'policies': [],
            'display_name': 'NetSH',
        },
        'ScriptIni': {
            'policy_keys': [
                'ScriptIni',
            ],
            'policies': [],
            'display_name': 'Startup/Shutdown Scripts',
        },
        'Other': {
            'policy_keys': [],
            'policies': [],
            'display_name': 'Other',
        },
    }

    secedit_policies = PolicyHelper().SECEDIT_POLICIES
    names = names or []
    types = types or policies.keys()

    # Coerce names and types to lists
    if isinstance(names, six.text_type):
        names = names.split(',')
    if isinstance(types, six.text_type):
        types = types.split(',')

    for name, policy in secedit_policies.items():
        # Skip any names not requested
        if names and name not in names:
            continue

        for type_ in policies.keys():
            # Map known lgpo policy types to their respective policies key
            keys = policies[type_]['policy_keys']
            if keys and any([key in policy for key in keys]):
                policies[type_]['policies'].append(
                    name if not show_details else {name: policy}
                )
                break
        else:
            # Map unknown lgpo policy types to the 'Other' key
            policies['Other']['policies'].append({name: policy})

    # Create map of requested types and policy names
    return {
        section['display_name']: sorted(section['policies'])
        for type_, section in policies.items()
        if type_ in types and section['policies']
    }


def get_regpol(regclass=None):
    regpol = {
        'Machine': _read_regpol_file(REGPOL_MACHINE) or b'',
        'User': _read_regpol_file(REGPOL_USER) or b''
    }
    return {regclass: regpol[regclass]} if regclass else regpol
