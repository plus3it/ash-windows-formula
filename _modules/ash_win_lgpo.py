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
    from salt.modules.win_lgpo import (
        _policy_info, _buildKnownDataSearchString, _policyFileReplaceOrAppend,
        _read_regpol_file, _write_regpol_data,
    )

    POLICY_INFO = _policy_info()
    REGPOL_MACHINE = _read_regpol_file(
        POLICY_INFO.admx_registry_classes['Machine']['policy_path']
    ) or b''
    REGPOL_USER = _read_regpol_file(
        POLICY_INFO.admx_registry_classes['User']['policy_path']
    ) or b''


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
                'DELETEALLVALUES': 'DELETEALLVALUES',
                'CREATEKEY': 'CREATEKEY',
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
        self.SECEDIT_POLICIES = {
            policy: details for policy, details
            in POLICY_INFO.policies['Machine']['policies'].items()
            if 'Registry' not in details
            and 'Registry Values' != details.get('Secedit', {}).get('Section')
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
            vname = key_[-1].replace('\\\\','\\').strip('"')
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
        if not all(key in policy for key in self.LGPO_VTYPE_KEYS) and not \
                all(key in policy for key in self.LGPO_ACTION_KEYS):
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

    def _secedit_name(self, name):
        return name if name in self.SECEDIT_POLICIES.keys() else None

    def validate_secedit(self, policy):
        """Validate secedit policy."""
        if not all(key in policy for key in self.LGPO_SECEDIT_KEYS):
            return False, 'Secedit policy dictionary is malformed'
        name = self._secedit_name(policy.get('name', ''))
        value = policy.get('value', '')
        if not name:
            return False, 'Secedit policy name "{0}" is unknown'.format(name)
        return (
            {
                'name': name,
                'value': value
            },
            ''
        )

    def _reg_to_pol(self, policy, regpol):
        vtype, vdata = policy['action'].split(':')

        setting = _buildKnownDataSearchString(
            reg_key=policy['key_path'],
            reg_valueName=policy['vname'],
            reg_vtype=vtype,
            reg_data=str(vdata),
        )

        return _policyFileReplaceOrAppend(setting, regpol)

    def policy_object_regpol(self, policies, **kwargs):
        """Return a regpol policy object."""
        overwrite_regpol = kwargs.pop('overwrite_regpol', True)
        policy_objects = {
            'Machine': b'' if overwrite_regpol else REGPOL_MACHINE,
            'User': b'' if overwrite_regpol else REGPOL_USER,
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
    return __virtualname__


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
                'action' : 'DELETE' | 'DELETEALLVALUES' | 'CREATEKEY'
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


def apply_policies(policies, overwrite_regpol=True):
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
        When ``True``, specified policies will wholly overwrite an existing
        registry.pol file. When ``False``, read the registry.pol if it exists
        and update it with the specified policies.

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
    for regclass, regpol in policy_objects.get('regpol', {}).items():
        _write_regpol_data(
            regpol,
            POLICY_INFO.admx_registry_classes[regclass]['policy_path'],
            POLICY_INFO.gpt_ini_path,
            POLICY_INFO.admx_registry_classes[regclass]['gpt_extension_location'],
            POLICY_INFO.admx_registry_classes[regclass]['gpt_extension_guid']
        )

    # Apply secedit policies
    __salt__['lgpo.set'](
        computer_policy=policy_objects.get('secedit', {}),
        cumulative_rights_assignments=False,
    )

    return valid_policies


def construct_policy(mode, name, value=None, vtype=None):
    """Map the mode and return a list containing the policy dictionary."""
    default = {
        'policy_type': 'unknown'
    }
    policy_map = {
        'set_reg_value': {
            'policy_type': 'regpol',
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

        salt '*' ash_lgpo.set_secedit_value name=MaxPasswordAge value=60
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


def get_secedit_policies():
    """Return all valid secedit policies."""
    secedit_policies = PolicyHelper().SECEDIT_POLICIES
    system_access = []
    privilege_rights = []
    advanced_audit = []
    netsh = []
    scripts = []
    other = []
    for name, policy in secedit_policies.items():
        if 'Secedit' in policy or 'NetUserModal' in policy:
            system_access.append(name)
        elif 'AdvAudit' in policy:
            advanced_audit.append(name)
        elif 'LsaRights' in policy:
            privilege_rights.append(name)
        elif 'NetSH' in policy:
            netsh.append(name)
        elif 'ScriptIni' in policy:
            scripts.append(name)
        else:
            other.append({name: policy})
    ret = {
        'Advanced Audit': sorted(advanced_audit),
        'NetSH': sorted(netsh),
        'Privilege Rights': sorted(privilege_rights),
        'Startup/Shutdown Scripts': sorted(scripts),
        'System Access': sorted(system_access),
        'Other': other,
    }
    return { section: names for section, names in ret.items() if names }
