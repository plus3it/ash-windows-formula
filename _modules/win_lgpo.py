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

try:
    from salt.utils.files import mkstemp
except ImportError:
    from salt.utils import mkstemp

try:
    from salt.utils.platform import is_windows
except ImportError:
    from salt.utils import is_windows

log = logging.getLogger(__name__)
__virtualname__ = 'lgpo'

LGPO_EXE = '{0}\\system32\\Apply_LGPO_Delta.exe'.format(os.environ.get(
    'SYSTEMROOT'))
HAS_LGPO = os.path.isfile(LGPO_EXE)


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
                'DWORD': 'DWORD',
                'REG_DWORD': 'DWORD',
                'SZ': 'SZ',
                'REG_SZ': 'SZ',
                'EXSZ': 'EXSZ',
                'REG_EXPAND_SZ': 'EXSZ',
            },
            'hives': {
                'COMPUTER': 'Computer',
                'HKLM': 'Computer',
                'MACHINE': 'Computer',
                'HKEY_LOCAL_MACHINE': 'Computer',
                'USER': 'User',
                'HKCU': 'User',
                'HKEY_CURRENT_USER': 'User',
            },
        }
        self.SECEDIT_MAP = {
            'MINIMUMPASSWORDAGE': {
                'type': 'SYSTEM_ACCESS',
                'name': 'MinimumPasswordAge',
            },
            'MAXIMUMPASSWORDAGE': {
                'type': 'SYSTEM_ACCESS',
                'name': 'MaximumPasswordAge',
            },
            'MINIMUMPASSWORDLENGTH': {
                'type': 'SYSTEM_ACCESS',
                'name': 'MinimumPasswordLength',
            },
            'PASSWORDCOMPLEXITY': {
                'type': 'SYSTEM_ACCESS',
                'name': 'PasswordComplexity',
            },
            'PASSWORDHISTORYSIZE': {
                'type': 'SYSTEM_ACCESS',
                'name': 'PasswordHistorySize',
            },
            'LOCKOUTBADCOUNT': {
                'type': 'SYSTEM_ACCESS',
                'name': 'LockoutBadCount',
            },
            'RESETLOCKOUTCOUNT': {
                'type': 'SYSTEM_ACCESS',
                'name': 'ResetLockoutCount',
            },
            'LOCKOUTDURATION': {
                'type': 'SYSTEM_ACCESS',
                'name': 'LockoutDuration',
            },
            'FORCELOGOFFWHENHOUREXPIRE': {
                'type': 'SYSTEM_ACCESS',
                'name': 'ForceLogoffWhenHourExpire',
            },
            'CLEARTEXTPASSWORD': {
                'type': 'SYSTEM_ACCESS',
                'name': 'ClearTextPassword',
            },
            'LSAANONYMOUSNAMELOOKUP': {
                'type': 'SYSTEM_ACCESS',
                'name': 'LSAAnonymousNameLookup',
            },
            'ENABLEGUESTACCOUNT': {
                'type': 'SYSTEM_ACCESS',
                'name': 'EnableGuestAccount',
            },
            'NEWGUESTNAME': {
                'type': 'SYSTEM_ACCESS',
                'name': 'NewGuestName',
            },
            'NEWADMINISTRATORNAME': {
                'type': 'SYSTEM_ACCESS',
                'name': 'NewAdministratorName',
            },
            'ENABLEADMINACCOUNT': {
                'type': 'SYSTEM_ACCESS',
                'name': 'EnableAdminAccount',
            },
            'SESECURITYPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeSecurityPrivilege',
            },
            'SEASSIGNPRIMARYTOKENPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeAssignPrimaryTokenPrivilege',
            },
            'SERELABELPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeRelabelPrivilege',
            },
            'SECREATETOKENPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeCreateTokenPrivilege',
            },
            'SETRUSTEDCREDMANACCESSPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeTrustedCredManAccessPrivilege',
            },
            'SEREMOTEINTERACTIVELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeRemoteInteractiveLogonRight',
            },
            'SECREATEPAGEFILEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeCreatePagefilePrivilege',
            },
            'SEREMOTESHUTDOWNPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeRemoteShutdownPrivilege',
            },
            'SEDENYINTERACTIVELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDenyInteractiveLogonRight',
            },
            'SEINCREASEBASEPRIORITYPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeIncreaseBasePriorityPrivilege',
            },
            'SELOADDRIVERPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeLoadDriverPrivilege',
            },
            'SERESTOREPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeRestorePrivilege',
            },
            'SESYSTEMTIMEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeSystemTimePrivilege',
            },
            'SECREATEGLOBALPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeCreateGlobalPrivilege',
            },
            'SEMANAGEVOLUMEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeManageVolumePrivilege',
            },
            'SEDENYBATCHLOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDenyBatchLogonRight',
            },
            'SEINTERACTIVELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeInteractiveLogonRight',
            },
            'SEENABLEDELEGATIONPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeEnableDelegationPrivilege',
            },
            'SECREATEPERMANENTPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeCreatePermanentPrivilege',
            },
            'SEDEBUGPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDebugPrivilege',
            },
            'SESYSTEMPROFILEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeSystemProfilePrivilege',
            },
            'SEPROFILESINGLEPROCESSPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeProfileSingleProcessPrivilege',
            },
            'SEBACKUPPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeBackupPrivilege',
            },
            'SENETWORKLOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeNetworkLogonRight',
            },
            'SEINCREASEQUOTAPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeIncreaseQuotaPrivilege',
            },
            'SESHUTDOWNPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeShutdownPrivilege',
            },
            'SECREATESYMBOLICLINKPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeCreateSymbolicLinkPrivilege',
            },
            'SETIMEZONEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeTimeZonePrivilege',
            },
            'SEDENYNETWORKLOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDenyNetworkLogonRight',
            },
            'SEIMPERSONATEPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeImpersonatePrivilege',
            },
            'SESYSTEMENVIRONMENTPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeSystemEnvironmentPrivilege',
            },
            'SELOCKMEMORYPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeLockMemoryPrivilege',
            },
            'SETCBPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeTcbPrivilege',
            },
            'SEAUDITPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeAuditPrivilege',
            },
            'SETAKEOWNERSHIPPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeTakeOwnershipPrivilege',
            },
            'SEDENYREMOTEINTERACTIVELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDenyRemoteInteractiveLogonRight',
            },
            'SEDENYSERVICELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeDenyServiceLogonRight',
            },
            'SECHANGENOTIFYPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeChangeNotifyPrivilege',
            },
            'SEBATCHLOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeBatchLogonRight',
            },
            'SEINCREASEWORKINGSETPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeIncreaseWorkingSetPrivilege',
            },
            'SEUNDOCKPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeUndockPrivilege',
            },
            'SEMACHINEACCOUNTPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeMachineAccountPrivilege',
            },
            'SESYNCAGENTPRIVILEGE': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeSyncAgentPrivilege',
            },
            'SESERVICELOGONRIGHT': {
                'type': 'PRIVILEGE_RIGHTS',
                'name': 'SeServiceLogonRight',
            },
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
        try:
            return self.SECEDIT_MAP[name.upper()]['name']
        except KeyError:
            pass
        return None

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

    def policy_template_regpol(self, policies):
        """Return a regpol policy template."""
        policy_template = []
        for policy in policies:
            policy_template.extend(
                [
                    policy['hive'],
                    policy['key_path'],
                    policy['vname'],
                    policy['action'],
                    ';'
                ]
            )
        return policy_template

    def policy_template_secedit(self, policies):
        """Return a secedit policy template."""
        policy_template = [
            '[Unicode]',
            'Unicode=yes',
            '[Version]',
            'signature="$CHICAGO$"',
            'Revision=1'
        ]
        system_access_template = [
            '[System Access]'
        ]
        privilege_rights_template = [
            '[Privilege Rights]'
        ]
        for policy in policies:
            policy_map = self.SECEDIT_MAP[policy['name'].upper()]
            if policy_map['type'] == 'SYSTEM_ACCESS':
                system_access_template.append('{0} = {1}'
                                              .format(policy_map['name'],
                                                      policy['value']))
            elif policy_map['type'] == 'PRIVILEGE_RIGHTS':
                privilege_rights_template.append('{0} = {1}'
                                                 .format(policy_map['name'],
                                                         policy['value']))
        return (policy_template + system_access_template +
                privilege_rights_template)


def __virtual__():
    """Load only on Windows and only if Apply_LGPO_Delta is present."""
    if not is_windows():
        return False
    if not HAS_LGPO:
        return (False, 'Module "{0}" not loaded because "{1}" could not be '
                       'found'.format(__virtualname__, LGPO_EXE))
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
                'vtype'  : 'DWORD' | 'SZ' | 'EXSZ'
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
        parameters. See ``lgpo.set_registry_value`` for the aliases.

    CLI Examples:

    .. code-block:: bash

        policies="[{'policy_type':'regpol', \
            'key':'HKLM\Software\Salt\Policies\Foo', \
            'value':'0', \
            'vtype':'DWORD'}]"
        salt '*' lgpo.validate_policies policies="${policies}"
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


def _write_policy_file(policy_template):
    policy_file = mkstemp()
    try:
        with io.open(policy_file, mode='wb') as fh_:
            fh_.write(os.linesep.join(policy_template).encode('utf-8'))
    except Exception as exc:
        raise CommandExecutionError('Error saving LGPO policy file "{0}". '
                                    'Exception: {1}'.format(policy_file, exc))
    return policy_file


def _write_policy_files(valid_policies):
    policy_files = {}
    policy_helper = PolicyHelper()
    for policy_type, policy_data in valid_policies.items():
        policy_template = getattr(policy_helper, 'policy_template_{0}'
                                  .format(policy_type))(policy_data)
        policy_files[policy_type] = _write_policy_file(policy_template)
    return policy_files


def apply_policies(policies=None, logfile=True, errorfile=True):
    r"""
    Apply a policy that manages Local Group Policy Objects.

    :param policies:
        A policy dictionary, or a list of policy dictionaries. Each policy
        dictionary must be of one of the forms below:
            {
                'policy_type' : 'regpol',
                'key'    : '<hive>\path\to\registry\key\value_name',
                'value'  : 'value of the registry key',
                'vtype'  : 'DWORD' | 'SZ' | 'EXSZ'
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
        parameters. See ``lgpo.set_registry_value`` for the aliases.
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

    CLI Examples:

    .. code-block:: bash

        policies="[{'policy_type':'regpol', \
            'key':'HKLM\Software\Salt\Policies\Foo', \
            'value':'0', \
            'vtype':'DWORD'}]"
        salt '*' lgpo.apply_policies policies="${policies}"
    """
    valid_policies, reason, policy = validate_policies(policies)
    if not valid_policies:
        raise SaltInvocationError('{0}; policy={1}'.format(reason, policy))
    policy_files = _write_policy_files(valid_policies)
    command = ' '.join([LGPO_EXE, policy_files.get('regpol', ''),
                        policy_files.get('secedit', '')])
    if logfile is True:
        logfile = mkstemp(prefix='lgpo_', suffix='.log')
    if logfile:
        try:
            __salt__['file.makedirs'](path=logfile)
        except Exception as exc:
            raise CommandExecutionError('Error creating directory for logfile '
                                        '"{0}". Exception: {1}'.format(logfile,
                                                                       exc))
        log.info('LGPO log file is "{0}"'.format(logfile))
        command = ' '.join([command, '/log', logfile])
    if errorfile is True:
        errorfile = mkstemp(prefix='lgpo_', suffix='.err')
    if errorfile:
        try:
            __salt__['file.makedirs'](path=errorfile)
        except Exception as exc:
            raise CommandExecutionError('Error creating directory for '
                                        'errorfile "{0}". Exception: {1}'
                                        .format(errorfile, exc))
        log.info('LGPO error file is "{0}"'.format(errorfile))
        command = ' '.join([command, '/error', errorfile])
    log.info('Applying LGPO policies')
    log.debug('LGPO policy data: {0}'.format(valid_policies))
    try:
        ret = __salt__['cmd.retcode'](command, python_shell=False)
    except Exception as exc:
        raise CommandExecutionError('Error applying LGPO policy template '
                                    '"{0}". Exception: {1}'
                                    .format(valid_policies, exc))

    if errorfile and os.path.getsize(errorfile) > 0:
        raise CommandExecutionError(
            'Encountered errors processing the LGPO policy template. See the '
            'error file for details -- {0}'.format(errorfile))

    if ret:
        raise CommandExecutionError('Non-zero exit [{0}] from {1}. We do not '
                                    'know what this means. Hopefully the '
                                    'error log contains details -- {2}'
                                    .format(ret, LGPO_EXE, errorfile))
    for policy_file in policy_files.values():
        if os.path.isfile(policy_file):
            os.remove(policy_file)
    return valid_policies


def construct_policy(mode, name, value=None, vtype=None):
    """Map the mode and return a list containing the policy dictionary."""
    default = {
        'policy_type': 'unknown'
    }
    policy_map = {
        'create_reg_key': {
            'policy_type': 'regpol',
            'action': 'CREATEKEY'
        },
        'delete_reg_value': {
            'policy_type': 'regpol',
            'action': 'DELETE'
        },
        'delete_all_reg_values': {
            'policy_type': 'regpol',
            'action': 'DELETEALLVALUES'
        },
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


def set_reg_value(key=None, value=None, vtype=None, logfile=True,
                  errorfile=True):
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
        ``DWORD``, ``SZ``, or ``EXSZ``. These types also support the following
        aliases:
            'DWORD'     : ['DWORD', 'REGDWORD', 'REG_DWORD']
            'SZ'        : ['SZ', 'REGSZ', 'REG_SZ']
            'EXSZ'      : ['EXSZ', 'REGEXPANDSZ', 'REG_EXPAND_SZ']
        ``vtype`` is case insensitive.
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

    CLI Examples:

    .. code-block:: bash

        salt '*' lgpo.set_reg_value \
            key='HKLM\Software\Salt\Policies\Foo' \
            value='0' \
            vtype='DWORD'
        salt '*' lgpo.set_reg_value \
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
        logfile=logfile,
        errorfile=errorfile
    ))


def create_reg_key(key=None, logfile=True, errorfile=True):
    r"""
    Use a Local Group Policy Object to create a registry key with no values.

    :param key:
        Path to the registry key managed by the policy. The path must be
        in the form: ``<hive>\path\to\registry\key``. ``<hive>`` may be one of
        ``Computer`` or ``User``. ``<hive>`` also supports aliases the
        following aliases:
            'Computer'  : ['COMPUTER', 'HKLM', 'MACHINE', 'HKEY_LOCAL_MACHINE']
            'User'      : ['USER', 'HKCU', 'HKEY_CURRENT_USER']
        ``<hive>`` is case insensitive.
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

    CLI Examples:

    .. code-block:: bash

        salt '*' lgpo.create_reg_key key='HKLM\Software\Salt\Policies\Foo'
        salt '*' lgpo.create_reg_key key='HKLM\Software\Salt\Policies\Bar'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='create_reg_key',
            name=key
        ),
        logfile=logfile,
        errorfile=errorfile
    ))


def delete_reg_value(key=None, logfile=True, errorfile=True):
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
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

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
        logfile=logfile,
        errorfile=errorfile
    ))


def delete_all_reg_values(key=None, logfile=True, errorfile=True):
    r"""
    Use a Local Group Policy Object to delete all values within a registry key.

    :param key:
        Path to the registry key containing the values to be removed. The path
        must be in the form: ``<hive>\path\to\registry\key``. ``<hive>`` may be
        one of ``Computer`` or ``User``. ``<hive>`` also supports aliases the
        following aliases:
            'Computer'  : ['COMPUTER', 'HKLM', 'MACHINE', 'HKEY_LOCAL_MACHINE']
            'User'      : ['USER', 'HKCU', 'HKEY_CURRENT_USER']
        ``<hive>`` is case insensitive.
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

    CLI Examples:

    .. code-block:: bash

        salt '*' lgpo.delete_all_reg_values \
            key='HKLM\Software\Salt\Policies\Foo'
        salt '*' lgpo.delete_all_reg_values \
            key='HKLM\Software\Salt\Policies\Bar'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='delete_all_reg_values',
            name=key
        ),
        logfile=logfile,
        errorfile=errorfile
    ))


def set_secedit_value(name=None, value=None, logfile=True, errorfile=True):
    r"""
    Modify a "System Access" or "Privilege Rights" security policy.

    :param name:
        Name of the "System Access" or "Privilege Rights" policy to modify.
        Parameter is case-insensitive. To get a list of known policy names,
        use ``lgpo.get_secedit_names``.
    :param value:
        Value to apply to the policy.
    :param logfile:
        The path to the log file where the results of applying the policy will
        be saved. If set to ``True`` (the Default), then the log file will be
        created in the system temp directory. If set to ``False``, then no log
        file will be created.
    :param errorfile:
        The path to the error file where errors resulting from applying the
        policy will be saved. If set to ``True`` (the Default), then the error
        file will be created in the system temp directory. If set to
        ``False``, then no error file will be created.

    CLI Examples:

    .. code-block:: bash

        salt '*' lgpo.set_secedit_value name=MaximumPasswordAge value=60
        salt '*' lgpo.set_secedit_value name=SeDenyServiceLogonRight \
            value=Guests
        salt '*' lgpo.set_secedit_value name=SeDenyNetworkLogonRight \
            value='*S-1-5-32-546'
    """
    return (apply_policies(
        policies=construct_policy(
            mode='set_secedit_value',
            name=name,
            value=value
        ),
        logfile=logfile,
        errorfile=errorfile
    ))


def get_secedit_names():
    """Return all "System Access" and "Privilege Rights" policy names."""
    policy_helper = PolicyHelper()
    system_access_names = []
    privilege_rights_names = []
    for policy in policy_helper.SECEDIT_MAP.values():
        if policy['type'] == 'SYSTEM_ACCESS':
            system_access_names.append(policy['name'])
        elif policy['type'] == 'PRIVILEGE_RIGHTS':
            privilege_rights_names.append(policy['name'])
    return (
        {
            'System Access': system_access_names,
            'Privilege Rights': privilege_rights_names
        }
    )
