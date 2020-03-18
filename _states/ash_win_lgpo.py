# -*- coding: utf-8 -*-
r"""
Manage Local Policy Group Policy Objects on Windows.

:maintainer: Loren Gordon <loren.gordon@plus3it.com>
:platform:   Windows
"""
import logging
import salt.utils

from salt.exceptions import CommandExecutionError, SaltInvocationError

log = logging.getLogger(__name__)
__virtualname__ = 'ash_lgpo'


def __virtual__():
    """Only load if ash_lgpo execution module is available."""
    if 'ash_lgpo.apply_policies' in __salt__:
        return __virtualname__
    else:
        return (False, 'State "{0}" not loaded because the "{0}" execution '
                       'module was not present'.format(__virtualname__))


def present(name, mode=None, value=None, vtype=None, policies=None, **kwargs):
    r"""
    Define a Local Group Policy Object (LGPO) that must be present.

    :param name:
        Name of the policy to apply. The type of value used depends on the
        mode specified, but it may be a path to a registry key, or a path to
        a registry value, or it may be the name of a secedit System Access or
        Privilege Rights security setting. For example, these would all be
        valid values for the ``name`` parameter:
            * ``HKLM\Software\Salt``
            * ``HKLM\Software\Salt\Foo``
            * ``MinimumPasswordAge``
            * ``SeSecurityPrivilege``
        The ``name`` parameter is ignored if the ``policies`` parameter is
        used.
    :param mode:
        Type of policy action to execute. May be one of:
            * ``create_reg_key``
            * ``delete_reg_value``
            * ``delete_all_reg_values``
            * ``set_reg_value``
            * ``set_secedit_value``
        The ``mode`` parameter is ignored if the ``policies`` parameter is
        used.
    :param value:
        Value to apply to the policy. Required for the ``set_reg_value`` and
        ``set_secedit_value`` modes. Ignored for other modes.
        The ``value`` parameter is ignored if the ``policies`` parameter is
        used.
    :param vtype:
        Type of registry value to create. Required for the ``set_reg_value``
        mode. Ignored for other modes. Valid values include:
            * REG_DWORD
            * REG_SZ
            * REG_EXPAND_SZ
        The ``vtype`` parameter is ignored if the ``policies`` parameter is
        used.

    :param policies:
        A list of dictionary policies to apply to the system. Rather than
        specifying individual states for each policy, ``policies`` enables
        multiple policies to be specified in a single state definition. The
        format for policy dictionaries is the same as for the
        ``ash_lgpo.apply_policies`` execution module. An example is below, but
        please see the execution module for details on the policy dictionary
        structure.

    State Examples:

    .. code-block:: yaml

        Set Registry Value:
          ash_lgpo.present:
            - name: HKLM\Software\Salt\Foo
            - mode: set_reg_value
            - value: 0
            - vtype: REG_DWORD

        Set Secedit Value:
          ash_lgpo.present:
            - name: MinimumPasswordAge
            - mode: set_secedit_value
            - value: 3

        Set Multiple Policies In One State:
          ash_lgpo.present:
            - policies:
              - policy_type: regpol
                key: HKLM\Software\Salt\Foo
                value: 0
                vtype: REG_DWORD
              - policy_type: regpol
                key: HKLM\Software\Salt\Bar
                value: 0
                vtype: REG_DWORD
              - policy_type: secedit
                name: MinimumPasswordAge
                value: 3
    """
    ret = {
        'name': name,
        'result': True,
        'comment': '',
        'changes': {}
    }

    if policies == []:
        # Passed an empty policies list, return without failing.
        ret['comment'] = '"policies" is an empty list'
        return ret

    policies = policies or __salt__['ash_lgpo.construct_policy'](
        name=name,
        mode=mode,
        value=value,
        vtype=vtype
    )

    if __opts__['test']:
        valid_policies, reason, policy = __salt__['ash_lgpo.validate_policies'](
            policies=policies
        )
        if not valid_policies:
            ret['result'] = False
            ret['comment'] = '{0}; policy={1}'.format(reason, policy)
        else:
            ret['comment'] = 'Would have applied local group policy objects'
            ret['changes'] = valid_policies
    else:
        try:
            result = __salt__['ash_lgpo.apply_policies'](policies=policies)
            ret['comment'] = 'Successfully applied local group policy objects'
            ret['changes'] = result
        except (CommandExecutionError, SaltInvocationError) as exc:
            ret['result'] = False
            ret['comment'] = exc

    return ret


def mod_aggregate(low, chunks, running):
    """
    Aggregate data from multiple states into a single state execution.

    The mod_aggregate function looks up all policies in the available low
    chunks and merges them into a single policies ref in the present low data
    """
    policies = []
    agg_enabled = [
        'present'
    ]
    if low.get('fun') not in agg_enabled:
        return low
    for chunk in chunks:
        tag = salt.utils.gen_state_tag(chunk)
        if tag in running:
            # Already ran the lgpo state, skip aggregation
            continue
        if chunk.get('state') == 'lgpo':
            if '__agg__' in chunk:
                continue
            # Check for the same function
            if chunk.get('fun') != low.get('fun'):
                continue
            # Check if the state disables aggregation
            if chunk.get('aggregate') is False:
                continue
            # Pull out the policy objects!
            if 'policies' in chunk:
                policies.extend(chunk['policies'])
                chunk['__agg__'] = True
            elif 'name' in chunk:
                policies.extend(__salt__['ash_lgpo.construct_policy'](
                    name=chunk['name'],
                    mode=chunk.get('mode', None),
                    value=chunk.get('value', None),
                    vtype=chunk.get('vtype', None)
                ))
                chunk['__agg__'] = True
    if policies:
        if 'policies' in low:
            low['policies'].extend(policies)
        else:
            low['policies'] = policies
    return low
