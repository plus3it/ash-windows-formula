[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/plus3it/ash-windows-formula?branch=master&svg=true)](https://ci.appveyor.com/project/plus3it/ash-windows-formula)

# ash-windows-formula
Automated System Hardening - Windows (*ash-windows*) is a Salt Formula for
applying a security baseline to a Windows system. The *ash-windows* security
baselines are developed from guidance provided by the OS vendor and guidance
derived from [Security Control Automated Protocol (SCAP) content][7] based on
[DISA Secure Technical Implementation Guides (STIGs)][0]. [SCAP][6] is a
program managed by the [National Institute of Standards and Technology
(NIST)][5].


## Supported Windows and Internet Explorer Versions

- Microsoft Windows Server 2012 R2
- Microsoft Windows Server 2016
- Microsoft Windows Server 2019
- Microsoft Windows 10
- Microsoft Internet Explorer 11


## Available Baselines


### ash-windows.sct

The **Microsoft SCT Baseline** (`ash-windows.sct`) is based on guidance
provided by Microsoft through the [Microsoft Security Compliance Toolkit
(SCT)][8]. This baseline includes the following steps:

- Install the [Maximum Segment Size (MSS)][1] extensions for the local group
policy editor
- Install the [Pass the Hash (PtH)][2] extensions for the local group
policy editor
- Apply the OS security policies from the Microsoft SCT baseline
- Apply the IE security policies from the Microsoft SCT baseline
- Apply the audit policies from the Microsoft SCT baseline

The SCT baseline supports the following components:

- IE 11
- Windows 10
- Windows Server 2012 R2
- Windows Server 2016
- Windows Server 2019

### ash-windows.stig

The **DISA STIG Baseline** (`ash-windows.stig`) is derived from a SCAP scan
based on the [DISA STIG][0] benchmark. This baseline includes the following
steps:

- Apply the Microsoft SCT baseline (includes everything listed in
[ash-windows.sct](#ash-windowssct))
- Apply the OS security policies from the DISA STIG baseline
    - The settings configured by the baseline are available from the DISA STIG
website
- Apply the IE security policies from the DISA STIG baseline
- Apply the audit policies from the DISA STIG baseline


### ash-windows.delta

The **Delta baseline** (`ash-windows.delta`) is used both to enforce
additional security settings, or to loosen them where they interfere with
operation of the system. For example, the Microsoft SCT policy will prevent
local accounts from logging on remotely, including the local administrator.
When a system is joined to a domain, this isn't a problem as domain accounts
would still be able to login. However, on a system that is not (or not yet)
joined to a domain, or in environments where there is no local console access
(such as many cloud infrastructures), this setting effectively bricks the
system. As this formula is intended to support both domain-joined and
non-domain-joined systems, as well as infrastructures of all types, the delta
policy loosens this security setting. In a domain, it would be recommended to
use group policy to re-apply this setting.

The **Delta** policy is also used to address inconsistencies across baseline
versions and between different OS versions. For example, the DISA STIG for
Windows 2008 R2 has a requirement to change the name of the local
administrator account. For whatever reason, this requirement is not present in
the STIG for Windows 2012 R2. For the sake of operational consistency, the
**Delta** policy modifies the name of the local administrator account for all
OS versions.

This baseline is not included by any other states. It must be applied using
targeting via top.sls, orchestrate, or an external utility. Below are all the
configuration tasks of the **Delta** policy:

- Rename local guest account to `xGuest`
- Rename local administrator account to `xAdministrator`
- Remove `NT Authority\Local Account` from the deny network logon right and
the deny remote interactive logon right; the **Delta** baseline settings,
listed below, deny only the Guest account:
    - `SeDenyRemoteInteractiveLogonRight` = `*S-1-5-32-546`
    - `SeDenyNetworkLogonRight` = `*S-1-5-32-546`
- Allow users to ignore certificate errors in IE:
    - `HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors` = `0`


### ash-windows.custom

The **Custom Baseline** (`ash-windows.custom`) is designed to allow the user to
define and apply their own baseline policy or policies to a system. This can
also be used to override a policy from another baseline. For example, the
`ash-windows.stig` baseline could be applied to a system first, then the
`ash-windows.custom` policy could be applied to change a specific setting from
the DISA STIG that interferred with the purpose of the system.

This baseline works by reading policies from both pillar and grains using the
key `ash-windows:lookup:custom_policies`. If the same policy setting is
defined in both pillar and grains, the policy in grains takes precedence (as
grains are considered more "local"). However, if the pillar policy includes
the flag `no_override: True`, then the pillar policy is always enforced. One
use case for this feature is to allow a central team managing the salt master
to determine whether specific policy settings should never be overridden by a
local administrator.

This baseline is not included by any other states. It must be applied using
targeting via top.sls, orchestrate, or an external utility. See the
[Configuration](#Configuration) section for examples of how to define custom
policies for use with the Custom Baseline.


## Configuration

The *ash-windows* formula supports configuration via pillar. The `role` and
`custom_policies` settings may alternatively be set via grains. All settings
must be namespaced under the `ash-windows:lookup` key. The available settings
include:

- `role`: Sets the role-type of the server. This setting may be configured via
the pillar or grain system. The grain value will take precedence over the
pillar value. The `role` value may be one of:

    - `MemberServer` - this is the default for a Server OS
    - `DomainController`
    - `Workstation` - this is the default for a Desktop OS

- `custom_policies`: A list of policy dictionaries. This key is used by the
[Custom Baseline](#ash-windowscustom) to apply a user-specified baseline to a
system. Each policy dictionary may either be a 'regpol' policy or a 'secedit'
policy. 'regpol' policies are used to manage registry entries. 'secedit'
policies are used to manage [Privilege Rights][9] and [Systems Access][10]
settings.

Below is an example pillar structure:

```
ash-windows:
  lookup:
    role: MemberServer
    custom_policies:
      - policy_type: regpol
        key: HKLM\Software\Salt\Foo
        value: 1
        vtype: REG_DWORD
      - policy_type: regpol
        key: HKLM\Software\Salt\Bar
        value: testing
        vtype: REG_SZ
      - policy_type: secedit
        name: NewAdministratorName
        value: superadmin
```


## Applying Policies from the Command Line

The `ash-windows` formula includes a [custom salt execution module]
(_modules/ash_win_lgpo.py) as a wrapper around salt's builtin `lgpo` module.
The execution module is used internally by `ash-windows` baselines and states,
and can also be called from the command line. This feature can be useful for
testing policies or executing a one-time override of a specific baseline
policy setting.

Below are some examples, executed from a PowerShell window using salt
masterless mode.

```powershell
# Apply several policies at once, using `ash_lgpo.apply_policies` to apply it.
# This method accepts a list policy dictionaries, so this method can be used
# to apply many policies at one time.
$policies=`
"[`
    {'policy_type':'regpol', `
    'key':'HKLM\Software\Salt\Policies\Foo', `
    'value':'0', `
    'vtype':'DWORD'},
    {'policy_type':'regpol', `
    'key':'HKLM\Software\Salt\Policies\Bar', `
    'value':'Baz', `
    'vtype':'SZ'}, `
    {'policy_type':'secedit', `
    'name':'MaximumPasswordAge', `
    'value':'60'} `
]"
C:\salt\salt-call.bat --local ash_lgpo.apply_policies policies="$($policies -replace `"`r|`n`")"

# Manage a registry entry via `lgpo.set_reg_value`
C:\salt\salt-call.bat --local ash_lgpo.set_reg_value `
    key='HKLM\Software\Salt\Policies\Foo' `
    value='Bar' `
    vtype='SZ'

# Manage a Privilige Right or Systems Access setting, using
# `lgpo.set_secedit_value`
C:\salt\salt-call.bat --local ash_lgpo.set_secedit_value `
    name=MaximumPasswordAge value=60

# Get a list of valid secedit policies
C:\salt\salt-call.bat --local ash_lgpo.list_secedit_policies
```


## References
- [DISA Secure Technical Implementation Guides (STIGs) for Windows][0]
- [Microsoft Maximum Segment Size (MSS) registry settings][1]
- [Microsoft Pass the Hash (PtH) group policy extensions][2]
- [Microsoft User / Privilege Rights][3]
- [Microsoft Account / Systems Access Policies][4]
- [Microsoft Security Compliance Toolkit][8]
- [National Institute of Standards and Technology (NIST)][5]
- [Security Control Automated Protocol (SCAP)][6]
- [SCAP Content][7]

[0]: http://iase.disa.mil/stigs/os/windows
[1]: https://technet.microsoft.com/en-us/library/dd349797(v=ws.10).aspx
[2]: http://blogs.technet.com/b/secguide/archive/2014/08/13/security-baselines-for-windows-8-1-windows-server-2012-r2-and-internet-explorer-11-final.aspx
[3]: https://technet.microsoft.com/en-us/library/dd349804(v=ws.10).aspx
[4]: https://technet.microsoft.com/en-us/library/jj852214(v=ws.11).aspx
[5]: http://www.nist.gov
[6]: http://scap.nist.gov
[7]: http://web.nvd.nist.gov/view/ncp/repository?keyword=Microsoft+Windows&startIndex=0
[8]: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10
