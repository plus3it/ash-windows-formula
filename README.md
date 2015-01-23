# ash-windows-formula
Automated System Hardening - Windows (*ash-windows*) is a Salt Formula that was 
developed to apply a security baseline to a Windows system. The *ash* security 
baselines are developed from guidance provided by the OS vendor and guidance 
derived from [Security Control Automated Protocol (SCAP) content][2], including 
[DISA Secure Technical Implementation Guides (STIGs)][4]. [SCAP][1] is a 
program managed by the [National Institute of Standards and Technology 
(NIST)][0].


##Dependencies

- A masterless salt configuration. This is due to the path references to the 
included tools/utilities/content. A later version will look into caching these 
from a salt master.


##Supported Windows and Internet Explorer Versions

- Microsoft Windows Server 2008 R2
- Microsoft Windows Server 2012 R2
- Microsoft Windows 8.1
- Microsoft Internet Explorer 8
- Microsoft Internet Explorer 9
- Microsoft Internet Explorer 10
- Microsoft Internet Explorer 11

##ash-windows Baselines

For each OS version, *ash-windows* is capable of applying two primary security 
baselines: 
- [**Microsoft SCM Baseline**](#ash-windowsscm): the baseline provided by 
Microsoft through the [Microsoft Security Compliance Manager (SCM)][3]
- [**DISA STIG Baseline**](#ash-windowsstig): the baseline derived from a SCAP 
scan based on the [DISA STIG][4] benchmark. 

For the Server OS versions above, the formula supports variations for both 
Member Servers and Domain Controllers, as defined by the Microsoft and DISA 
baselines.

There is a further [**Delta baseline**](#ash-windowsdelta) policy that is used 
to enforce additional security settings or to loosen security settings where 
they interfere with operation of the system. For example, the Microsoft SCM 
policy will prevent local accounts from logging on remotely, including the 
local administrator. When a system is joined to a domain, this isn't a problem 
as domain accounts would still be able to login. However, on a system that is 
not (or not yet) joined to a domain, or in environments where there is no local 
console access (such as many cloud infrastructures), this setting effectively 
bricks the system. As this formula is intended to support both domain-joined 
and non-domain-joined systems, as well as infrastructures of all types, the 
delta policy loosens this security setting. In a domain, it would be 
recommended to use group policy to re-apply this setting.

The **Delta** policy is also used to address inconsistencies across baseline 
versions and between different OS versions. For example, the DISA STIG for 
Windows 2008 R2 has a requirement to change the name of the local 
administrator account. For whatever reason, this requirement is not present in 
the STIG for Windows 2012 R2. For the sake of operational consistency, the 
**Delta** policy modifies the name of the local administrator account for all 
OS versions. 

##Available States

###ash-windows
See [ash-windows.stig](#ash-windowsstig). The only content of [init.sls]
(ash-windows/init.sls) is an `include` statement for 
`ash-windows.stig`.

###ash-windows.mss
The `ash-windows.mss` salt state will install the Maximum Segment Size 
extensions into the local group policy editor (gpedit.msc). This exposes the 
settings in the editor so they can be managed properly as part of a security 
policy. This state is included by the [ash-windows.scm](#ash-windowsscm) state.

###ash-windows.scm

The **Microsoft SCM baseline** (`ash-windows.scm`) includes the following 
steps:

- Install the [Maximum Segment Size (MSS)][5] extensions for the local group 
policy editor
- Install the [Pass the Hash (PtH)][6] extensions for the local group 
policy editor
- Apply the OS security policies from the Microsoft SCM baseline
- Apply the IE security policies from the Microsoft SCM baseline
- Apply the audit policies from the Microsoft SCM baseline

###ash-windows.stig

The **DISA STIG baseline** (`ash-windows.stig`) includes the following steps:

- Apply the Microsoft SCM baseline (includes everything listed in 
[ash-windows.scm](#ash-windowsscm))
- Apply the OS security policies from the DISA STIG baseline
  - The settings configured by the baseline are available from the DISA STIG 
website
- Apply the IE security policies from the DISA STIG baseline
- Apply the audit policies from the DISA STIG baseline

###ash-windows.delta

The **Delta baseline** (`ash-windows.delta`) is not included by any other 
baseline. It must be applied using targeting via top.sls, orchestrate, or an 
external utility.

Below are all the configuration tasks of the **Delta** policy:

- Rename local guest account to `xGuest`
- Rename local administrator account to `xAdministrator`
- Remove `NT Authority\Local Account` from the deny network logon right and 
the deny remote interactive logon right; the **Delta** baseline settings, 
listed below, deny only the Guest account:
  - `SeDenyRemoteInteractiveLogonRight` = `*S-1-5-32-546`
  - `SeDenyNetworkLogonRight` = `*S-1-5-32-546`
- Allow users to ignore certificate errors in IE:
  - `HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors` = `0`


##Configuration
The *ash-windows* formula supports configuration via pillar. The `role` 
configuration setting may alternatively be set via a grain. The available 
settings include:

- `ash-windows:lookup:common_logdir`: Path on the local filesystem where the 
formula will store output of any command line [tools](#Tools) that apply 
baseline settings. Defaults to: 
  - `%SystemDrive%\Ash\logs`
- `ash-windows:lookup:salt_ash_root`: Path in the `salt://` filesystem of the 
*ash-windows* formula. This is used to determine the `source` for files copied 
to the local system. The `file_roots` configuration of the salt installation 
will affect the value. Defaults to: 
  - `salt://ash-windows`
- `ash-windows:lookup:system_ash_root`: Path on the local filesystem to the 
*ash-windows* formula. This is used to set the command working directory 
(`cwd`) when executing the command line [tools](#Tools). Defaults to:
  - `%systemdrive%\salt\formulas\ash-windows-formula\ash-windows`
- `ash-windows:role`: Sets the role-type of the server. This setting may be 
configured via the pillar or grain system. The grain value will take 
precedence over the pillar value. The `role` value may be one of:
  - `MemberServer` - this is the default for a Server OS
  - `DomainController`
  - `Workstation` - this is the default for a Desktop OS

Below is an example pillar structure:

```
ash-windows:
  lookup:
    common_logdir: 'C:\\Ash\\logs'
    salt_ash_root: 'salt://ash-windows'
    system_ash_root: 'C:\\salt\\formulas\\ash-windows-formula\\ash-windows'

  role: 'MemberServer'
```

##Tools
- [Microsoft LocalGPO][8]
- [Microsoft Apply_LGPO_Delta.exe][7]
- [Microsoft ImportRegPol.exe][7]


##References
- [DISA Secure Technical Implementation Guides (STIGs) for Windows][4]
- [Microsoft SCM][3]
- [Microsoft Maximum Segment Size (MSS) registry settings][5]
- [Microsoft Pass the Hash (PtH) group policy extensions][6]
- [Microsoft Local Group Policy Utilities][7]
- [Microsoft LocalGPO][8] (Part of Microsoft SCM)
- [National Institute of Standards and Technology (NIST)][0]
- [Security Control Automated Protocol (SCAP)][1]
- [SCAP Content][2]

[0]: http://www.nist.gov
[1]: http://scap.nist.gov
[2]: http://web.nvd.nist.gov/view/ncp/repository?keyword=Microsoft+Windows&startIndex=0
[3]: http://www.microsoft.com/scm
[4]: http://iase.disa.mil/stigs/os/windows
[5]: https://technet.microsoft.com/en-us/library/dd349797(v=ws.10).aspx
[6]: http://blogs.technet.com/b/secguide/archive/2014/08/13/security-baselines-for-windows-8-1-windows-server-2012-r2-and-internet-explorer-11-final.aspx
[7]: http://blogs.technet.com/b/fdcc/archive/2008/05/07/lgpo-utilities.aspx
[8]: https://technet.microsoft.com/en-us/magazine/hh489604.aspx
