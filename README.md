# ash-windows-formula
Automated System Hardening - Windows (*ash-windows*) is a Salt Formula that was 
developed to apply a security baseline to a Windows system. The *ash* security 
baselines are developed from guidance provided by the OS vendor and guidance 
derived from Security Control Automated Protocol (SCAP) content, including 
DISA Secure Technical Implementation Guides (STIGs). For more information on 
[SCAP][0] and [SCAP content][1], please refer to the NIST sites. 


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

##Baselines

For each OS version, *ash-windows* is capable of applying two primary security 
baselines: the baseline provided by Microsoft through the [Microsoft Security 
Compliance Manager (SCM)][2], and the baseline derived from a SCAP scan based 
on the [DISA STIG][3] benchmark. For the Server OS versions above, the formula 
supports variations for both Member Servers and Domain Controllers, as defined 
by the Microsoft and DISA baselines. 

The **Microsoft SCM baseline** includes the following steps:

- Install the [Maximum Segment Size (MSS)][4] extensions for the local group  
policy editor
- Install the [Pass the Hash (PtH)][5] extensions for the local group  
policy editor
- Apply the OS security policies from the Microsoft SCM baseline
- Apply the IE security policies from the Microsoft SCM baseline
- Apply the audit policies from the Microsoft SCM baseline

The **DISA STIG baseline** includes the following steps:

- Apply the Microsoft SCM baseline (includes everything listed above)
- Apply the OS security policies from the DISA STIG baseline
  - The settings configured by the baseline are available from the DISA STIG  
website
- Apply the IE security policies from the DISA STIG baseline
- Apply the audit policies from the DISA STIG baseline

There is a further **Delta baseline** policy that is used to enforce 
additional security settings or to loosen security settings where they 
interfere with operation of the system. For example, the Microsoft SCM policy 
will prevent local accounts from logging on remotely, including the local 
administrator. When a system is joined to a domain, this isn't a problem as 
domain accounts would still be able to login. However, on a system that is not 
(or not yet) joined to a domain, or environments where there is no local 
console access (such as many cloud infrastructures), this setting effectively 
bricks the system. As this formula is intended to support both domain-joined 
and non-domain-joined systems, as well as infrastructures of all types, the 
delta policy loosens this security setting. In a domain, it would be 
recommended to use group policy to re-apply this setting.

The **delta** policy is also used to address inconsistencies across baseline 
versions and between different OS versions. For example, the DISA STIG for 
Windows 2008 R2 has a requirement to change the name of the local 
administrator account. For whatever reason, this requirement is not present in 
the STIG for Windows 2012 R2. For the sake of operational consistency, the 
**delta** policy modifies the name of the local administrator account for all 
OS versions. Below are all the configuration tasks of the **delta** policy:

- Rename local guest account to `xGuest`
- Rename local administrator account to `xAdministrator`
- Remove `NT Authority\Local Account` from the deny network logon right and  
the deny remote interactive logon right; the settings listed below deny only  
the Guest account
  - SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
  - SeDenyNetworkLogonRight = *S-1-5-32-546
- Allow users to ignore certificate errors in IE
  - HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\PreventIgnoreCertErrors = 0


##Available States

###ash-windows
See [ash-windows.stig](#ash-windows.stig). The only content of `init.sls` is 
an `include` statement for `ash-windows.stig`.

###ash-windows.mss
The `ash-windows.mss` salt state will install the Maximum Segment Size 
extensions into the local group policy editor (gpedit.msc). This exposes the 
settings in the editor so they can be managed properly as part of a security 
policy.

###ash-windows.scm

###ash-windows.scm

###ash-windows.stig

###ash-windows.delta


##Example Usage
Targeting via top.sls


##Configuration


##Tools
- Microsoft SCM
- [Microsoft Apply_LGPO_Delta.exe][6]
- [Microsoft ImportRegPol.exe][6]


##References

- Security Control Automated Protocol (SCAP) - [0](http://scap.nist.gov/) 
- SCAP Content - [1](http://web.nvd.nist.gov/view/ncp/repository?keyword=Microsoft+Windows&startIndex=0) 
- Microsoft Security Compliance Manager (SCM) - [2](http://www.microsoft.com/scm)
- DISA STIG Benchmarks - [3](http://iase.disa.mil/stigs/os/windows)
- Microsoft MSS Registry Settings - [4](https://technet.microsoft.com/en-us/library/dd349797(v=ws.10).aspx)
- Microsoft Pass the Hash (PtH) group policy extensions - [5](http://blogs.technet.com/b/secguide/archive/2014/08/13/security-baselines-for-windows-8-1-windows-server-2012-r2-and-internet-explorer-11-final.aspx)
- Microsoft LGPO Utilities - [6](http://blogs.technet.com/b/fdcc/archive/2008/05/07/lgpo-utilities.aspx)