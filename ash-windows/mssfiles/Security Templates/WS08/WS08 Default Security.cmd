@echo off
REM (c) Microsoft Corporation 2009
REM
REM Security Configuration Template for Security Configuration Editor
REM
REM File Name   WS08 Default Security.cmd
REM Version     1.0
REM
REM This batch file is included with the LocalGPO Tool. 
REM It is used to reset the local security policy of a 
REM Windows Server 2008 computer to the Windows Server 2008 default settings.  

reg delete "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v TcpMaxDataRetransmissions /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxConnectResponseRetransmissions /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v PerformRouterDiscovery /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v EnableDeadGWDetect /F
reg delete "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /F
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /F
reg delete "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /F
reg delete "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RefusePasswordChange /F
reg delete "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v NoNameReleaseOnDemand /F
reg delete "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /F
reg delete "HKLM\System\CurrentControlSet\Services\Lanmanserver\Parameters" /v Hidden /F
reg delete "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /F
reg delete "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /F
reg delete "HKLM\System\CurrentControlSet\Services\IPSEC" /v NoDefaultExempt /F
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /F
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /F
reg delete "HKLM\System\CurrentControlSet\Control\Lsa" /v SubmitControl /F
reg delete "HKLM\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /F
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\DCOM" /v MachineLaunchRestriction /F
reg delete "HKLM\Software\Policies\Microsoft\Windows NT\DCOM" /v MachineAccessRestriction /F
reg delete "HKLM\Software\Policies\Microsoft\Cryptography" /v ForceKeyProtection /F
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLockedUserId /F
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /F
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /F
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /F
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD /F
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /F
