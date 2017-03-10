SV-85259r1_rule - The Windows PowerShell 2.0 feature must be disabled on the system:
  cmd.run:
    - name: Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName MicrosoftWindowsPowerShellV2Root
    - shell: powershell

SV-85261r1_rule - The Server Message Block (SMB) v1 protocol must be disabled on the system:
  cmd.run:
    - name: Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName SMB1Protocol
    - shell: powershell

SV-86953r1_rule - Run as different user must be removed from context menus - batfile:
  reg.present:
    - name: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\batfile\shell\runasuser
    - vname: SuppressionPolicy
    - vdata: 4096
    - vtype: REG_DWORD

SV-86953r1_rule - Run as different user must be removed from context menus - cmdfile:
  reg.present:
    - name: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\cmdfile\shell\runasuser
    - vname: SuppressionPolicy
    - vdata: 4096
    - vtype: REG_DWORD

SV-86953r1_rule - Run as different user must be removed from context menus - exefile:
  reg.present:
    - name: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser
    - vname: SuppressionPolicy
    - vdata: 4096
    - vtype: REG_DWORD

SV-86953r1_rule - Run as different user must be removed from context menus - mscfile:
  reg.present:
    - name: HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\runasuser
    - vname: SuppressionPolicy
    - vdata: 4096
    - vtype: REG_DWORD
