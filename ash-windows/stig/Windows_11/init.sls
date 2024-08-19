SV-253283r828933_rule - Data Execution Prevention (DEP) must be configured to at least OptOut:
  cmd.run:
    - name: BCDEDIT /set "{current}" nx OptOut
    - shell: powershell

SV-253285r828939_rule - The Windows PowerShell 2.0 feature must be disabled on the system:
  cmd.run:
    - name: Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName MicrosoftWindowsPowerShellV2Root
    - shell: powershell
