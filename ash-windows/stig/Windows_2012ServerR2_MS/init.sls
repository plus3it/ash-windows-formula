SV-71667r1_rule-Windows Error Reporting service must be enabled:
  service.enabled:
    - name: WerSvc

SV-71667r1_rule-Windows Error Reporting service must be running:
  service.running:
    - name: WerSvc
    - require:
      - service: SV-71667r1_rule-Windows Error Reporting service must be enabled

CCE-24365-9-Smart Card Removal Policy service must be enabled:
  service.enabled:
    - name: SCPolicySvc

The Server Message Block (SMB) v1 protocol must be disabled on Windows 2012 R2:
  cmd.run:
    - name: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    - shell: powershell
