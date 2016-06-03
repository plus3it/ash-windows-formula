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
