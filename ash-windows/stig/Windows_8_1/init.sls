SV-71665r1_rule-Windows Error Reporting service must be enabled:
  service.enabled:
    - name: WerSvc

SV-71665r1_rule-Windows Error Reporting service must be running:
  service.running:
    - name: WerSvc
    - require:
      - service: SV-71665r1_rule-Windows Error Reporting service must be enabled
