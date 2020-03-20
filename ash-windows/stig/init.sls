{%- from tpldir ~ '/map.jinja' import stig with context %}

include:
  - ash-windows.sct
  - .{{ stig.os_path }}
  - .dodcerts

Apply STIG Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ stig.stig_policies | yaml }}

Apply IE STIG Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ stig.ie_stig_policies | yaml }}
    - require:
      - ash_lgpo: Apply STIG Local Group Policy Objects

Apply .NET STIG Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ stig.dotnet_stig_policies | yaml }}
    - require:
      - ash_lgpo: Apply STIG Local Group Policy Objects

Apply STIG Audit Policy:
  file.managed:
    - name: {{ stig.win_audit_file_name }}
    - source: {{ stig.audit_file_source }}
    - makedirs: True
    - require:
      - ash_lgpo: Apply IE STIG Local Group Policy Objects
  cmd.run:
    - name: auditpol /clear /y && auditpol /restore /file:"{{ stig.win_audit_file_name }}"
    - require:
      - file: Apply STIG Audit Policy
