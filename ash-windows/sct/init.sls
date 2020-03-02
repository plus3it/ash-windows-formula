{%- from tpldir ~ '/map.jinja' import sct with context %}

include:
  - ash-windows.mss
  - .{{ sct.os_path }}

Apply Security Template:
  ash_lgpo.present:
    - policies: {{ sct.gpttmpl_policies | yaml }}

Apply Computer Configuration:
  ash_lgpo.present:
    - policies: {{ sct.computer_policies | yaml }}
    - require:
      - ash_lgpo: 'Apply Security Template'

Apply User Configuration:
  ash_lgpo.present:
    - policies: {{ sct.user_policies | yaml}}
    - require:
      - ash_lgpo: 'Apply Computer Configuration'

Apply Internet Explorer Machine Policy:
  ash_lgpo.present:
    - policies: {{ sct.ie_computer_policies | yaml}}
    - require:
      - ash_lgpo: 'Apply User Configuration'

Apply Internet Explorer User Policy:
  ash_lgpo.present:
    - policies: {{ sct.ie_user_policies | yaml }}
    - require:
      - ash_lgpo: 'Apply Internet Explorer Machine Policy'

Apply SCT Audit Policy:
  file.managed:
    - name: {{ sct.win_audit_file_name }}
    - source: {{ sct.audit_file_source }}
    - makedirs: True
    - require:
      - ash_lgpo: 'Apply Internet Explorer User Policy'
  cmd.run:
    - name: auditpol /clear /y && auditpol /restore /file:"{{ sct.win_audit_file_name }}"
    - require:
      - file: 'Apply sct Audit Policy'

Manage Pass the Hash ADMX:
  file.managed:
    - name: {{ sct.pth_admx_name }}
    - source: {{ sct.pth_admx_source }}
    - require:
      - cmd: 'Apply sct Audit Policy'

Manage Pass the Hash ADML:
  file.managed:
    - name: {{ sct.pth_adml_name }}
    - source: {{ sct.pth_adml_source }}
    - require:
      - cmd: 'Apply sct Audit Policy'
