{%- from tpldir ~ '/map.jinja' import scm with context %}

{%- if grains.osrelease not in ['2008ServerR2', '8.1'] %}

include:
  - ash-windows.sct

{%- else %}

include:
  - ash-windows.mss
  - .{{ scm.os_path }}

Apply Security Template:
  ash_lgpo.present:
    - policies: {{ scm.gpttmpl_policies | yaml }}

Apply Computer Configuration:
  ash_lgpo.present:
    - policies: {{ scm.computer_policies | yaml }}
    - require:
      - ash_lgpo: 'Apply Security Template'

Apply User Configuration:
  ash_lgpo.present:
    - policies: {{ scm.user_policies | yaml}}
    - require:
      - ash_lgpo: 'Apply Computer Configuration'

Apply Internet Explorer Machine Policy:
  ash_lgpo.present:
    - policies: {{ scm.ie_computer_policies | yaml}}
    - require:
      - ash_lgpo: 'Apply User Configuration'

Apply Internet Explorer User Policy:
  ash_lgpo.present:
    - policies: {{ scm.ie_user_policies | yaml }}
    - require:
      - ash_lgpo: 'Apply Internet Explorer Machine Policy'

Apply SCM Audit Policy:
  file.managed:
    - name: {{ scm.win_audit_file_name }}
    - source: {{ scm.audit_file_source }}
    - makedirs: True
    - require:
      - ash_lgpo: 'Apply Internet Explorer User Policy'
  cmd.run:
    - name: auditpol /clear /y && auditpol /restore /file:"{{ scm.win_audit_file_name }}"
    - require:
      - file: 'Apply SCM Audit Policy'

Manage Pass the Hash ADMX:
  file.managed:
    - name: {{ scm.pth_admx_name }}
    - source: {{ scm.pth_admx_source }}
    - require:
      - cmd: 'Apply SCM Audit Policy'

Manage Pass the Hash ADML:
  file.managed:
    - name: {{ scm.pth_adml_name }}
    - source: {{ scm.pth_adml_source }}
    - require:
      - cmd: 'Apply SCM Audit Policy'

{%- endif %}
