{%- from tpldir ~ '/map.jinja' import sct with context %}

include:
  - ash-windows.tools
  - ash-windows.mss
  - .{{ sct.os_path }}

Create SCT Log Directory:
  file.directory:
    - name: {{ sct.logdir }}
    - makedirs: True

Apply Security Template:
  lgpo.present:
    - policies: {{ sct.gpttmpl_policies | yaml }}
    - logfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-GptTmpl.log
    - errorfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-GptTmpl.err
    - require:
      - file: 'Create sct Log Directory'

Apply Computer Configuration:
  lgpo.present:
    - policies: {{ sct.computer_policies | yaml }}
    - logfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-MachineSettings.log
    - errorfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-MachineSettings.err
    - require:
      - lgpo: 'Apply Security Template'

Apply User Configuration:
  lgpo.present:
    - policies: {{ sct.user_policies | yaml}}
    - logfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-UserSettings.log
    - errorfile: {{ sct.logdir }}\sct-{{ sct.os_path }}-UserSettings.err
    - require:
      - lgpo: 'Apply Computer Configuration'

Apply Internet Explorer Machine Policy:
  lgpo.present:
    - policies: {{ sct.ie_computer_policies | yaml}}
    - logfile: {{ sct.logdir }}\sct-{{ sct.ie_path }}-MachineSettings.log
    - errorfile: {{ sct.logdir }}\sct-{{ sct.ie_path }}-MachineSettings.err
    - require:
      - lgpo: 'Apply User Configuration'

Apply Internet Explorer User Policy:
  lgpo.present:
    - policies: {{ sct.ie_user_policies | yaml }}
    - logfile: {{ sct.logdir }}\sct-{{ sct.ie_path }}-UserSettings.log
    - errorfile: {{ sct.logdir }}\sct-{{ sct.ie_path }}-UserSettings.err
    - require:
      - lgpo: 'Apply Internet Explorer Machine Policy'

Apply SCT Audit Policy:
  file.managed:
    - name: {{ sct.win_audit_file_name }}
    - source: {{ sct.audit_file_source }}
    - makedirs: True
    - require:
      - lgpo: 'Apply Internet Explorer User Policy'
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
