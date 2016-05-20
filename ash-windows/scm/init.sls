{%- from tpldir ~ '/map.jinja' import scm with context %}

include:
  - ash-windows.tools
  - ash-windows.mss
  - .{{ scm.os_path }}

Create SCM Log Directory:
  file.directory:
    - name: {{ scm.logdir }}
    - makedirs: True

Apply Security Template:
  lgpo.present:
    - policies: {{ scm.gpttmpl_policies }}
    - logfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-GptTmpl.log
    - errorfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-GptTmpl.err
    - require:
      - file: 'Create SCM Log Directory'

Apply Computer Configuration:
  lgpo.present:
    - policies: {{ scm.computer_policies }}
    - logfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-MachineSettings.log
    - errorfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-MachineSettings.err
    - require:
      - lgpo: 'Apply Security Template'

Apply User Configuration:
  lgpo.present:
    - policies: {{ scm.user_policies }}
    - logfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-UserSettings.log
    - errorfile: {{ scm.logdir }}\scm-{{ scm.os_path }}-UserSettings.err
    - require:
      - lgpo: 'Apply Computer Configuration'

Apply Internet Explorer Machine Policy:
  lgpo.present:
    - policies: {{ scm.ie_computer_policies }}
    - logfile: {{ scm.logdir }}\scm-{{ scm.ie_path }}-MachineSettings.log
    - errorfile: {{ scm.logdir }}\scm-{{ scm.ie_path }}-MachineSettings.err
    - require:
      - lgpo: 'Apply User Configuration'

Apply Internet Explorer User Policy:
  lgpo.present:
    - policies: {{ scm.ie_user_policies }}
    - logfile: {{ scm.logdir }}\scm-{{ scm.ie_path }}-UserSettings.log
    - errorfile: {{ scm.logdir }}\scm-{{ scm.ie_path }}-UserSettings.err
    - require:
      - lgpo: 'Apply Internet Explorer Machine Policy'

Apply SCM Audit Policy:
  file.managed:
    - name: {{ scm.win_audit_file_name }}
    - source: {{ scm.audit_file_source }}
    - makedirs: True
    - require:
      - lgpo: 'Apply Internet Explorer User Policy'
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
