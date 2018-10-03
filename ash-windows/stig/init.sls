{%- from tpldir ~ '/map.jinja' import stig with context %}

include:
  - ash-windows.tools
  - ash-windows.scm
  - .{{ stig.os_path }}
  - .dodcerts

Create STIG Log Directory:
  file.directory:
    - name: {{ stig.logdir }}
    - makedirs: True

Apply STIG Local Group Policy Objects:
  lgpo.present:
    - policies: {{ stig.stig_policies | yaml }}
    - logfile: {{ stig.logdir }}\stig-{{ stig.os_path }}-MachineSettings.log
    - errorfile: {{ stig.logdir }}\stig-{{ stig.os_path }}-MachineSettings.err
    - require:
      - file: Create STIG Log Directory

Apply IE STIG Local Group Policy Objects:
  lgpo.present:
    - policies: {{ stig.ie_stig_policies | yaml }}
    - logfile: {{ stig.logdir }}\stig-{{ stig.ie_path }}-MachineSettings.log
    - errorfile: {{ stig.logdir }}\stig-{{ stig.ie_path }}-MachineSettings.err
    - require:
      - lgpo: Apply STIG Local Group Policy Objects

Apply STIG Audit Policy:
  file.managed:
    - name: {{ stig.win_audit_file_name }}
    - source: {{ stig.audit_file_source }}
    - makedirs: True
    - require:
      - lgpo: Apply IE STIG Local Group Policy Objects
  cmd.run:
    - name: auditpol /clear /y && auditpol /restore /file:"{{ stig.win_audit_file_name }}"
    - require:
      - file: Apply STIG Audit Policy
