{% from "ash-windows/map.jinja" import ash with context %}

include:
  - ash-windows.mss

Create SCM Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell
    - require: 
      - cmd: 'Expose MSS Settings'

#Apply Security Template
Apply Security Template:
  cmd.run:
    - name: 'start /wait .\Apply_LGPO_Delta.exe {{ ash.scm_cwd }}\{{ ash.os_path }}{{ ash.role_path }}\GptTmpl.inf /log "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}-gpttmpl.log" /error "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}-gpttmpl.err"'
    - cwd: {{ ash.common_tools }}
    - require: 
      - cmd: 'Create SCM Log Directory'

#Apply Computer Configuration
Apply Computer Configuration:
  cmd.run:
    - name: 'start /wait .\ImportRegPol.exe /m {{ ash.scm_cwd }}\{{ ash.os_path }}{{ ash.role_path }}\machine_registry.pol /log "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}MachineSettings.log" /error "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}MachineSettings.err"'
    - cwd: {{ ash.common_tools }}
    - require: 
      - cmd: 'Apply Security Template'

#Apply User Configuration
Apply User Configuration:
  cmd.run:
    - name: 'start /wait .\ImportRegPol.exe /u {{ ash.scm_cwd }}\{{ ash.os_path }}{{ ash.role_path }}\user_registry.pol /log "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}UserSettings.log" /error "{{ ash.common_logdir }}\{{ ash.os_path }}{{ ash.role_path }}UserSettings.err"'
    - cwd: {{ ash.common_tools }}
    - require: 
      - cmd: 'Apply Computer Configuration'

#Apply Internet Explorer Machine Policy
Apply Internet Explorer Machine Policy:
  cmd.run:
    - name: 'start /wait .\ImportRegPol.exe /m {{ ash.scm_cwd }}\{{ ash.ie_path }}\machine_registry.pol /log "{{ ash.common_logdir }}\IEMachineSettings.log" /error "{{ ash.common_logdir }}\IEMachineSettings.err"'
    - cwd: {{ ash.common_tools }}
    - require: 
      - cmd: 'Apply User Configuration'

#Apply Internet Explorer User Policy
Apply Internet Explorer User Policy:
  cmd.run:
    - name: 'start /wait .\ImportRegPol.exe /u {{ ash.scm_cwd }}\{{ ash.ie_path }}\user_registry.pol /log "{{ ash.common_logdir }}\IEUserSettings.log" /error "{{ ash.common_logdir }}\IEUserSettings.err"'
    - cwd: {{ ash.common_tools }}
    - require: 
      - cmd: 'Apply Internet Explorer Machine Policy'

#Apply Audit Policy
Manage SCM Audit.csv:
  file.managed:
    - name: {{ ash.win_audit_file_name }}
    - source: {{ ash.scm_audit_file_source }}
    - makedirs: True
    - require: 
      - cmd: 'Apply Internet Explorer User Policy'
Clear Audit Policy:
  cmd.run:
    - name: auditpol /clear /y
    - require: 
      - file: 'Manage SCM Audit.csv'
Apply Audit Policy:
  cmd.run:
    - name: auditpol /restore /file:"{{ ash.win_audit_file_name }}"
    - require: 
      - cmd: 'Clear Audit Policy'

#Copy Custom Administrative Template for Pass the Hash mitigations
PtH.admx:
  file.managed:
    - name: {{ ash.scm_pth_admx_name }}
    - source: {{ ash.scm_pth_admx_source }}
    - require: 
      - cmd: 'Apply Audit Policy'

PtH.adml:
  file.managed:
    - name: {{ ash.scm_pth_adml_name }}
    - source: {{ ash.scm_pth_adml_source }}
    - require: 
      - file: PtH.admx