{% from "ash-windows/map.jinja" import ash with context %}

include:
  - ash-windows.tools
  - ash-windows.scm
  - ash-windows.stigfiles.{{ ash.os_path }}{{ ash.role_path }}

Create STIG Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell

#Apply STIG Security Template
Apply STIG Security Template:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.stig_cwd }}\{{ ash.os_path }}{{ ash.role_path }}\stig.inf /log "{{ ash.common_logdir }}\stig-{{ ash.os_path }}{{ ash.role_path }}-gpttmpl.log" /error "{{ ash.common_logdir }}\stig-{{ ash.os_path }}{{ ash.role_path }}-gpttmpl.err"'
    - require: 
      - cmd: 'Create STIG Log Directory'

Apply STIG Security Policy:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.stig_cwd }}\{{ ash.os_path }}{{ ash.role_path }}\stig.txt /log "{{ ash.common_logdir }}\stig-{{ ash.os_path }}{{ ash.role_path }}-gptpol.log" /error "{{ ash.common_logdir }}\stig-{{ ash.os_path }}{{ ash.role_path }}-gptpol.err"'
    - require: 
      - cmd: 'Apply STIG Security Template'

Apply STIG IE Security Policy:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.stig_cwd }}\{{ ash.ie_path }}\stig.txt /log "{{ ash.common_logdir }}\stig-{{ ash.ie_path }}-iepol.log" /error "{{ ash.common_logdir }}\stig-{{ ash.ie_path }}-iepol.err"'
    - require: 
      - cmd: 'Apply STIG Security Policy'

#Apply STIG Audit Policy
Manage stig_audit.csv:
  file.managed:
    - name: {{ ash.win_audit_file_name }}
    - source: {{ ash.stig_audit_file_source }}
    - makedirs: True
    - require: 
      - cmd: 'Apply STIG IE Security Policy'
Clear STIG Audit Policy:
  cmd.run:
    - name: auditpol /clear /y
    - require: 
      - file: 'Manage stig_audit.csv'
Apply STIG Audit Policy:
  cmd.run:
    - name: auditpol /restore /file:"{{ ash.win_audit_file_name }}"
    - require: 
      - cmd: 'Clear STIG Audit Policy'

#The Windows Error Reporting Service must be running and configured to start automatically
SV-71667r1_rule:
  cmd.run:
    - name: 'Get-Service -name WerSvc | Set-Service -StartupType "Automatic" -PassThru | Start-Service'
    - shell: powershell
