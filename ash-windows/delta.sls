{% from "ash-windows/map.jinja" import ash with context %}

Create Delta Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell

#Apply Delta Template
Apply Delta Template:
  cmd.run:
    - name: 'start /wait .\Apply_LGPO_Delta.exe {{ ash.delta_cwd }}\GpoDelta.inf /log "{{ ash.common_logdir }}\ash-GpoDelta-tmpl.log" /error "{{ ash.common_logdir }}\ash-GpoDelta-tmpl.err"'
    - cwd: {{ ash.common_tools }}
    - require:
        - cmd: 'Create Delta Log Directory'

#Apply Delta Policy
Apply Delta Policy:
  cmd.run:
    - name: 'start /wait .\Apply_LGPO_Delta.exe {{ ash.delta_cwd }}\GpoDelta.txt /log "{{ ash.common_logdir }}\ash-GpoDelta-pol.log" /error "{{ ash.common_logdir }}\ash-GpoDelta-pol.err"'
    - cwd: {{ ash.common_tools }}
    - require:
        - cmd: 'Apply Delta Template'
