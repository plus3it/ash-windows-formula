{% from "ash-windows/map.jinja" import ash with context %}

include:
  - ash-windows.tools

Create Delta Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell

#Apply Delta Template
Apply Delta Template:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.delta_cwd }}\GpoDelta.inf /log "{{ ash.common_logdir }}\ash-GpoDelta-tmpl.log" /error "{{ ash.common_logdir }}\ash-GpoDelta-tmpl.err"'
    - require:
        - cmd: 'Create Delta Log Directory'

#Apply Delta Policy
Apply Delta Policy:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.delta_cwd }}\GpoDelta.txt /log "{{ ash.common_logdir }}\ash-GpoDelta-pol.log" /error "{{ ash.common_logdir }}\ash-GpoDelta-pol.err"'
    - require:
        - cmd: 'Apply Delta Template'
