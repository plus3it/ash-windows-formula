{% from "ash-windows/map.jinja" import ash with context %}

include:
  - ash-windows.tools

Create IAVM Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell


#Apply IAVM Policy
Apply IAVM Policy:
  cmd.run:
    - name: 'start /wait {{ ash.apply_lgpo_filename }} {{ ash.iavm_cwd }}\GpoIAVM.txt /log "{{ ash.common_logdir }}\ash-GpoIAVM-pol.log" /error "{{ ash.common_logdir }}\ash-GpoIAVM-pol.err"'
    - require:
        - cmd: 'Create IAVM Log Directory'

#Disable SSL 3.0 for server software
Disable SSL 3.0 Server:
  reg.present:
    - name: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\Enabled'
    - value: 0
    - vtype: REG_DWORD
    - reflection: False

#Disable SSL 3.0 for client software
Disable SSL 3.0 Client:
  reg.present:
    - name: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\Enabled'
    - value: 0
    - vtype: REG_DWORD
    - reflection: False
