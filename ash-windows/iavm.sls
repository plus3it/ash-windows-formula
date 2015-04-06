{% from "ash-windows/map.jinja" import ash with context %}

Create IAVM Log Directory:
  cmd.run:
    - name: 'md "{{ ash.common_logdir }}" -Force'
    - shell: powershell


#Apply IAVM Policy
Apply IAVM Policy:
  cmd.run:
    - name: 'start /wait Tools\Apply_LGPO_Delta.exe GpoIAVM.txt /log "{{ ash.common_logdir }}\ash-GpoIAVM-pol.log" /error "{{ ash.common_logdir }}\ash-GpoIAVM-pol.err"'
    - cwd: {{ ash.iavm_cwd }}
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
