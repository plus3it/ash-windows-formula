{#- From GptTmpl.inf conversion #}
Machine AllowedPaths:
  reg.present:
    - name: HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
    - vname: Machine
    - vdata:
      - System\CurrentControlSet\Control\Print\Printers
      - System\CurrentControlSet\Services\Eventlog
      - Software\Microsoft\OLAP Server
      - Software\Microsoft\Windows NT\CurrentVersion\Print
      - Software\Microsoft\Windows NT\CurrentVersion\Windows
      - System\CurrentControlSet\Control\ContentIndex
      - System\CurrentControlSet\Control\Terminal Server
      - System\CurrentControlSet\Control\Terminal Server\UserConfig
      - System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
      - Software\Microsoft\Windows NT\CurrentVersion\Perflib
      - System\CurrentControlSet\Services\SysmonLog
    - vtype: REG_MULTI_SZ

Machine AllowedExactPaths:
  reg.present:
    - name: HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths
    - vname: Machine
    - vdata:
      - System\CurrentControlSet\Control\ProductOptions
      - System\CurrentControlSet\Control\Server Applications
      - Software\Microsoft\Windows NT\CurrentVersion
    - vtype: REG_MULTI_SZ
