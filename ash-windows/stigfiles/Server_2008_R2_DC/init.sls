#The Smart Card Removal Policy service must be configured to automatic
CCE-24365-9:
  cmd.run:
    - name: 'Get-Service -name SCPolicySvc | Set-Service -StartupType "Automatic" -PassThru | Start-Service'
    - shell: powershell

#Optional Subsystems will not be permitted to operate on the system
#vdata: [] is an empty list in python -- to clear a Multi-Sz key, set it to an empty list
CCE-10913-2:
  reg.present:
    - name: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems'
    - vname: 'Optional'
    - vdata: []
    - vtype: REG_MULTI_SZ
    - reflection: False
