#The Smart Card Removal Policy service must be configured to automatic
CCE-24365-9:
  cmd.run:
    - name: 'Get-Service -name SCPolicySvc | Set-Service -StartupType "Automatic" -PassThru | Start-Service'
    - shell: powershell
