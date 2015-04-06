{% from "ash-windows/map.jinja" import ash with context %}

#Expose MSS Settings
Expose MSS Settings:
  cmd.run:
    - name: 'cscript //nologo LocalGPO.wsf /ConfigSCE'
    - cwd: {{ ash.mss_cwd }}
    - shell: powershell
