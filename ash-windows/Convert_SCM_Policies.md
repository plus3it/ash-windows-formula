- Standup a Windows 8.1 VM
- Download [SCM](http://www.microsoft.com/scm)
- Install SCM to Windows 8.1 VM
- Run SCM and update the database for IE, ws2008r2, ws2012r2, and win81
- Extract the user and machine registry .pol files for each
- Use ImportRegPol.exe from [lgpo-utilities](http://blogs.technet.com/b/fdcc/archive/2008/05/07/lgpo-utilities.aspx) to convert the .pol files to .txt policies
- Name user policies 'user_registry.txt' and machine policies 'machine_registry.txt'
- Place the files in the appropriate directory under scmfiles

```
# Convert IE_10
.\tools\ImportRegPol.exe -u .\scmfiles\IE_10\user_registry.pol /log .\scmfiles\IE_10\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\IE_10\machine_registry.pol /log .\scmfiles\IE_10\machine_registry.txt /parseOnly

# Convert IE_11
.\tools\ImportRegPol.exe -u .\scmfiles\IE_11\user_registry.pol /log .\scmfiles\IE_11\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\IE_11\machine_registry.pol /log .\scmfiles\IE_11\machine_registry.txt /parseOnly

# Convert IE_8
.\tools\ImportRegPol.exe -u .\scmfiles\IE_8\user_registry.pol /log .\scmfiles\IE_8\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\IE_8\machine_registry.pol /log .\scmfiles\IE_8\machine_registry.txt /parseOnly

# Convert IE_9
.\tools\ImportRegPol.exe -u .\scmfiles\IE_9\user_registry.pol /log .\scmfiles\IE_9\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\IE_9\machine_registry.pol /log .\scmfiles\IE_9\machine_registry.txt /parseOnly

# Convert Server_2008_R2_DC
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2008_R2_DC\user_registry.pol /log .\scmfiles\Server_2008_R2_DC\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2008_R2_DC\machine_registry.pol /log .\scmfiles\Server_2008_R2_DC\machine_registry.txt /parseOnly

# Convert Server_2008_R2_MS
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2008_R2_MS\user_registry.pol /log .\scmfiles\Server_2008_R2_MS\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2008_R2_MS\machine_registry.pol /log .\scmfiles\Server_2008_R2_MS\machine_registry.txt /parseOnly

# Convert Server_2012_R2_DC
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2012_R2_DC\user_registry.pol /log .\scmfiles\Server_2012_R2_DC\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2012_R2_DC\machine_registry.pol /log .\scmfiles\Server_2012_R2_DC\machine_registry.txt /parseOnly

# Convert Server_2012_R2_MS
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2012_R2_MS\user_registry.pol /log .\scmfiles\Server_2012_R2_MS\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\Server_2012_R2_MS\machine_registry.pol /log .\scmfiles\Server_2012_R2_MS\machine_registry.txt /parseOnly

# Convert Windows_8_1
.\tools\ImportRegPol.exe -u .\scmfiles\Windows_8_1\user_registry.pol /log .\scmfiles\Windows_8_1\user_registry.txt /parseOnly
.\tools\ImportRegPol.exe -u .\scmfiles\Windows_8_1\machine_registry.pol /log .\scmfiles\Windows_8_1\machine_registry.txt /parseOnly
```
