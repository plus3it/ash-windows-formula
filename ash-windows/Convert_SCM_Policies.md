-   Standup a Windows 8.1 VM

-   Download [SCM](http://www.microsoft.com/scm)

-   Install SCM to Windows 8.1 VM

-   Run SCM and update the database for IE8-11, ws2008r2, ws2012r2, ws2016,
    win81, and win10

-   Extract the user and machine registry .pol files for each

-   Use ImportRegPol.exe from [lgpo-utilities](
  http://blogs.technet.com/b/fdcc/archive/2008/05/07/lgpo-utilities.aspx) to
  convert the .pol files to .txt policies

-   Name user policies 'user_registry.pol' and machine policies
'machine_registry.pol'

-   Grab any GptTmpl.inf and audit.csv files while at it

-   Place the files in the appropriate directory under ash-windows/scm

-   Run the PowerShell code below from the root of the ash-windows-formula repo

```powershell
$baselines = @(
    'IE_10'
    'IE_11'
    'IE_8'
    'IE_9'
    'Windows_2008ServerR2_DC'
    'Windows_2008ServerR2_MS'
    'Windows_2012ServerR2_DC'
    'Windows_2012ServerR2_MS'
    'Windows_2016Server_DC'
    'Windows_2016Server_MS'
    'Windows_8_1'
    'Windows_10'
)

foreach ($baseline in $baselines)
{
    $dir = ".\ash-windows\scm\$baseline"
    $gpttmpl_inf = "$dir\GptTmpl.inf"
    $user_pol = "$dir\user_registry.pol"
    $machine_pol = "$dir\machine_registry.pol"

    $TxtFile = "$gpttmpl_inf"
    $YmlFile = "$(Resolve-Path $dir)\gpttmpl.yml"
    if (Test-Path "$TxtFile")
    {
        Write-Host "Processing $TxtFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$TxtFile" `
            dst_file="$YmlFile"
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }

    $TxtFile = "${dir}\user_registry.txt"
    $YmlFile = "${dir}\user_registry.yml"
    rm $TxtFile -ErrorAction SilentlyContinue
    if (Test-Path "$user_pol")
    {
        .\ash-windows\tools\ImportRegPol.exe -u "$user_pol" /log "$TxtFile" /parseOnly
        Write-Host "Processing $TxtFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$TxtFile" `
            dst_file="$YmlFile"
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }

    $TxtFile = "${dir}\machine_registry.txt"
    $YmlFile = "${dir}\machine_registry.yml"
    rm $TxtFile -ErrorAction SilentlyContinue
    if (Test-Path "$machine_pol")
    {
        .\ash-windows\tools\ImportRegPol.exe -m "$machine_pol" /log "$TxtFile" /parseOnly
        Write-Host "Processing $TxtFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$TxtFile" `
            dst_file="$YmlFile"
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }
}
```
