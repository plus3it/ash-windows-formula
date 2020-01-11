- Download the SCT baseline zip files: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10
  - Be sure to select LGPO. It is used to convert GPO policies from .pol to .txt

- Unzip LGPO.zip and place the exe at `tools/LGPO.exe`

- Unzip the baseline archives on your computer

- Select a baseline to update, open the unzipped baseline folder, then open the `Local_Script` folder

- There will be a .ps1 or .cmd script in the directory. -- DO NOT DOUBLECLICK -- That will execute it; VERY BAD for your workstation. Just open it in your editor
  - For 2012r2, there is no helper script. You have to navigate into the GUID directories and open gpreport.xml. The `<name>` tag in the xml will identify whether the GPO is for a Member Server or Domain Controller

- Identitfy the GPO GUID for the corresponding baseline, e.g. *Windows_2019Server_MS* => *MSFT Windows Server 2019 - Member Server*

- Navigate to the matching GUID under the `GPOs` folder

- Open `{GUID}\DomainSysvol\GPO\Machine` and copy `registry.pol` to the `sct/<baseline>` folder, renaming it to `machine_registry.pol`

- Check for `audit.csv` and `GptTmpl.inf` files under `{GUID}\DomainSysvol\GPO\Machine\microsoft\windows nt\` and copy them to `sct/<baseline>`

- Open `{GUID}\DomainSysvol\GPO\User` and copy `registry.pol` to the `sct/<baseline>` folder, renaming it to `user_registry.pol`

- Run the PowerShell code below from the root of the ash-windows-formula repo

```powershell
$baselines = @(
    'IE_11'
    'Windows_10'
    'Windows_2012ServerR2_DC'
    'Windows_2012ServerR2_MS'
    'Windows_2016Server_DC'
    'Windows_2016Server_MS'
    'Windows_2019Server_DC'
    'Windows_2019Server_MS'
)

foreach ($baseline in $baselines)
{
    $dir = ".\ash-windows\sct\$baseline"
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
        .\ash-windows\tools\LGPO.exe /parse /u "$user_pol" | Out-File "$TxtFile" -Encoding "ascii"
        Write-Host "Processing $TxtFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$TxtFile" `
            dst_file="$YmlFile"
        rm $TxtFile -ErrorAction SilentlyContinue
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
        .\ash-windows\tools\LGPO.exe /parse /m "$machine_pol" | Out-File "$TxtFile" -Encoding "ascii"
        Write-Host "Processing $TxtFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$TxtFile" `
            dst_file="$YmlFile"
        rm $TxtFile -ErrorAction SilentlyContinue
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }
}
```
