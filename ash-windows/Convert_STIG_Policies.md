- Download the latest available DISA-provided GPO baseline zip file: https://public.cyber.mil/stigs/gpo/

- Unzip the GPO baseline file on your computer

- Open the unzipped folder and browse to the desired baseline to update

- To identify the STIG GPO baseline associated with each GUID, you have to navigate into the GUID directories and open gpreport.xml. The <name> tag near the top in the xml will identify the STIG baseline provided

- Depending on the baseline, the `Machine` and `User` policies maybe under the same GUID or separate GUIDs.  In either case, the following steps still applies

  - Open `{GUID}\DomainSysvol\GPO\Machine` and copy `registry.pol` to the `stig/<baseline>` folder, renaming it to `machine_registry.pol`.  Skip this step if `registry.pol` is missing or contains no policies (e.g. File size is very small)

  - Check for `audit.csv` and `GptTmpl.inf` files under `{GUID}\DomainSysvol\GPO\Machine\microsoft\windows nt\` and copy them to `stig/<baseline>`

  - Open `{GUID}\DomainSysvol\GPO\User` and copy `registry.pol` to the `stig/<baseline>` folder, renaming it to `user_registry.pol`.  Again, skip if `registry.pol` is missing or contains no policies (e.g. File size is very small)

  - Run the PowerShell code below from the root of the ash-windows-formula repo

```powershell
$baselines = @(
    'IE_11'
    'Windows_10'
    'Windows_11'
    'Windows_2012ServerR2_DC'
    'Windows_2012ServerR2_MS'
    'Windows_2016Server_DC'
    'Windows_2016Server_MS'
    'Windows_2019Server_DC'
    'Windows_2019Server_MS'
    'Windows_2022Server_DC'
    'Windows_2022Server_MS'
)

foreach ($baseline in $baselines)
{
    $dir = ".\ash-windows\stig\$baseline"
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
    #rm $TxtFile -ErrorAction SilentlyContinue
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
    # Combine yml files into single stig.yml file
    Get-Content -Path ${dir}\user_registry.yml,${dir}\machine_registry.yml,$dir\gpttmpl.yml | Set-Content -Path $dir\stig.yml
}
```

- After a new `stig.yml` file is generated for the STIG baseline being updated, open the file and inspect the policies.  The DISA policies may have placeholder values that need to be updated or remove as needed for your environment.
