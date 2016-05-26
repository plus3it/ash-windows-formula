```powershell
$baselines = @(
    'IE_10',
    'IE_11',
    'IE_8',
    'IE_9',
    'Windows_2008ServerR2_DC',
    'Windows_2008ServerR2_MS',
    'Windows_2012ServerR2_DC',
    'Windows_2012ServerR2_MS',
    'Windows_8.1',
    'Windows_10'
)

foreach ($baseline in $baselines)
{
    $dir = Resolve-Path ".\ash-windows\stig\$baseline"
    $StigInf = "${dir}\stig.inf"
    $StigTxt = "${dir}\stig.txt"

    $PolFile = $StigInf
    $YmlFile = "${dir}\stig.inf.yml"
    if (Test-Path "$PolFile")
    {
        Write-Host "Processing $PolFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$PolFile" `
            dst_file="$YmlFile"
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }

    $PolFile = $StigTxt
    $YmlFile = "${dir}\stig.txt.yml"
    if (Test-Path "$PolFile")
    {
        Write-Host "Processing $PolFile"
        python .\ash-windows\tools\convert-lgpo-policy.py `
            src_file="$PolFile" `
            dst_file="$YmlFile"
    }
    else
    {
        # We need to ensure an empty YmlFile exists
        $null = New-Item -Path $YmlFile -ItemType File -Force
    }
}
```
