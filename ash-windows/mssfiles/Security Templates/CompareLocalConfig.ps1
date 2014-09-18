#===============================================================================
# *** Microsoft Solution Accelerators: Security and Compliance
# *** 
# *** --------------------------------------------------------------------------
# *** Filename   :  CompareLocalConfig.ps1
# *** --------------------------------------------------------------------------
# *** Description:  Compares the contents of a GPO Backup or GPOPack to the local 
# ***               configuration of a Windows computer without applying any settings.
# ***               Works on WS08R2/Win7 or later computers.
# ***
# *** ---T-----------------------------------------------------------------------
# *** Version    :  3.0
# *** Notes      :  Send questions and feedback to secwish@microsoft.com	
# *** --------------------------------------------------------------------------
# *** Copyright (C) Microsoft Corporation 2012, All Rights Reserved
# *** --------------------------------------------------------------------------
# ***
#===============================================================================


#Basic file manipulation that enables successful comparison of .POL file contents
#Leverages LocalPOL.exe to create txt files that are easily compared using PS
Function process-POL([string]$POLFile,[string]$POLTxt)
{
    #LocalPOL.exe is called differently if using a GPOPack
    If ((Test-Path .\LocalPol.exe) -eq $True)
    {
        & .\LocalPol.exe -f $POLFile >> $POLTxt
    }
    Else
    {
        & .\LocalConfig\LocalPol.exe -f $POLFile >> $POLTxt
    }
    
    #.POL contains settings if $POLTxt created with LocalPol.exe has more than 2 lines
    If ((Get-content $POLTxt | select -skip 2) -ne $Null)
    {
        #Don't need the first line... it is unique for each $POLTxt
        $POLResult = Get-content $POLTxt | where {$_ -ne ""} | select -skip 1
    }
    Else
    {
        $POLResult = "Empty .POL File!"
    }   
    return $POLResult
}

#Performs GPO file comparisons, and returns diff object
Function compareGPOFiles([string]$masterFilePath,[string]$configFilePath,[string]$POLMasterTxt,[string]$POLConfigTxt)
{
    $global:noMaster = Test-Path $masterFilePath
    $global:noConfig = Test-Path $configFilePath

    If (($global:noMaster -eq $False) -and ($global:noConfig -eq $False))
    {
        return "No Files to Compare!"
    }

    If (($global:noMaster) -eq $False)
    {
        $master = "No Master File!"        
    }
    ElseIf ($POLMasterTxt -ne "")
    {
        $master = process-POL $masterFilePath $POLMasterTxt
    }
    Else
    {
        $master = Get-content $masterFilePath
    }

    If (($global:noConfig) -eq $False)
    {
        $config = "No Config File!"
    }
    ElseIf ($POLConfigTxt -ne "")
    {
        $config = process-POL $configFilePath $POLConfigTxt
    }
    Else
    {
	    $config = Get-content $configFilePath
    }

    $fileDiff = Compare-Object $master $config

    return $fileDiff
}

#Analyzes comparison results, reports findings to the screen, and logs results to a text file. 
Function reportLogResults($fileDiff,[string]$compareFiles,[string]$noFilestoCompare,[string]$noMastertoCompare,[string]$noConfigtoCompare,[string]$filesMatch)
{
    Write-Host $compareFiles
    Add-Content $global:compareResults $compareFiles
        
	If (($global:noMaster -eq $False) -and ($global:noConfig -eq $False))
	{
	    Write-Host $noFilestoCompare -ForegroundColor Green
		Add-Content $global:compareResults $noFilestoCompare  
	}
	ElseIf ($global:noMaster -eq $False)
	{
	    Write-Host $noMastertoCompare -ForegroundColor Green
		Add-Content $global:compareResults $noMastertoCompare  
	}
	ElseIf ($global:noConfig -eq $False)
	{
	    Write-Host $noConfigtoCompare -ForegroundColor Green
		Add-Content $global:compareResults $noConfigtoCompare  
	}
	ElseIf ($fileDiff -eq $Null)
	{
	    Write-Host $filesMatch -ForegroundColor Green
		Add-Content $global:compareResults $filesMatch
		
		$global:gpoBackupEmpty = $False  
	}
    Else
    {
	    Write-Host $global:differencesFound -ForegroundColor Red
	    $fileDiff | Format-List

	    Add-Content $global:compareResults $global:differencesFound 
	    Add-Content $global:compareResults $fileDiff

        $global:gpoBackupEmpty = $False
		$global:overallConfigCompliant = $False
        
    }
 }

#===============================================================================
#Main - Start comparing and reporting 
#===============================================================================

#Some Global strings
$global:currentFolder = Get-Location
$global:currentTime = Get-Date
$global:compareResults = Get-Date -uformat "%Y%d%m-%H%M%S-CompareResults.txt"

$global:gpoPath1 = $args[0]
$global:gpoPath2 = $args[1]

if (($global:gpoPath1 -ne $Null) -and ($global:gpoPath2 -ne $Null))
{
    Set-Location $global:gpoPath1
    $global:currentFolder = Get-Location
    write-host $global:currentFolder
    New-Item .\LocalConfig -type directory
    Copy-Item "$global:gpoPath2\DomainSysvol" .\LocalConfig -Recurse
}

#Computer config is assumed to be compliant
$global:overallConfigCompliant = $True
$global:gpoBackupEmpty = $True

#Global Report here-strings
$global:differencesFound = @"

Differences found!

"@
$global:emptyGPOBackup = @"

Empty GPO Backup... nothing to compare!

"@

#Build report header 
$reportHeader = @"

Comparing GPO Backup against Computer Configuration
GPO Backup source folder: $global:currentFolder
Computer: $env:COMPUTERNAME

"@
Write-host $reportHeader
Add-Content $global:compareResults $reportHeader

#===============================================================================
#Compare INFs - Security Template settings
#===============================================================================
#INF file paths
$INFMasterFile = ".\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
$INFConfigFile = ".\LocalConfig\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"

#INF compare here-strings
$compareINFs = @"

Comparing Security Settings(.INF settings):
"@
$noINFstoCompare = @"
Nothing to compare... GPO Backup does not contain .INF settings!

"@
$noMasterINFtoCompare = @"
No Master .INF file to compare!

"@
$noConfigINFtoCompare = @"
No Config .INF file to compare!

"@
$INFsMatch = @"
GPO Backup and .INF settings Match!

"@

#Comparing INF configuration
$fileDiff = compareGPOFiles $INFMasterFile $INFConfigFile $Null $Null
reportLogResults $fileDiff $compareINFs $noINFstoCompare $noMasterINFtoCompare $noConfigINFtoCompare $INFsMatch

#===============================================================================
#Compare POLs - Administrative template settings 
#===============================================================================
#Paths to registry.pol files inside the GPO backup or GPOPack
$POLMachineMasterFile = ".\DomainSysvol\GPO\Machine\registry.pol"
$POLUserMasterFile = ".\DomainSysvol\GPO\User\registry.pol"

#Paths to registry.pol files created based on the computer's current config
$POLMachineConfigFile = ".\LocalConfig\DomainSysvol\GPO\Machine\registry.pol"
$POLUserConfigFile = ".\LocalConfig\DomainSysvol\GPO\User\registry.pol"

#Text files created using LocalPOL.exe
$POLMachineMasterTxt = ".\LocalConfig\DomainSysvol\GPO\Machine\PolMachineMaster.txt"
$POLUserMasterTxt = ".\LocalConfig\DomainSysvol\GPO\User\PolUserMaster.txt"
$POLMachineConfigTxt = ".\LocalConfig\DomainSysvol\GPO\Machine\PolMachineConfig.txt"
$POLUserConfigTxt = ".\LocalConfig\DomainSysvol\GPO\User\PolUserConfig.txt"

#POL compare here-strings
$compareMachinePOLs = @"

Comparing Adminstrative Template Machine Settings(.POL settings):
"@
$noMachinePOLstoCompare = @"
Nothing to compare... GPO Backup does not contain machine .POL settings!

"@
$noMasterMachinePOLtoCompare = @"
No Master machine .POL to compare!

"@
$noConfigMachinePOLtoCompare = @"
No Config machine .POL to compare!

"@
$machinePOLsMatch =  @"
GPO Backup and Computer .POL settings Match!

"@
$compareUserPOLs = @"

Comparing Adminstrative Template User Settings(.POL settings):
"@
$noUserPOLstoCompare = @"
Nothing to compare... GPO Backup does not contain user .POL settings!

"@
$noMasterUserPOLtoCompare = @"
No Master user .POL to compare!

"@
$noConfigUserPOLtoCompare = @"
No Config user .POL to compare!

"@
$userPOLsMatch =  @"
GPO Backup and User .POL settings Match!

"@

$fileDiff = compareGPOFiles $POLMachineMasterFile $POLMachineConfigFile $POLMachineMasterTxt $POLMachineConfigTxt
reportLogResults $fileDiff $compareMachinePOLs $noMachinePOLstoCompare $noMasterMachinePOLtoCompare $noConfigMachinePOLtoCompare $machinePOLsMatch

$fileDiff = compareGPOFiles $POLUserMasterFile $POLUserConfigFile $POLUserMasterTxt $POLUserConfigTxt
reportLogResults $fileDiff $compareUserPOLs $noUserPOLstoCompare $noMasterUserPOLtoCompare $noConfigUserPOLtoCompare $userPOLsMatch

#===============================================================================
#Compare CSV - Advanced Audit Policy settings
#===============================================================================
$CSVMasterFile = ".\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"
$CSVConfigFile = ".\LocalConfig\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"

#CSV compare here-strings
$compareAuditCSVs = @"

Comparing Audit Policy Settings(.CSV settings):
"@
$noAuditCSVstoCompare = @"
Nothing to compare... GPO Backups do not contain Audit Policy .CSV settings!

"@
$noMasterAuditCSVstoCompare = @"
No Master Audit Policy .CSV to compare!

"@
$noConfigAuditCSVstoCompare = @"
No Config Audit Policy .CSV to compare!

"@
$auditCSVsMatch =  @"
GPO Backup and Computer Audit Policy Match!

"@

$fileDiff = compareGPOFiles $CSVMasterFile $CSVConfigFile $Null $Null
reportLogResults $fileDiff $compareAuditCSVs $noAuditCSVstoCompare $noMasterAuditCSVstoCompare $noConfigAuditCSVstoCompare $auditCSVsMatch

#Build report footer
$configMisMatch = @"


System Configuration does not match contents of GPO Backup!


"@
$configMatch = @"


System Configuration matches contents of GPO Backup!


"@
$report = @"
Report saved to $currentFolder\$global:compareResults

"@
$reportCreated = @"
Report created $global:currentTime

"@

#Reports overall comparison result
If ($global:overallConfigCompliant -eq $False)
{
	Write-Host $configMisMatch -ForegroundColor Red
	Add-Content $global:compareResults $configMisMatch
}
ElseIF (($global:overallConfigCompliant -eq $True) -and ($global:gpoBackupEmpty -eq $False))
{
	Write-Host $configMatch -ForegroundColor Green
	Add-Content $global:compareResults $configMatch
}
Else
{
	Write-Host $global:emptyGPOBackup -ForegroundColor Red
	Add-Content $global:compareResults $global:emptyGPOBackup
}

Write-Host $report
Add-Content $global:compareResults $reportCreated

#Cleanup - Removes folder containing local configuration
Remove-Item .\LocalConfig -Recurse

# SIG # Begin signature block
# MIIaUgYJKoZIhvcNAQcCoIIaQzCCGj8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwVh8JIXVoIITlAAK/WR+7CbS
# JDSgghUmMIIEmTCCA4GgAwIBAgITMwAAAJ0ejSeuuPPYOAABAAAAnTANBgkqhkiG
# 9w0BAQUFADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMw
# IQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQTAeFw0xMjA5MDQyMTQy
# MDlaFw0xMzAzMDQyMTQyMDlaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6pElsEPsi
# nGWiFpg7y2Fi+nQprY0GGdJxWBmKXlcNaWJuNqBO/SJ54B3HGmGO+vyjESUWyMBY
# LDGKiK4yHojbfz50V/eFpDZTykHvabhpnm1W627ksiZNc9FkcbQf1mGEiAAh72hY
# g1tJj7Tf0zXWy9kwn1P8emuahCu3IWd01PZ4tmGHmJR8Ks9n6Rm+2bpj7TxOPn0C
# 6/N/r88Pt4F+9Pvo95FIu489jMgHkxzzvXXk/GMgKZ8580FUOB5UZEC0hKo3rvMA
# jOIN+qGyDyK1p6mu1he5MPACIyAQ+mtZD+Ctn55ggZMDTA2bYhmzu5a8kVqmeIZ2
# m2zNTOwStThHAgMBAAGjggENMIIBCTATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV
# HQ4EFgQU3lHcG/IeSgU/EhzBvMOzZSyRBZgwHwYDVR0jBBgwFoAUyxHoytK0FlgB
# yTcuMxYWuUyaCh8wVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljQ29kU2lnUENBXzA4LTMxLTIwMTAu
# Y3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraS9jZXJ0cy9NaWNDb2RTaWdQQ0FfMDgtMzEtMjAxMC5jcnQw
# DQYJKoZIhvcNAQEFBQADggEBACqk9+7AwyZ6g2IaeJxbxf3sFcSneBPRF1MoCwwA
# Qj84D4ncZBmENX9Iuc/reomhzU+p4LvtRxD+F9qHiRDRTBWg8BH/2pbPZM+B/TOn
# w3iT5HzVbYdx1hxh4sxOZLdzP/l7JzT2Uj9HQ8AOgXBTwZYBoku7vyoDd3tu+9BG
# ihcoMaUF4xaKuPFKaRVdM/nff5Q8R0UdrsqLx/eIHur+kQyfTwcJ7SaSbrOUGQH4
# X4HnrtqJj39aXoRftb58RuVHr/5YK5F/h9xGH1GVzMNiobXHX+vJaVxxkamNViAs
# Ok6T/ZsGj62K+Gh+O7p5QpM5SfXQXuxwjUJ1xYJVkBu1VWEwggS6MIIDoqADAgEC
# AgphApJKAAAAAAAgMA0GCSqGSIb3DQEBBQUAMHcxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQTAeFw0xMjAxMDkyMjI1NTlaFw0xMzA0MDkyMjI1NTlaMIGzMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYD
# VQQLEx5uQ2lwaGVyIERTRSBFU046QjhFQy0zMEE0LTcxNDQxJTAjBgNVBAMTHE1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQDNY8P3orVH2fk5lFOsa4+meTgh9NFuPRU4FsFzLJmP++A8W+Gi
# TIuyq4u08krHuZNQ0Sb1h1OwenXzRw8XK2csZOtg50qM4ItexFZpNzoqBF0XAci/
# qbfTyaujkaiB4z8tt9jkxHgAeTnP/cdk4iMSeJ4MdidJj5qsDnTjBlVVScjtoXxw
# RWF+snEWHuHBQbnS0jLpUiTzNlAE191vPEnVC9R2QPxlZRN+lVE61f+4mqdXa0sV
# 5TdYH9wADcWu6t+BR/nwUq7mz1qs4BRKpnGUgPr9sCMwYOmDYKwOJB7/EfLnpVVi
# le6ff54p1s1LCnaD8EME3wZJIPJTWkSwUXo5AgMBAAGjggEJMIIBBTAdBgNVHQ4E
# FgQUzRmsYU2UZyv2r5R1WdvwWACDoTowHwYDVR0jBBgwFoAUIzT42VJGcArtQPt2
# +7MrsMM1sw8wVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNybDBY
# BggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKGPGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNydDATBgNVHSUE
# DDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAURzW3zYd3IC8AqfGmd8W
# yJAGaRWaMrnzZBDSivNiKRt5j8pgqbNdxOQWLTWMRJvx9FxhpEGumou6UNFqeWqz
# YoydTVFQC6mO1L+iEMBH1U51UokeP5Zqjy5AFAZy7j9wWZJdhe2DmfqChJ7kAwEh
# E6sn1sxxSeXaHf9vPAlO1Y1m6AzJf+4xFAI3X3tp7Ik+RX8lROcfGtbFGsNK5OHx
# hJjnT/mpmKcYRuyEbOypAwr9fHpSHZxrpKgPmJKkknhcK3jjfbLH2bZwfd9bc1O/
# qtRmUEvwyTuVheXBSmWdJVhQuyBUkXk6GwdcalcorzHHn+fDHe5H/SfXf8903GXF
# PzCCBbwwggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEG
# CgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsG
# A1UEAxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEw
# MDgzMTIyMTkzMloXDTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmlu
# ZyBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2a
# YCAgQpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicqu
# IEn08GisTUuNpb15S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiX
# GqelcnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U
# 3RQwWfjSjWL9y8lfRjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUy
# t0vXT2Pn0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8
# wawJXwPTAgMBAAGjggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTL
# EejK0rQWWAHJNy4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUC
# AwEAATAjBgkrBgEEAYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYB
# BAGCNxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEK
# U5VZ5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29t
# L3BraS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUF
# BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aS9jZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIB
# AFk5Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2s
# PS9MuqKoVpzjcLu4tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gN
# ogOlVuC4iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOl
# kU7IG9KPcpUqcW2bGvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQv
# X/TartSCMm78pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4
# lhhcyTUWX92THUmOLb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR
# 82zKwexwo1eSV32UjaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZl
# Hg6K3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6w
# QuxO7bN2edgKNAltHIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJ
# jdibIa4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5i
# R9HOiMm4GPoOco3Boz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIK
# YRZoNAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29t
# MRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEw
# NDAzMTMwMzA5WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4k
# D+7Rp9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMk
# h53y9GccLPx754gd6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDl
# KEYuJ6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gA
# SkdmEScpZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1U
# n68eeEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIB
# pzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWz
# DzALBgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAU
# DqyCYEBWJ5flJRP8KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20x
# GTAXBgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNV
# HR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQG
# CCsGAQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y3Jvc29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQUFAAOCAgEAEJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQS
# ooxtYrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBT
# Fd1Pq5Lk541q1YDB5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2Oawpylbih
# OZxnLcVRDupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfr
# Tot/xTUrXqO/67x9C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWG
# zFFW6J1wlGysOUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H21
# 46SodDW4TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4i
# IdBD6Svpu/RIzCzU2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2
# sWo9iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1
# sMpjtHhUBdRBLlCslLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/J
# mu5J4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSW
# MIIEkgIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSMwIQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAJ0ejSeu
# uPPYOAABAAAAnTAJBgUrDgMCGgUAoIG4MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBSBGFYqCeO3GQzna7imfbnzlWirbjBYBgorBgEEAYI3AgEMMUowSKAqgCgATABv
# AGMAYQBsAEcAUABPACAAMwAuADAAIABDAG8AbQBwAGEAcgBloRqAGGh0dHA6Ly9t
# aWNyb3NvZnQuY29tL3NjbTANBgkqhkiG9w0BAQEFAASCAQCHqFZutuwOlaoOlUc9
# kYSaZmIOmbCzPJbqfyw8e1h3KEoJDp1tbhfCnPE5aYpEnjQ2V5olz7PxZ6Zx/wCl
# q+8IDBFt+e0a0dqelgceO/vwkKRX0I4MNVqe309VufsuvdcvoMMMZOWrL/Winl8j
# +qxd11aGiNkZPxSpnnekeX0phJ+W2DH8Mx6UMMtHLR9Ht1IP0W6BJjo4YK3xoJSc
# DPQ5azXvmXFPwWHrptOfPL6riK3eHuKbStYM9Y8eczRVNpWZoctI6YbZhhwx0j5a
# qsKmPslZR/KIFvtm9czoeXb4hYD3TpanWaVckMpKUjeZ5zWx3iCWKR3N8Szr8Zbi
# nur3oYICHzCCAhsGCSqGSIb3DQEJBjGCAgwwggIIAgEBMIGFMHcxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQQIKYQKSSgAAAAAAIDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTMwMTA5MTkxNDAzWjAj
# BgkqhkiG9w0BCQQxFgQUIDzgbfv0eLhKYrv9fZrDS1zZA20wDQYJKoZIhvcNAQEF
# BQAEggEAiPYh+H9K9R+lAZtPCoQ/IXMWmnPTS4m1AP/H8vnF/G0/J0D6hYsizaMA
# KaPvsXYY2ZPal6I8R1fAgXrEBThojIddS69aMN8kO+xDnlth9WIUf/d8O5cFrfiy
# W99ljNuTg4QC8W5ueBsm9v++z9QZumDIauxoVhpwTfvRTVn3+HVpcYlH41ccHS7e
# ibJk46OwOKYEpItVG2HfD4NUEREJUXZKON1pxE808sakwX0/XsvJupZfibbjSiGz
# HJVR2i5wSoVpHeDMnj1nh4D3HU/csZJMXlyEIissINq0e0rE6SEoG/sWlu3Ga+KY
# QXjZdwIJ1i6tRQdutrLLfLVkHtUTpQ==
# SIG # End signature block
