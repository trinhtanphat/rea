#Requires -Version 5.1
<#
.SYNOPSIS
  Verify official Ghidra 12.1.4 and JDK 21 Windows ZIP archives before use.
.DESCRIPTION
  Offline, read-only check of exact artifact size and upstream SHA-256.
  Does not download, unzip, install, set environment variables, or run Java.
  Rejects partial/missing archives; only existing REA-LAB paths are read.
#>
[CmdletBinding()]
param([string]$LabRoot = 'C:\REA-LAB')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$downloads = Join-Path $lab 'toolchains\downloads'
if (-not (Test-Path -LiteralPath $downloads -PathType Container)) {
    throw 'The pre-existing lab download directory is missing.'
}
$artifacts = @(
    [ordered]@{
        role = 'Ghidra'
        version = '12.1.4'
        filename = 'ghidra_12.1.4_PUBLIC_20260921.zip'
        expectedBytes = [long]569649598
        expectedSha256 = 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
        source = 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip'
    },
    [ordered]@{
        role = 'JDK'
        version = 'Amazon Corretto 21.0.13.0.10'
        filename = 'amazon-corretto-21.0.13.0.10-windows-x64-jdk.zip'
        expectedBytes = [long]202668246
        expectedSha256 = 'abd264a79e07c64e19aaa705e5b8ea8db01d5213877b8ac0b855a94541a4b0fd'
        source = 'https://corretto.aws/downloads/resources/21.0.13.0.10/amazon-corretto-21.0.13.0.10-windows-x64-jdk.zip'
    },
    [ordered]@{
        role = 'JDK'
        version = 'Temurin 21.0.12.1+1'
        filename = 'OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'
        expectedBytes = [long]205073461
        expectedSha256 = 'f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e'
        source = 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'
    }
)
$checks = @()
foreach($spec in $artifacts) {
    $archive = Join-Path $downloads $spec.filename
    $partial = $archive + '.partial'
    $isFull = Test-Path -LiteralPath $archive -PathType Leaf
    $length = if($isFull){(Get-Item -LiteralPath $archive).Length}else{0L}
    $correctSize = $isFull -and $length -eq $spec.expectedBytes
    $digest = $null
    if($correctSize){
        $digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $ready = $correctSize -and $digest -eq $spec.expectedSha256
    $partialBytes = if(Test-Path -LiteralPath $partial -PathType Leaf){
        (Get-Item -LiteralPath $partial).Length
    }else{0L}
    $checks += [pscustomobject]@{
        role = $spec.role
        version = $spec.version
        filename = $spec.filename
        verified = $ready
        fullFileBytes = $length
        partialFileBytes = $partialBytes
        expectedBytes = $spec.expectedBytes
        expectedSha256 = $spec.expectedSha256
        actualSha256 = $digest
        releaseUrl = $spec.source
    }
}
$ghidraVerified = @($checks | Where-Object { $_.role -eq 'Ghidra' -and $_.verified }).Count -eq 1
$jdkVerified = @($checks | Where-Object { $_.role -eq 'JDK' -and $_.verified }).Count -ge 1
$allVerified = $ghidraVerified -and $jdkVerified
[ordered]@{
    ready = $allVerified
    ghidra_archive_verified = $ghidraVerified
    compatible_jdk_archive_verified = $jdkVerified
    checks = $checks
    only_read_files = $true
    extraction_attempted_by_this_script = $false
} | ConvertTo-Json -Depth 6
if (-not $allVerified) { exit 2 }
