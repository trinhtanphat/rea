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
$allVerified = @($checks | Where-Object { -not $_.verified }).Count -eq 0
[ordered]@{
    ready = $allVerified
    checks = $checks
    only_read_files = $true
    ghidra_installed = $false
    extraction_attempted = $false
} | ConvertTo-Json -Depth 6
if (-not $allVerified) { exit 2 }
