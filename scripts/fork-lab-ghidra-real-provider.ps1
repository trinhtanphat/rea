#Requires -Version 5.1
<#
.SYNOPSIS
  Run REA 6.8.0 + real Ghidra 12.1.4 + portable JDK 21 on a source-owned PE.
.DESCRIPTION
  Lab-only, LocalSystem read-only Windows provider smoke/regression.
  The Windows PE DLL is checked by SHA-256 before and after each run.
  Each REA process is resource bounded, job-owned by native Windows code,
  and receives Java/Ghidra settings ONLY through its environment.
  No global install, registry edit, account creation, desktop interaction,
  production package replacement, or GitHub Actions.
#>
[CmdletBinding()]
param([string]$LabRoot = 'C:\REA-LAB', [switch]$Deterministic)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    throw 'This verified REA Windows P0 lane must run under LocalSystem only.'
}
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
$ghidra = Join-Path $lab 'toolchains\ghidra1214-isolated\ghidra_12.1.4_PUBLIC'
$jdk = Join-Path $lab 'toolchains\jdk21-corretto-isolated\jdk21.0.13_0'
$pkg = Join-Path $lab 'runtime\node_modules\rea-agents-pr2-hardened'
$cli = Join-Path $pkg 'scripts\rea.mjs'
$addon = Join-Path $pkg 'native\windows\build\rea-windows-x64.node'
$fixture = if($Deterministic) {
    Join-Path $lab 'fixtures\ghidra-pe-reproducible\rea_lab_arithmetic.dll'
} else {
    Join-Path $lab 'fixtures\ghidra-pe-arithmetic\rea_lab_arithmetic.dll'
}
$expectedFixtureSha = if($Deterministic) {
    '8be0a6f9f9ae5a18e2dcf65f0e0b21d0034b968c6606fb112b07133f372da299'
} else {
    'f3b3bb1f7b97924ac6d366204152592ee2ce80a1a93061fccbf27e4524996f41'
}
$temp = Join-Path $lab 'tmp'
$artifacts = Join-Path $lab 'artifacts'
$preflight = Join-Path $lab 'rea\scripts\fork-lab-ghidra-archives-preflight.ps1'
foreach ($p in @($node,$cli,$addon,$fixture,$preflight,
                 (Join-Path $ghidra 'support\analyzeHeadless.bat'),
                 (Join-Path $jdk 'bin\java.exe'))) {
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw "Missing lab input: $p" }
}
$shaAddon = (Get-FileHash -LiteralPath $addon -Algorithm SHA256).Hash.ToLowerInvariant()
$shaFixture = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
if ($shaAddon -ne '4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019' -or
    $shaFixture -ne $expectedFixtureSha) {
    throw 'Hardened addon or source-owned PE digest changed.'
}
$preflightRaw = & powershell.exe -NoProfile -File $preflight -LabRoot $lab
if($LASTEXITCODE -ne 0){ throw 'Official Ghidra/JDK archives did not verify.' }
$preflightData = $preflightRaw | ConvertFrom-Json
if($preflightData.ready -ne $true){throw 'Official Ghidra/JDK archives are not ready.'}

$workspace = Join-Path $artifacts ('ghidra-real-provider-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
function Invoke-IsolatedRea {
    param([string]$Name, [string]$Arguments, [int]$TimeoutSeconds = 150)
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $node
    $info.Arguments = ('"{0}" ' -f $cli) + $Arguments
    $info.WorkingDirectory = $workspace
    $info.CreateNoWindow = $true
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['JAVA_HOME'] = $jdk
    $info.EnvironmentVariables['GHIDRA_INSTALL_DIR'] = $ghidra
    $info.EnvironmentVariables['Path'] = (Join-Path $jdk 'bin') + ';' + $info.EnvironmentVariables['Path']
    $info.EnvironmentVariables['TEMP'] = $temp
    $info.EnvironmentVariables['TMP'] = $temp
    $info.EnvironmentVariables['JAVA_TOOL_OPTIONS'] = '-Xmx1024m'
    $process=[Diagnostics.Process]::new()
    try {
        $process.StartInfo=$info
        [void]$process.Start()
        try {
            $process.PriorityClass=[Diagnostics.ProcessPriorityClass]::BelowNormal
            $process.ProcessorAffinity=[IntPtr]15
        } catch {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw 'Cannot constrain CPU priority and affinity: '+$_.Exception.Message
        }
        $outTask=$process.StandardOutput.ReadToEndAsync()
        $errTask=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit($TimeoutSeconds * 1000)){
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw "Timeout during REA $Name."
        }
        $process.WaitForExit()
        $stdout=$outTask.GetAwaiter().GetResult()
        $stderr=$errTask.GetAwaiter().GetResult()
        if($stdout.Length -gt (6MB) -or $stderr.Length -gt (3MB)) {
            throw "Unexpected output length during REA $Name."
        }
        [IO.File]::WriteAllText((Join-Path $workspace ($Name+'.json')), $stdout,
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $workspace ($Name+'.stderr.txt')), $stderr,
            [Text.UTF8Encoding]::new($false))
        return [pscustomobject]@{ Exit=$process.ExitCode; Text=$stdout; Stderr=$stderr }
    } finally { $process.Dispose() }
}
$target = '"'+$fixture+'"'
$analysis = Invoke-IsolatedRea -Name 'analyze' -Arguments ('analyze '+$target+' --provider ghidra --json')
if($analysis.Exit -ne 0){throw 'Real Ghidra analysis nonzero: '+$analysis.Stderr.Substring([Math]::Max(0,$analysis.Stderr.Length-700))}
$a=$analysis.Text | ConvertFrom-Json
if($a.subject.digest.sha256 -ne $shaFixture -or
    $a.analysis_profile.parameters.upstream_analysis_profile.provider.id -ne 'ghidra' -or
    $a.analysis_profile.parameters.upstream_analysis_profile.provider.version -ne '12.1.4'){
    throw 'Ghidra analyze Evidence subject/provider mismatch.'
}
$found=Invoke-IsolatedRea -Name 'search' -Arguments ('search '+$target+' rea_lab_ --kind procedures --mode regex --provider ghidra --json')
if($found.Exit -ne 0){throw 'Real Ghidra search failed'}
$search=$found.Text | ConvertFrom-Json
if($search.provider.id -ne 'ghidra' -or $search.subject.digest.sha256 -ne $shaFixture){
    throw 'Ghidra symbol search Evidence provenance mismatch.'
}
$add=@($search.normalized_result | Where-Object { $_.value -eq 'rea_lab_add' -and $_.symbol.type -eq 'function' })
$mix=@($search.normalized_result | Where-Object { $_.value -eq 'rea_lab_mix' -and $_.symbol.type -eq 'function' })
if($add.Count -ne 1 -or $mix.Count -ne 1){throw 'Source-exported function names are missing or ambiguous.'}
$address=[string]$add[0].address
if($address -notmatch '^0x[0-9a-fA-F]+$'){throw 'Invalid observed function address.'}
$decompiled=Invoke-IsolatedRea -Name 'decompile' -Arguments ('decompile '+$target+' '+$address+' --provider ghidra --json')
if($decompiled.Exit -ne 0){throw 'Real Ghidra decompiler call failed'}
$code=$decompiled.Text | ConvertFrom-Json
$source=[string]$code.normalized_result
if($code.provider.id -ne 'ghidra' -or
    $code.subject.digest.sha256 -ne $shaFixture -or
    $source -notmatch 'int\s+rea_lab_add\s*\(' -or
    $source -notmatch 'param_1' -or $source -notmatch 'param_2' -or
    $source -notmatch 'return\s+[^;]*\+\s*7\s*;'){
    throw 'Decompiler failed to reconstruct the source-owned add+7 function.'
}
if((Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant() -ne $shaFixture){
    throw 'Target fixture unexpectedly modified.'
}
if((Get-FileHash -LiteralPath $addon -Algorithm SHA256).Hash.ToLowerInvariant() -ne $shaAddon){
    throw 'Native addon unexpectedly modified.'
}
$remaining=@(Get-CimInstance Win32_Process -Filter "name='java.exe' OR name='node.exe'" |
  Where-Object {$_.CommandLine -match 'ghidra1214-isolated|rea-agents-pr2-hardened|rea_lab_arithmetic'})
if($remaining.Count -gt 0){throw 'Owned REA/Ghidra subprocesses remain after verifier exit.'}
$leftovers=@(Get-ChildItem -LiteralPath $temp -Directory -Filter 'rea-native-probe-*' -ErrorAction SilentlyContinue)
if($leftovers.Count -gt 0){throw 'Native probe cleanup incomplete.'}
$summary=[ordered]@{
    passed = $true
    provider = 'ghidra'
    providerVersion = '12.1.4'
    jdk = 'Amazon Corretto 21.0.13'
    fixtureSha256 = $shaFixture
    fixtureKind = if($Deterministic) { 'reproducible-pe-x64' } else { 'original-pe-x64' }
    hardenedAddonSha256 = $shaAddon
    functionNames = @('rea_lab_add','rea_lab_mix')
    decompiledAddress = $address
    decompiledSource = $source
    stepsPassed = @('pinned-archives','real-analyze','real-symbol-search','real-decompile','byte-integrity','owned-process-cleanup')
    resourcePolicy = 'BelowNormal, four CPU logical cores, Java -Xmx1024m'
    globalConfigurationChanged = $false
    outputDir = $workspace
}
[IO.File]::WriteAllText((Join-Path $workspace 'summary.json'),
    ($summary | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Write-Output ($summary | ConvertTo-Json -Depth 6)
