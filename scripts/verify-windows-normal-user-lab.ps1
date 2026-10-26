#Requires -Version 5.1
<#
.SYNOPSIS
  Run the existing Windows-native REA verifier as a genuine non-SYSTEM user.
.DESCRIPTION
  A read-only launcher for an already-authenticated user's desktop or
  non-SYSTEM shell. It never changes user tokens, ACLs, services or global
  packages. The package must be a copy under a dedicated lab directory.
  This script intentionally refuses to run as LocalSystem.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$LabRoot,
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$VerifierPath,
    [Parameter(Mandatory=$true)][string]$NodeExe,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedAddonSha256,
    [ValidateRange(30,300)][int]$TimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -eq 'S-1-5-18') {
    [Console]::Error.WriteLine('Normal-user native verification requires an existing authorized non-SYSTEM shell.')
    exit 2
}

$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$pkg = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).Path
$verifier = (Resolve-Path -LiteralPath $VerifierPath -ErrorAction Stop).Path
$node = (Resolve-Path -LiteralPath $NodeExe -ErrorAction Stop).Path
if (-not $pkg.StartsWith($lab + '\', [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($verifier) -ne 'verify-windows-native.mjs' -or
    [IO.Path]::GetFileName($node) -ne 'node.exe' -or
    -not (Test-Path -LiteralPath (Join-Path $lab 'artifacts') -PathType Container)) {
    throw 'Inputs must select an isolated REA-LAB package and the official Windows verifier.'
}
$addon = Join-Path $pkg 'native\windows\build\rea-windows-x64.node'
$manifestPath = Join-Path $pkg 'native\windows\build\manifest.json'
if (-not (Test-Path -LiteralPath $addon -PathType Leaf) -or
    -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Missing compiled Windows addon and manifest in the isolated package.'
}
$digest = (Get-FileHash -LiteralPath $addon -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($digest -ne $ExpectedAddonSha256.ToLowerInvariant() -or
    $manifest.artifactSha256 -ne $digest -or
    $manifest.platform -ne 'win32' -or
    $manifest.architecture -ne 'x64') {
    throw 'The isolated native addon manifest or expected digest did not match.'
}

$directory = Join-Path (Join-Path $lab 'artifacts') (
    'normal-user-native-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$stdout = Join-Path $directory 'conformance.json'
$stderr = Join-Path $directory 'conformance.stderr.txt'
$summary = Join-Path $directory 'summary.json'
$report = [ordered]@{
    passed = $false
    tested_as_non_system = $true
    account_sid = $identity.User.Value
    addon_sha256 = $digest
    verifier_exit_code = $null
    controls = 0
    processes = 0
    output_dir = $directory
    error = $null
}
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$env:TEMP = $directory
$env:TMP = $directory
try {
    # Use .NET Process so PowerShell 5.1 service shells do not confuse
    # native stderr with the actual exit status. The verifier is trusted
    # local source code, and its subprocesses use the same user token.
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $node
    $info.Arguments = ('"{0}" "{1}"' -f $verifier, $pkg)
    $info.WorkingDirectory = $directory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $info
        [void]$process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw "Windows native verifier exceeded $TimeoutSeconds seconds."
        }
        $process.WaitForExit()
        $report.verifier_exit_code = $process.ExitCode
        [IO.File]::WriteAllText($stdout, $outTask.GetAwaiter().GetResult(),
            [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($stderr, $errTask.GetAwaiter().GetResult(),
            [Text.UTF8Encoding]::new($false))
    }
    finally { $process.Dispose() }
    if ($report.verifier_exit_code -ne 0) {
        throw "Windows native verifier failed (exit $($report.verifier_exit_code))."
    }
    $data = Get-Content -LiteralPath $stdout -Raw -Encoding UTF8 | ConvertFrom-Json
    $report.controls = @($data.controls.PSObject.Properties).Count
    $report.processes = @($data.processes.PSObject.Properties).Count
    if ($data.ok -ne $true -or $report.controls -lt 20 -or
        $report.processes -lt 6) {
        throw 'Verifier did not complete its full expected conformance suite.'
    }
    $report.passed = $true
}
catch { $report.error = $_.Exception.Message }
finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    [IO.File]::WriteAllText($summary, ($report | ConvertTo-Json -Depth 5),
        [Text.UTF8Encoding]::new($false))
}
Write-Output ($report | ConvertTo-Json -Depth 5)
if (-not $report.passed) { exit 1 }