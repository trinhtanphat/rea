#Requires -Version 5.1
<#
.SYNOPSIS
  Compare the unmodified and patched REA native addons on the same host.
.DESCRIPTION
  Reproduces the LocalSystem Win32 5 regression on isolated addon COPIES.
  Runs only the native inspect control; does not replace a package binary,
  change Windows ACLs, launch a user application, or enable a provider.
#>
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\REA-LAB',
    [Parameter(Mandatory=$true)][string]$OriginalAddonPath,
    [Parameter(Mandatory=$true)][string]$PatchedAddonPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$OriginalSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$PatchedSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($identity -ne 'S-1-5-18') {
    throw 'The historical LocalSystem native A/B case requires the LocalSystem token.'
}
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
$artifactRoot = Join-Path $lab 'artifacts'
$tempRoot = Join-Path $lab 'tmp'
if (-not (Test-Path -LiteralPath $node -PathType Leaf) -or
    -not (Test-Path -LiteralPath $artifactRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $tempRoot -PathType Container)) {
    throw 'A pre-existing isolated lab and pinned portable Node are required.'
}
$old = (Resolve-Path -LiteralPath $OriginalAddonPath -ErrorAction Stop).Path
$new = (Resolve-Path -LiteralPath $PatchedAddonPath -ErrorAction Stop).Path
foreach ($path in @($old, $new)) {
    if (-not $path.StartsWith($lab + '\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($path) -ne 'rea-windows-x64.node') {
        throw 'Both addons must be ordinary REA addon files inside the existing lab.'
    }
}
$originalHash = (Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash.ToLowerInvariant()
$patchedHash = (Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash.ToLowerInvariant()
if ($originalHash -ne $OriginalSha256.ToLowerInvariant() -or
    $patchedHash -ne $PatchedSha256.ToLowerInvariant() -or
    $originalHash -eq $patchedHash) {
    throw 'Addon SHA-256 mismatch or identical candidate binaries.'
}

$workspace = Join-Path $artifactRoot ('native-ab-comparison-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
$script = @'
const addon = require("./rea-windows-x64.node");
try {
  const result = addon.call("inspect", []);
  console.log(JSON.stringify({ok: true, inspection: result}));
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    message: String(error?.message || error),
    win32Code: error?.win32Code
  }));
  process.exitCode = 1;
}
'@

$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$env:TEMP = $tempRoot
$env:TMP = $tempRoot
$results = @()
try {
    foreach ($item in @(
        @{ name = 'original'; source = $old; hash = $originalHash },
        @{ name = 'patched'; source = $new; hash = $patchedHash }
    )) {
        $dir = Join-Path $workspace $item.name
        [void][IO.Directory]::CreateDirectory($dir)
        [IO.File]::Copy($item.source, (Join-Path $dir 'rea-windows-x64.node'))
        $js = Join-Path $dir 'inspect.cjs'
        [IO.File]::WriteAllText($js, $script, [Text.UTF8Encoding]::new($false))
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $node
        $info.Arguments = '"' + $js + '"'
        $info.WorkingDirectory = $dir
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $p = [Diagnostics.Process]::new()
        try {
            $p.StartInfo = $info
            [void]$p.Start()
            $stdoutTask = $p.StandardOutput.ReadToEndAsync()
            $stderrTask = $p.StandardError.ReadToEndAsync()
            if (-not $p.WaitForExit(15000)) {
                $p.Kill()
                [void]$p.WaitForExit(5000)
                throw "Native A/B probe timed out: $($item.name)"
            }
            $p.WaitForExit()
            $exit = $p.ExitCode
            $stdout = $stdoutTask.GetAwaiter().GetResult().Trim()
            $stderr = $stderrTask.GetAwaiter().GetResult().Trim()
        }
        finally { $p.Dispose() }
        if ($stdout.Length -gt 128KB -or $stderr.Length -gt 128KB) {
            throw 'Native inspect exceeded its bounded expected output.'
        }
        $outputPath = Join-Path $dir 'stdout.json'
        $errorPath = Join-Path $dir 'stderr.json'
        [IO.File]::WriteAllText($outputPath, $stdout, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($errorPath, $stderr, [Text.UTF8Encoding]::new($false))
        $parsed = if ($exit -eq 0) { $stdout | ConvertFrom-Json } else { $stderr | ConvertFrom-Json }
        $isSuccess = $parsed.ok -eq $true
        $results += [pscustomobject]@{
            label = $item.name
            exit_code = $exit
            ok = $isSuccess
            privateDacl = if ($isSuccess) { $parsed.inspection.privateDacl } else { $null }
            win32_code = if ($isSuccess) { $null } else { $parsed.win32Code }
            expected_error = if ($isSuccess) { $false } else {
                [bool]([string]$parsed.message -match 'Private DACL contains unexpected trustees')
            }
            sha256 = $item.hash
        }
    }
}
finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}
$success = $results.Count -eq 2 -and
    $results[0].exit_code -eq 1 -and $results[0].ok -eq $false -and
    $results[0].win32_code -eq 5 -and $results[0].expected_error -eq $true -and
    $results[1].exit_code -eq 0 -and $results[1].ok -eq $true -and
    $results[1].privateDacl -eq $true
$summary = [ordered]@{
    passed = $success
    scope = 'historical LocalSystem native inspect A/B'
    results = $results
    output_dir = $workspace
    service_changed = $false
    production_addon_changed = $false
}
$summary | ConvertTo-Json -Depth 5
if (-not $success) { throw 'The expected strict native A/B assertion did not hold.' }
