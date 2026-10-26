#Requires -Version 5.1
<#
.SYNOPSIS
  Test the shipped REA Windows addon manifest/PE fail-closed policy offline.
.DESCRIPTION
  Copies only package metadata, addon binary and the official artifact
  verifier to disposable test folders inside a pre-existing REA lab.
  Never changes an installed REA package, ACL, user account or service.
#>
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\REA-LAB',
    [string]$PackageRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$artifacts = Join-Path $lab 'artifacts'
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
if (-not (Test-Path -LiteralPath $artifacts -PathType Container) -or
    -not (Test-Path -LiteralPath $node -PathType Leaf)) {
    throw 'A pre-existing isolated lab with portable Node and artifacts is required.'
}
if ([string]::IsNullOrWhiteSpace($PackageRoot)) {
    $PackageRoot = Join-Path $lab 'runtime\node_modules\rea-agents-pr2'
}
$pkg = (Resolve-Path -LiteralPath $PackageRoot -ErrorAction Stop).Path
if (-not $pkg.StartsWith($lab + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The package must be within the selected lab.'
}
$relativeFiles = @(
    'package.json',
    'scripts\verify-windows-native-artifact.mjs',
    'native\windows\build\manifest.json',
    'native\windows\build\rea-windows-x64.node'
)
foreach ($relative in $relativeFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $pkg $relative) -PathType Leaf)) {
        throw "Missing REA package file: $relative"
    }
}
$root = Join-Path $artifacts ('artifact-guard-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)

function Invoke-Case([string]$id, [string]$mutation, [bool]$expectedSuccess) {
    $dir = Join-Path $root $id
    [void][IO.Directory]::CreateDirectory($dir)
    foreach ($relative in $relativeFiles) {
        $destination = Join-Path $dir $relative
        [void][IO.Directory]::CreateDirectory((Split-Path $destination -Parent))
        [IO.File]::Copy((Join-Path $pkg $relative), $destination)
    }
    $manifestPath = Join-Path $dir 'native\windows\build\manifest.json'
    $binaryPath = Join-Path $dir 'native\windows\build\rea-windows-x64.node'
    if ($mutation -ne 'none') {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($mutation -eq 'bad-digest') {
            $manifest.artifactSha256 = '0000000000000000000000000000000000000000000000000000000000000000'
        }
        elseif ($mutation -eq 'wrong-version') {
            $manifest.packageVersion = '99.99.99-test'
        }
        elseif ($mutation -eq 'wrong-node-api') {
            $manifest.nodeApiVersion = 99
        }
        elseif ($mutation -eq 'wrong-pe-architecture-with-updated-digest') {
            $bytes = [IO.File]::ReadAllBytes($binaryPath)
            if ($bytes.Length -lt 256) { throw 'Source binary too short for PE test' }
            $offset = [BitConverter]::ToUInt32($bytes, 0x3c)
            if ($offset -gt ($bytes.Length - 26)) { throw 'Invalid source PE offset' }
            $bytes[[int]($offset + 4)] = 0x4c
            $bytes[[int]($offset + 5)] = 0x01
            [IO.File]::WriteAllBytes($binaryPath, $bytes)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $manifest.artifactSha256 =
                    ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
            }
            finally { $sha.Dispose() }
        }
        elseif ($mutation -eq 'corrupt-pe-with-updated-digest') {
            $bytes = [IO.File]::ReadAllBytes($binaryPath)
            $bytes[0] = 0
            [IO.File]::WriteAllBytes($binaryPath, $bytes)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $manifest.artifactSha256 =
                    ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
            }
            finally { $sha.Dispose() }
        }
        else { throw "Unknown mutation: $mutation" }
        [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 12),
            [Text.UTF8Encoding]::new($false))
    }
    $verifier = Join-Path $dir 'scripts\verify-windows-native-artifact.mjs'
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $node
    $start.Arguments = '"' + $verifier + '"'
    $start.WorkingDirectory = $dir
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $start
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(12000)) {
            $process.Kill()
            [void]$process.WaitForExit(5000)
            throw "Artifact verifier exceeded 12 seconds: $id"
        }
        $process.WaitForExit()
        $code = $process.ExitCode
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
    }
    finally { $process.Dispose() }
    if ($stdout.Length -gt 32768 -or $stderr.Length -gt 32768) {
        throw "Unexpected artifact verification output size: $id"
    }
    [IO.File]::WriteAllText((Join-Path $dir 'stdout.txt'), $stdout, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $dir 'stderr.txt'), $stderr, [Text.UTF8Encoding]::new($false))
    if ($expectedSuccess) {
        $facts = $stdout | ConvertFrom-Json
        if ($code -ne 0 -or $facts.ok -ne $true -or
            $facts.architecture -ne 'x64' -or $facts.nodeApiVersion -ne 8) {
            throw "Valid native artifact did not verify: $id"
        }
    }
    else {
        $required = if ($mutation -in @('corrupt-pe-with-updated-digest',
                                       'wrong-pe-architecture-with-updated-digest')) {
            'PE32+'
        } else {
            'metadata or SHA-256'
        }
        if ($code -eq 0 -or $stderr -notmatch [regex]::Escape($required)) {
            throw "Mutated native artifact was not safely rejected: $id"
        }
    }
    return [pscustomobject]@{
        test = $id
        mutation = $mutation
        exit_code = $code
        expected_success = $expectedSuccess
        passed = $true
    }
}
$checks = @()
$checks += Invoke-Case -id 'valid-artifact' -mutation 'none' -expectedSuccess $true
$checks += Invoke-Case -id 'invalid-digest' -mutation 'bad-digest' -expectedSuccess $false
$checks += Invoke-Case -id 'invalid-version' -mutation 'wrong-version' -expectedSuccess $false
$checks += Invoke-Case -id 'invalid-node-api' -mutation 'wrong-node-api' -expectedSuccess $false
$checks += Invoke-Case -id 'wrong-pe-architecture' -mutation 'wrong-pe-architecture-with-updated-digest' -expectedSuccess $false
$checks += Invoke-Case -id 'invalid-pe-with-honest-digest' -mutation 'corrupt-pe-with-updated-digest' -expectedSuccess $false
[ordered]@{
    passed = $true
    suite = 'rea-windows-native-artifact-guards'
    cases_passed = $checks.Count
    cases = $checks
    source_package = $pkg
    output_dir = $root
    original_package_changed = $false
} | ConvertTo-Json -Depth 6
