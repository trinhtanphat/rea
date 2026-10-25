#Requires -Version 5.1
<#
.SYNOPSIS
  Run bounded, offline REA static-format smoke tests on a dedicated Windows lab.
.DESCRIPTION
  Creates synthetic and locally copied fixtures under the selected lab only.
  No target is launched. No native provider, agent setup or OS ACL is changed.
#>
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\REA-LAB',
    [string]$ManagedAssemblyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
$cli = Join-Path $lab 'runtime\node_modules\rea-agents\scripts\rea.mjs'
$artifacts = Join-Path $lab 'artifacts'
foreach ($required in @($node, $cli, $artifacts)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "REA test-lab prerequisite missing: $required"
    }
}
if (-not (Test-Path -LiteralPath $artifacts -PathType Container)) {
    throw 'Artifacts root must be an existing directory.'
}

if ([string]::IsNullOrWhiteSpace($ManagedAssemblyPath)) {
    $dotnet = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App'
    $candidates = @(Get-ChildItem -LiteralPath $dotnet -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    $assembly = $null
    foreach ($candidate in $candidates) {
        $path = Join-Path $candidate.FullName 'System.Runtime.dll'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $assembly = $path
            break
        }
    }
    if ($null -eq $assembly) {
        throw 'No stock System.Runtime.dll found; provide -ManagedAssemblyPath.'
    }
}
else {
    $assembly = (Resolve-Path -LiteralPath $ManagedAssemblyPath -ErrorAction Stop).Path
}
if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) {
    throw 'The selected .NET fixture must be an existing file.'
}

$workspace = Join-Path $artifacts ('static-matrix-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
$copiedDll = Join-Path $workspace 'System.Runtime.dll'
[IO.File]::Copy($assembly, $copiedDll)
# Keep the fixture bounded by REA's unmodified default PE reader size limit.
if ((Get-Item -LiteralPath $copiedDll).Length -gt 64MB) {
    throw 'The selected fixture exceeds the default 64 MiB PE reader limit.'
}

$modelFixture = Join-Path $workspace 'tiny.safetensors'
$json = '{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
$header = [Text.Encoding]::UTF8.GetBytes($json)
$length = [BitConverter]::GetBytes([UInt64]$header.Length)
$payload = [BitConverter]::GetBytes([single]1.0)
[IO.File]::WriteAllBytes($modelFixture, [byte[]]($length + $header + $payload))
$badModel = Join-Path $workspace 'truncated.safetensors'
$badDll = Join-Path $workspace 'truncated.dll'
[IO.File]::WriteAllBytes($badModel, [byte[]](1, 2, 3, 4))
[IO.File]::WriteAllBytes($badDll, [byte[]](0x4d, 0x5a, 0, 0, 1))

function Invoke-StaticProbe {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][string]$Command,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][bool]$ExpectSuccess,
        [string]$ExpectedProvider
    )
    $stdout = Join-Path $workspace "$Id.json"
    $stderr = Join-Path $workspace "$Id.stderr.txt"
    # The process is the isolated REA CLI only; the target is never executed.
    # PowerShell 5.1 Start-Process does not provide reliable ExitCode on this
    # service runner. Native invocation retains the actual $LASTEXITCODE.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $node $cli $Command $Target '--format' 'json' 1> $stdout 2> $stderr
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    $raw = Get-Content -LiteralPath $stdout -Raw -Encoding UTF8
    $parsed = $raw | ConvertFrom-Json
    if ($ExpectSuccess) {
        if ($code -ne 0 -or $null -eq $parsed.evidence_id -or
            $null -eq $parsed.normalized_result -or $parsed.provider.id -ne $ExpectedProvider) {
            throw "Expected successful structured Evidence from $Id (exit $code)."
        }
    }
    else {
        if ($code -eq 0 -or [string]::IsNullOrEmpty([string]$parsed.code) -or
            $parsed.category -notin @('invalid_input', 'unsupported_target')) {
            throw "Malformed fixture was not safely rejected by $Id (exit $code)."
        }
    }
    return [pscustomobject]@{
        test = $Id
        passed = $true
        expected_success = $ExpectSuccess
        exit_code = $code
        evidence_sha256 = (Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash.ToLowerInvariant()
        error_code = if ($ExpectSuccess) { $null } else { [string]$parsed.code }
    }
}

$checks = @()
$checks += Invoke-StaticProbe -Id 'model-valid' -Command 'inspect-model-artifact' -Target $modelFixture -ExpectSuccess $true -ExpectedProvider 'model-artifact'
$checks += Invoke-StaticProbe -Id 'managed-valid' -Command 'inspect-managed-artifact' -Target $copiedDll -ExpectSuccess $true -ExpectedProvider 'rea-dotnet-static'
$checks += Invoke-StaticProbe -Id 'pe-valid' -Command 'inspect-pe-imports' -Target $copiedDll -ExpectSuccess $true -ExpectedProvider 'rea-pe-imports'
$checks += Invoke-StaticProbe -Id 'model-truncated' -Command 'inspect-model-artifact' -Target $badModel -ExpectSuccess $false -ExpectedProvider ''
$checks += Invoke-StaticProbe -Id 'managed-truncated' -Command 'inspect-managed-artifact' -Target $badDll -ExpectSuccess $false -ExpectedProvider ''
$checks += Invoke-StaticProbe -Id 'pe-truncated' -Command 'inspect-pe-imports' -Target $badDll -ExpectSuccess $false -ExpectedProvider ''

# Validate semantic facts, not only a successful exit code.
$model = Get-Content -LiteralPath (Join-Path $workspace 'model-valid.json') -Raw | ConvertFrom-Json
$tensor = @($model.normalized_result.tensors)
if ($model.normalized_result.format -ne 'safetensors' -or $tensor.Count -ne 1 -or
    $tensor[0].name -ne 'weight' -or $tensor[0].type -ne 'F32' -or
    [string]$tensor[0].parameter_count -ne '1' -or
    $model.normalized_result.coverage.header -ne 'complete') {
    throw 'The model smoke test did not recover the expected header declarations.'
}
$managed = Get-Content -LiteralPath (Join-Path $workspace 'managed-valid.json') -Raw | ConvertFrom-Json
$pe = Get-Content -LiteralPath (Join-Path $workspace 'pe-valid.json') -Raw | ConvertFrom-Json
if ($null -eq $managed.normalized_result.assembly -or
    $null -eq $pe.normalized_result.imports) {
    throw 'A static parser returned insufficient normalized facts.'
}

[ordered]@{
    passed = $true
    suite = 'rea-offline-static-matrix'
    tests_passed = $checks.Count
    tests = $checks
    copied_managed_assembly_sha256 = (Get-FileHash -LiteralPath $copiedDll -Algorithm SHA256).Hash.ToLowerInvariant()
    output_dir = $workspace
    target_code_executed = $false
    native_decompiler_verified = $false
    javascript_graph_verified = $false
} | ConvertTo-Json -Depth 6
