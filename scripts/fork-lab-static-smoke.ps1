#Requires -Version 5.1
<#
.SYNOPSIS
  Exercise REA's offline safetensors reader with synthetic data.
.DESCRIPTION
  Creates a unique evidence directory below the caller-selected lab root.
  Never executes a target binary, changes MCP registration, downloads data,
  or modifies files outside that directory.
#>
[CmdletBinding()]
param([string]$LabRoot = 'C:\REA-LAB')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
$cli = Join-Path $lab 'runtime\node_modules\rea-agents\scripts\rea.mjs'
foreach ($prerequisite in @($node, $cli)) {
    if (-not (Test-Path -LiteralPath $prerequisite -PathType Leaf)) {
        throw "Missing isolated REA lab prerequisite: $prerequisite"
    }
}

$outputRoot = Join-Path $lab 'artifacts'
if (-not (Test-Path -LiteralPath $outputRoot -PathType Container)) {
    throw "Lab artifacts directory does not exist: $outputRoot"
}

$workspace = Join-Path $outputRoot ('static-smoke-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
$fixture = Join-Path $workspace 'one-weight.safetensors'
$evidence = Join-Path $workspace 'rea-evidence.json'
$stderr = Join-Path $workspace 'rea-stderr.txt'

# Safetensors: unsigned little-endian header size, JSON tensor declarations,
# then exactly four payload bytes representing a single F32 value of 1.0.
$json = '{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
$header = [Text.Encoding]::UTF8.GetBytes($json)
$length = [BitConverter]::GetBytes([UInt64]$header.Length)
$payload = [BitConverter]::GetBytes([single]1.0)
[IO.File]::WriteAllBytes($fixture, [byte[]]($length + $header + $payload))

$process = Start-Process -FilePath $node -ArgumentList @(
    $cli, 'inspect-model-artifact', $fixture, '--format', 'json'
) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $evidence -RedirectStandardError $stderr

if ($process.ExitCode -ne 0) {
    throw "REA static reader failed with exit code $($process.ExitCode). Evidence: $workspace"
}

$result = Get-Content -LiteralPath $evidence -Raw -Encoding UTF8 | ConvertFrom-Json
if ($result.normalized_result.format -ne 'safetensors') {
    throw "REA did not recognize the safetensors format. Evidence: $workspace"
}
$tensors = @($result.normalized_result.tensors)
if ($tensors.Count -ne 1 -or $tensors[0].name -ne 'weight' -or
    $tensors[0].type -ne 'F32' -or [string]$tensors[0].parameter_count -ne '1' -or
    [string]$tensors[0].byte_length -ne '4' -or
    $result.normalized_result.coverage.header -ne 'complete') {
    throw "REA did not return the expected synthetic tensor declarations. Evidence: $workspace"
}

[ordered]@{
    success = $true
    test = 'offline-safetensors-static-smoke'
    scope = 'single synthetic file, header-only analysis'
    result_format = $result.normalized_result.format
    tensor_name = $tensors[0].name
    tensor_type = $tensors[0].type
    evidence_sha256 = (Get-FileHash -LiteralPath $evidence -Algorithm SHA256).Hash.ToLowerInvariant()
    fixture_sha256 = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    evidence_directory = $workspace
    native_provider_verified = $false
    javascript_analysis_verified = $false
} | ConvertTo-Json -Depth 4
