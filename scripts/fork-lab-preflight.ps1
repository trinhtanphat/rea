#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only readiness report for a REA checkout and optional analysis target.
.DESCRIPTION
  Does not execute the target, download packages, change agent configuration,
  write files, inspect credentials or connect to a remote service.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TargetPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ExternalVersion {
    param([string]$Command, [string]$Argument)
    $tool = Get-Command -Name $Command -ErrorAction SilentlyContinue
    if ($null -eq $tool) {
        return $null
    }
    try {
        $lines = @(& $tool.Source $Argument 2>&1)
        if ($LASTEXITCODE -ne 0 -or $lines.Count -eq 0) {
            return $null
        }
        return ([string]$lines[0]).Trim()
    }
    catch {
        return $null
    }
}

function Test-NodeEngine {
    param([string]$NodeVersion)
    if ($NodeVersion -notmatch '^v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$') {
        return $false
    }
    $parsed = [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
    if ($parsed.Major -eq 22) {
        return $parsed -ge [version]'22.23.4'
    }
    if ($parsed.Major -eq 24) {
        return $parsed -ge [version]'24.22.1'
    }
    return $parsed -ge [version]'26.12.1'
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$pinnedNode = (Get-Content -LiteralPath (Join-Path $repositoryRoot '.nvmrc') -TotalCount 1).Trim()
$nodeVersion = Get-ExternalVersion -Command 'node.exe' -Argument '--version'
$npmVersion = Get-ExternalVersion -Command 'npm.cmd' -Argument '--version'
$gitVersion = Get-ExternalVersion -Command 'git.exe' -Argument '--version'
$nodeSupported = Test-NodeEngine -NodeVersion $nodeVersion

$problems = New-Object 'System.Collections.Generic.List[string]'
if (-not $nodeSupported) {
    $problems.Add("Node.js is missing or outside REA's declared supported engine ranges.")
}
if ($null -eq $npmVersion) {
    $problems.Add('npm is unavailable.')
}
if ($null -eq $gitVersion) {
    $problems.Add('git is unavailable.')
}

$target = [ordered]@{
    supplied = -not [string]::IsNullOrWhiteSpace($TargetPath)
    exists = $null
    kind = 'not-selected'
    hint = 'Provide the absolute local path of an authorized binary, app, or extracted app.'
}
if ($target.supplied) {
    $targetItem = Get-Item -LiteralPath $TargetPath -ErrorAction SilentlyContinue
    if ($null -eq $targetItem) {
        $target.exists = $false
        $target.kind = 'missing'
        $target.hint = 'The target path does not exist on this machine.'
        $problems.Add('The requested target path does not exist.')
    }
    elseif ($targetItem.PSIsContainer) {
        $target.exists = $true
        $target.kind = 'directory'
        $target.hint = 'A source repository is not automatically a decompilable binary; point REA at a built artifact or supported app directory.'
    }
    else {
        $target.exists = $true
        $target.kind = 'file'
        $target.hint = 'Determine the file format and required REA provider before starting analysis.'
    }
}

$report = [ordered]@{
    check = 'rea-fork-lab-preflight'
    checked_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    mode = 'read-only'
    node_version = $nodeVersion
    pinned_node_version = $pinnedNode
    node_supported = $nodeSupported
    npm_version = $npmVersion
    git_version = $gitVersion
    prerequisites_ready = ($problems.Count -eq 0)
    target = $target
    engine_verification = 'not-run; Ghidra/IDA/Hopper and external tooling require separate checks'
    limitations = 'No target run, no decompilation, no network requests, no npm install and no MCP configuration changes.'
    problems = @($problems.ToArray())
}
$report | ConvertTo-Json -Depth 5
if ($problems.Count -gt 0) {
    exit 2
}
