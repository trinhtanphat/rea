#Requires -Version 5.1
<#
.SYNOPSIS
  Preview or safely mirror upstream Git heads/tags into the existing REA fork.
.DESCRIPTION
  Default is read-only. -Apply allows only:
   - create a ref missing in fork (all reachable Git commit history retained);
   - non-forced fast-forward of an existing branch after ancestor checks.
  Never deletes any refs, never uses --force, and never rewrites divergent
  branches or tags. No GitHub Actions or background scheduling.
  The user is responsible for invoking this in a clean isolated lab checkout.
.EXAMPLE
  powershell.exe -NoProfile -File scripts/fork-lab-safe-upstream-sync.ps1
.EXAMPLE
  powershell.exe -NoProfile -File scripts/fork-lab-safe-upstream-sync.ps1 -Apply
#>
[CmdletBinding()]
param([switch]$Apply)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$env:GIT_TERMINAL_PROMPT = '0'

function Invoke-Git([string[]]$Arguments) {
    $output = @(& git -C $repo @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw ('Git '+($Arguments -join ' ')+' failed: '+($output -join ' '))
    }
    return $output
}
$top = @((Invoke-Git -Arguments @('rev-parse','--show-toplevel')))[0]
if ([IO.Path]::GetFullPath($top).TrimEnd('\') -ne $repo.TrimEnd('\')) {
    throw 'Refusing to operate outside selected REA lab repository.'
}
$origin = @((Invoke-Git -Arguments @('remote','get-url','origin')))[0]
$upstream = @((Invoke-Git -Arguments @('remote','get-url','upstream')))[0]
if ($origin -notmatch '(?i)(?:github\.com[:/])trinhtanphat/rea(?:\.git)?$' -or
    $upstream -notmatch '(?i)(?:github\.com[:/])morluto/rea(?:\.git)?$') {
    throw 'Remote origin/upstream URLs do not match the expected public REA repositories.'
}
$dirty = @(Invoke-Git -Arguments @('status','--porcelain'))
if ($dirty.Count -ne 0 -and @($dirty | Where-Object { $_.Length -gt 0 }).Count -gt 0) {
    throw 'Refusing to sync from a dirty REA working tree.'
}
function Get-Refs([string]$remote) {
    $table = @{}
    foreach ($line in @(Invoke-Git -Arguments @('ls-remote','--heads','--tags',$remote))) {
        $parts = $line -split '\s+'
        if ($parts.Length -ne 2) { continue }
        $hash = $parts[0]
        $ref = $parts[1]
        # git ls-remote includes peeled annotated-tag ^{} lines: do not
        # create or compare those as independent refs.
        if ($ref.EndsWith('^{}')) { continue }
        if ($hash -notmatch '^[0-9a-f]{40}$' -or
            $ref -notmatch '^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$') {
            throw ('Unrecognized ref/commit format: '+$line)
        }
        $table[$ref] = $hash
    }
    return $table
}
$source = Get-Refs 'upstream'
$target = Get-Refs 'origin'
$unchanged = 0
$created = 0
$advanced = 0
$preserved = 0
$plan = @()
foreach ($ref in @($source.Keys | Sort-Object)) {
    $expected = $source[$ref]
    $present = $target.ContainsKey($ref)
    $current = if ($present) { $target[$ref] } else { $null }
    $action = if (-not $present) { 'missing' } elseif ($expected -eq $current) { 'equal' }
              elseif ($ref.StartsWith('refs/tags/')) { 'divergent_tag_preserve' }
              elseif ($ref -eq 'refs/heads/release-please--branches--main--components--rea-agents') {
                  'protected_release_branch_preserve'
              }
              else { 'different_branch_check_ancestry' }
    if ($action -eq 'equal') { $unchanged++; continue }
    $result = [ordered]@{ ref=$ref; upstream_sha=$expected; fork_sha=$current; action=$action }
    if ($Apply) {
        if ($action -eq 'divergent_tag_preserve' -or
            $action -eq 'protected_release_branch_preserve') {
            if ($action -eq 'protected_release_branch_preserve') {
                $result.action = 'protected_release_branch_preserved'
            } else {
                $result.action = 'divergent_tag_preserved'
            }
            $preserved++
        } else {
            # Materialize the source ref at exactly its observed SHA.
            $fetch = @(& git -C $repo fetch --no-tags upstream $ref)
            if ($LASTEXITCODE -ne 0) { throw ('Source fetch failed: '+($fetch -join ' ')) }
            $fetched = @((Invoke-Git -Arguments @('rev-parse','FETCH_HEAD')))[0]
            if ($fetched -ne $expected) {
                throw ('Source ref changed during fetch; stopped without push: '+$ref)
            }
            if ($present) {
                $ancestor = @(& git -C $repo merge-base --is-ancestor $current $expected)
                if ($LASTEXITCODE -ne 0) {
                    $result.action='divergent_branch_preserved'
                    $preserved++
                } else {
                    # GitHub enforces non-forced fast-forward on this push.
                    [void](Invoke-Git -Arguments @('push','origin',($expected+':'+$ref)))
                    $result.action='fast_forwarded'
                    $advanced++
                }
            } else {
                [void](Invoke-Git -Arguments @('push','origin',($expected+':'+$ref)))
                $result.action='created'
                $created++
            }
        }
    }
    $plan += [pscustomobject]$result
}
$final = if ($Apply) { Get-Refs 'origin' } else { $target }
$missing = @($source.Keys | Where-Object {-not $final.ContainsKey($_)})
$report = [ordered]@{
    applied = [bool]$Apply
    upstream_refs = $source.Count
    fork_refs = $final.Count
    equal_before = $unchanged
    created = $created
    fast_forwarded = $advanced
    divergent_preserved = $preserved
    missing_upstream_refs_after = $missing.Count
    operations = $plan
    force_pushed = $false
    deleted_any_ref = $false
}
Write-Output ($report|ConvertTo-Json -Depth 6)
if ($Apply -and $missing.Count -gt 0) {
    throw ('Incomplete mirror: '+($missing -join ', '))
}
