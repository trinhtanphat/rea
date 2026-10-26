#Requires -Version 5.1
<#
.SYNOPSIS
  Offline git-remote endpoint integrity test for REA safe fork sync.
.DESCRIPTION
  Creates only isolated temporary Git repositories under C:\REA-LAB\artifacts,
  tests actual git remote get-url --all / --push behavior. Never fetches,
  pushes, or mutates the real trinhtanphat/rea worktree or its configuration.
#>
[CmdletBinding()]
param([string]$LabRoot = 'C:\REA-LAB')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'fork-lab-github-remote-guard.ps1')
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
if ($lab -ne 'C:\REA-LAB') { throw 'Only isolated C:\REA-LAB allowed.' }
$workspace = Join-Path $lab ('artifacts\fork-git-endpoint-check-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)

function Git-Checked([string]$Repository,[string[]]$GitParameters) {
    $out = @(& git -C $Repository @GitParameters)
    if ($LASTEXITCODE -ne 0) {
        throw ('Git command failed: '+($GitParameters -join ' '))
    }
    return $out
}
function Run-Endpoint-Case([string]$Name,[string]$Origin,[string[]]$PushUrls,
                           [string[]]$UpstreamUrls,[bool]$Expected,
                           [string]$PushInsteadOf = '',
                           [string]$FetchInsteadOf = '') {
    $repo = Join-Path $workspace $Name
    [void][IO.Directory]::CreateDirectory($repo)
    [void](Git-Checked -Repository $repo -GitParameters @('init','--quiet'))
    [void](Git-Checked -Repository $repo -GitParameters @('remote','add','origin',$Origin))
    [void](Git-Checked -Repository $repo -GitParameters @('remote','add','upstream',$UpstreamUrls[0]))
    foreach ($url in @($UpstreamUrls | Select-Object -Skip 1)) {
        [void](Git-Checked -Repository $repo -GitParameters @('remote','set-url','--add','upstream',$url))
    }
    # Git may rewrite the effective destination through url.*.insteadOf
    # and url.*.pushInsteadOf even when remote.origin.url is legitimate.
    # Confirm get-url --all and --push --all expose both rewrites.
    if ($PushInsteadOf.Length -gt 0) {
        [void](Git-Checked -Repository $repo -GitParameters @(
            'config','--local',('url.'+$PushInsteadOf+'.pushInsteadOf'),'https://github.com/'))
    }
    if ($FetchInsteadOf.Length -gt 0) {
        [void](Git-Checked -Repository $repo -GitParameters @(
            'config','--local',('url.'+$FetchInsteadOf+'.insteadOf'),'https://github.com/'))
    }
    for ($i=0; $i -lt $PushUrls.Length; $i++) {
        $gitCommand = if ($i -eq 0) {
            @('remote','set-url','--push','origin',$PushUrls[$i])
        } else {
            @('remote','set-url','--add','--push','origin',$PushUrls[$i])
        }
        [void](Git-Checked -Repository $repo -GitParameters $gitCommand)
    }
    $fetch = @(Git-Checked -Repository $repo -GitParameters @('remote','get-url','--all','origin'))
    $push = @(Git-Checked -Repository $repo -GitParameters @('remote','get-url','--push','--all','origin'))
    $upstream = @(Git-Checked -Repository $repo -GitParameters @('remote','get-url','--all','upstream'))
    $ok = $true
    try {
        Assert-ReaRemoteEndpoints -OriginFetch $fetch -OriginPush $push -UpstreamFetch $upstream
    } catch { $ok = $false }
    if ($ok -ne $Expected) {
        throw ('Unexpected '+$Name+' result '+$ok+', expected '+$Expected+
               ', origin='+($fetch -join '|')+', push='+($push -join '|'))
    }
    return [pscustomobject]@{
        case = $Name; accepted = $ok; expected = $Expected
        origin_urls = $fetch.Count; push_urls = $push.Count; upstream_urls = $upstream.Count
    }
}

$goodOrigin = 'https://github.com/trinhtanphat/rea.git'
$goodUpstream = 'https://github.com/morluto/rea.git'
$badPush = 'https://attacker.invalid/path/github.com/trinhtanphat/rea.git'
$results = @()
$results += Run-Endpoint-Case -Name 'valid-simple' -Origin $goodOrigin -PushUrls @() -UpstreamUrls @($goodUpstream) -Expected $true
$results += Run-Endpoint-Case -Name 'valid-explicit-ssh-push' -Origin $goodOrigin -PushUrls @('git@github.com:trinhtanphat/rea.git') -UpstreamUrls @($goodUpstream) -Expected $true
$results += Run-Endpoint-Case -Name 'malicious-explicit-pushurl' -Origin $goodOrigin -PushUrls @($badPush) -UpstreamUrls @($goodUpstream) -Expected $false
$results += Run-Endpoint-Case -Name 'second-malicious-pushurl' -Origin $goodOrigin -PushUrls @($goodOrigin,$badPush) -UpstreamUrls @($goodUpstream) -Expected $false
$results += Run-Endpoint-Case -Name 'malicious-upstream' -Origin $goodOrigin -PushUrls @() -UpstreamUrls @('https://attacker.invalid/path/github.com/morluto/rea.git') -Expected $false
$results += Run-Endpoint-Case -Name 'two-upstreams' -Origin $goodOrigin -PushUrls @() -UpstreamUrls @($goodUpstream,'https://github.com/morluto/rea') -Expected $false
$results += Run-Endpoint-Case -Name 'malicious-pushInsteadOf-rewrite' -Origin $goodOrigin -PushUrls @() -UpstreamUrls @($goodUpstream) -Expected $false -PushInsteadOf 'https://attacker.invalid/'
$results += Run-Endpoint-Case -Name 'malicious-insteadOf-fetch-rewrite' -Origin $goodOrigin -PushUrls @() -UpstreamUrls @($goodUpstream) -Expected $false -FetchInsteadOf 'https://attacker.invalid/'

[ordered]@{
    ok = $true
    passed = $results.Count
    expected_good = @($results | Where-Object { $_.accepted }).Count
    expected_rejected = @($results | Where-Object { -not $_.accepted }).Count
    fixture_dir = $workspace
    no_network_access = $true
    existing_git_repo_untouched = $true
    tests = $results
} | ConvertTo-Json -Depth 5
