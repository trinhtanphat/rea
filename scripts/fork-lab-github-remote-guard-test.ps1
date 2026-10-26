#Requires -Version 5.1
<#
.SYNOPSIS
  Offline allowlist regression for fork-lab-safe-upstream-sync.ps1.
.DESCRIPTION
  Uses the actual guard function, makes no network requests and does
  not alter Git remotes, refs, Windows settings, or any user sessions.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'fork-lab-github-remote-guard.ps1')

$cases = @(
    @{owner='trinhtanphat';url='https://github.com/trinhtanphat/rea';allowed=$true}
    @{owner='trinhtanphat';url='https://github.com/trinhtanphat/rea.git';allowed=$true}
    @{owner='trinhtanphat';url='git@github.com:trinhtanphat/rea.git';allowed=$true}
    @{owner='trinhtanphat';url='ssh://git@github.com/trinhtanphat/rea.git';allowed=$true}
    @{owner='morluto';url='https://github.com/morluto/rea.git';allowed=$true}
    @{owner='morluto';url='git@github.com:morluto/rea';allowed=$true}
    @{owner='morluto';url='ssh://git@github.com/morluto/rea.git';allowed=$true}
    @{owner='trinhtanphat';url='https://attacker.invalid/path/github.com/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com.evil.invalid/redirect/github.com/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://evil.example/https://github.com/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com@attacker.invalid/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://attacker@github.com/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com:443/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com/trinhtanphat/rea.git?redirect=1';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com/trinhtanphat/rea.git#hash';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com/trinhtanphat/rea.git/extra';allowed=$false}
    @{owner='trinhtanphat';url='http://github.com/trinhtanphat/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='file:///C:/REA-LAB/rea.git';allowed=$false}
    @{owner='trinhtanphat';url='https://github.com/morluto/rea.git';allowed=$false}
    @{owner='morluto';url='git@github.com:trinhtanphat/rea.git';allowed=$false}
    @{owner='morluto';url='https://phish.example/subpath/github.com/morluto/rea.git';allowed=$false}
    @{owner='morluto';url='https://github.com/morluto/rea/';allowed=$false}
)
$passed = 0
foreach ($case in $cases) {
    $actual = Test-ReaGitHubRemote -Url $case.url -Owner $case.owner
    if ($actual -ne $case.allowed) {
        throw ('GitHub remote guard mismatch, wanted '+$case.allowed+
            ', actual '+$actual+', url='+$case.url)
    }
    $passed++
}
[ordered]@{
    ok = $true
    passed = $passed
    total = $cases.Count
    allowed_cases = @($cases | Where-Object { $_.allowed }).Count
    blocked_cases = @($cases | Where-Object { -not $_.allowed }).Count
    no_network_calls = $true
    no_git_mutation = $true
} | ConvertTo-Json -Depth 3
