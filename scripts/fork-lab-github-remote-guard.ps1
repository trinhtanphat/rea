#Requires -Version 5.1
<#
.SYNOPSIS
  Strictly validate a known REA fork/upstream Git remote.
.DESCRIPTION
  Pure, side-effect-free GitHub remote allowlist. No network calls.
  Anchors both host and repository path, excluding attacker-controlled
  redirect hosts, host suffixes, ports, query strings and userinfo.
#>
function Test-ReaGitHubRemote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)]
        [ValidateSet('trinhtanphat','morluto')][string]$Owner
    )
    $pattern = '\A(?:https://github[.]com/|git@github[.]com:|ssh://git@github[.]com/)' +
               [regex]::Escape($Owner) + '/rea(?:[.]git)?\z'
    return [bool]($Url -match $pattern)
}
