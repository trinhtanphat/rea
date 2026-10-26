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

function Assert-ReaRemoteEndpoints {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$OriginFetch,
        [Parameter(Mandatory = $true)][string[]]$OriginPush,
        [Parameter(Mandatory = $true)][string[]]$UpstreamFetch
    )
    # Git supports distinct pushurl and multiple push/fetch destinations.
    # Refuse ambiguous remote lists rather than silently trusting item 0.
    if ($OriginFetch.Count -ne 1 -or $OriginPush.Count -ne 1 -or
        $UpstreamFetch.Count -ne 1) {
        throw 'Expected one fetch and one push destination for origin and one upstream fetch destination.'
    }
    if (-not (Test-ReaGitHubRemote -Url $OriginFetch[0] -Owner 'trinhtanphat') -or
        -not (Test-ReaGitHubRemote -Url $OriginPush[0] -Owner 'trinhtanphat') -or
        -not (Test-ReaGitHubRemote -Url $UpstreamFetch[0] -Owner 'morluto')) {
        throw 'Effective GitHub fetch/push remote destination does not match the exact REA allowlist.'
    }
}
