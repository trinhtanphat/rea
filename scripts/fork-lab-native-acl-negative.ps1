#Requires -Version 5.1
<#
.SYNOPSIS
  Exercise strict Windows native DACL admission with isolated ACL fixtures.
.DESCRIPTION
  Creates exactly six private test directories under the pre-existing REA
  lab artifacts root. Checks the patched REA native addon directly: it must
  admit one protected full-control SYSTEM ACE and refuse broader, weaker or
  malformed ACLs. No pre-existing path is modified or removed; only one
  newly created fixture is changed to model an unprotected DACL.
#>
[CmdletBinding()]
param(
    [string]$LabRoot = 'C:\REA-LAB',
    [Parameter(Mandatory=$true)][string]$PatchedAddonPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ExpectedAddonSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    throw 'This focused regression requires the LocalSystem Windows identity.'
}
$lab = (Resolve-Path -LiteralPath $LabRoot -ErrorAction Stop).Path.TrimEnd('\')
$root = Join-Path $lab 'artifacts'
$node = Join-Path $lab 'toolchains\node-v24.22.1-win-x64\node.exe'
$addon = (Resolve-Path -LiteralPath $PatchedAddonPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $root -PathType Container) -or
    -not (Test-Path -LiteralPath $node -PathType Leaf) -or
    -not $addon.StartsWith($lab + '\', [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($addon) -ne 'rea-windows-x64.node') {
    throw 'Only the pre-existing isolated REA-LAB and Windows addon are permitted.'
}
$hash = (Get-FileHash -LiteralPath $addon -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $ExpectedAddonSha256.ToLowerInvariant()) {
    throw 'The patched addon SHA-256 differs from the explicitly pinned candidate.'
}
$workspace = Join-Path $root ('acl-admission-negative-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
$cases = @(
    @{name='baseline-system-only'; sddl='O:SYG:SYD:P(A;OICI;FA;;;SY)'; shouldPass=$true;
      expectedAceCount=1; reason=''},
    @{name='extra-administrators'; sddl='O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)';
      shouldPass=$false; expectedAceCount=2; reason='unexpected trustees'},
    @{name='wrong-inheritance'; sddl='O:SYG:SYD:P(A;;FA;;;SY)';
      shouldPass=$false; expectedAceCount=1; reason='unsupported rights or ACE type'},
    @{name='unprotected-dacl'; sddl='O:SYG:SYD:(A;OICI;FA;;;SY)';
      shouldPass=$false; expectedAceCount=-1; reason='present protected DACL'},
    @{name='wrong-access-mask'; sddl='O:SYG:SYD:P(A;OICI;0x00120089;;;SY)';
      shouldPass=$false; expectedAceCount=1; reason='unsupported rights or ACE type'},
    @{name='extra-deny-ace'; sddl='O:SYG:SYD:P(D;OICI;FA;;;BA)(A;OICI;FA;;;SY)';
      shouldPass=$false; expectedAceCount=2; reason='Access is denied'}
)
foreach ($fixture in $cases) {
    $target = Join-Path $workspace $fixture.name
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($fixture.sddl)
    [void][IO.Directory]::CreateDirectory($target, $security)
    if ($fixture.name -eq 'unprotected-dacl') {
        # Windows can make an explicit DACL protected during creation,
        # even when the SDDL has no P flag. Change ONLY this new fixture
        # to re-enable inheritance and then assert the actual readback.
        $ownAcl = [Security.AccessControl.DirectorySecurity]::new(
            $target, [Security.AccessControl.AccessControlSections]'Owner,Access')
        $ownAcl.SetAccessRuleProtection($false, $true)
        [IO.Directory]::SetAccessControl($target, $ownAcl)
    }
    $readback = [Security.AccessControl.DirectorySecurity]::new(
        $target, [Security.AccessControl.AccessControlSections]'Owner,Access')
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new(
        $readback.GetSecurityDescriptorBinaryForm(), 0)
    $wantProtected = $fixture.name -ne 'unprotected-dacl'
    if ($readback.AreAccessRulesProtected -ne $wantProtected -or
        $raw.Owner.Value -ne 'S-1-5-18' -or
        ($fixture.expectedAceCount -ge 0 -and
         $raw.DiscretionaryAcl.Count -ne $fixture.expectedAceCount)) {
        throw "The on-disk security descriptor changed during fixture creation: $($fixture.name)"
    }
}

# This helper loads exactly the user-selected, digest-checked native addon
# and calls only the read-only private-directory verifier operation.
$helper = @'
const addon = require(process.argv[2]);
const path = require("node:path");
const root = process.argv[3];
const checks = JSON.parse(process.argv[4]);
const results = checks.map(({name, shouldPass, reason}) => {
  let accepted = false, message = "", code = null;
  try {
    accepted = addon.call("cutter_bridge_verify_directory", [
      path.join(root, name)
    ])?.privateDacl === true;
  } catch (error) {
    message = String(error?.message ?? error);
    code = error?.win32Code ?? null;
  }
  const passed = accepted === shouldPass &&
    (shouldPass || (code === 5 && message.includes(reason)));
  return {name, expected_accept:shouldPass, accepted, win32_code:code,
          message:message.slice(0, 350), passed};
});
console.log(JSON.stringify({
  passed:results.length===6 && results.every(x=>x.passed),
  tests:results
}, null, 2));
if (results.length !== 6 || !results.every(x=>x.passed)) process.exitCode=1;
'@
$helperPath = Join-Path $workspace 'check.cjs'
[IO.File]::WriteAllText($helperPath, $helper, [Text.UTF8Encoding]::new($false))
$expectations = @($cases | ForEach-Object {
    @{name=$_.name;shouldPass=$_.shouldPass;reason=$_.reason}
}) | ConvertTo-Json -Compress -Depth 4
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $node
$start.Arguments = ('"{0}" "{1}" "{2}" "{3}"' -f
    $helperPath, $addon, $workspace, $expectations.Replace('"', '\"'))
$start.WorkingDirectory = $workspace
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$p = [Diagnostics.Process]::new()
try {
    $p.StartInfo = $start
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEndAsync()
    $stderr = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(15000)) {
        $p.Kill()
        [void]$p.WaitForExit(5000)
        throw 'Native DACL negative regression exceeded 15 seconds.'
    }
    $p.WaitForExit()
    $code = $p.ExitCode
    $out = $stdout.GetAwaiter().GetResult()
    $err = $stderr.GetAwaiter().GetResult()
}
finally { $p.Dispose() }
if ($out.Length -gt 65536 -or $err.Length -gt 65536) {
    throw 'Unexpectedly large native DACL regression output.'
}
[IO.File]::WriteAllText((Join-Path $workspace 'stdout.json'), $out,
    [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $workspace 'stderr.txt'), $err,
    [Text.UTF8Encoding]::new($false))
if ($code -ne 0) {
    throw "Native DACL regression failed (exit $code): $err"
}
$result = $out | ConvertFrom-Json
if ($result.passed -ne $true -or @($result.tests).Count -ne $cases.Count) {
    throw 'Native DACL acceptance/rejection did not match expected policy.'
}
[ordered]@{
    passed = $true
    suite = 'rea-windows-localsystem-private-dacl-deny-tests'
    cases_passed = @($result.tests).Count
    tests = $result.tests
    addon_sha256 = $hash
    output_dir = $workspace
    existing_acl_modified = $false
} | ConvertTo-Json -Depth 8
