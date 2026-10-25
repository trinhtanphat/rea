#Requires -Version 5.1
<#
.SYNOPSIS
  Isolated native Windows DACL ACE-count readback for the REA LocalSystem gate.
.DESCRIPTION
  Calls CreateDirectoryW and GetFileSecurityW on unique, synthetic empty
  directories only under the existing REA lab artifacts folder.
  Tests identical versus distinct well-known trustees. No ACL of an existing
  application, service, user profile or executable is modified.
#>
[CmdletBinding()]
param([string]$LabRoot = 'C:\REA-LAB')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$lab = (Resolve-Path -LiteralPath $LabRoot).Path
$artifacts = Join-Path $lab 'artifacts'
if (-not (Test-Path -LiteralPath $artifacts -PathType Container)) {
    throw 'An existing REA-LAB artifacts directory is required.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($identity -ne 'S-1-5-18') {
    throw "This diagnostic reproduces the LocalSystem token only. Observed SID: $identity"
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ReaLabNativeAcl {
    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW",
       CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);
    [DllImport("advapi32.dll", EntryPoint = "GetFileSecurityW",
       CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileSecurity(string path, uint information,
       IntPtr descriptor, uint length, out uint needed);
}
'@ -ErrorAction Stop

$workspace = Join-Path $artifacts ('acl-native-proof-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)

function Get-NativeSecurityDescriptor([string]$path) {
    # OWNER_SECURITY_INFORMATION (1) | DACL_SECURITY_INFORMATION (4)
    [uint32]$needed = 0
    [void][ReaLabNativeAcl]::GetFileSecurity($path, 5, [IntPtr]::Zero, 0, [ref]$needed)
    if ($needed -lt 20 -or $needed -gt 65536) {
        throw "Unexpected native security descriptor length: $needed"
    }
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$needed)
    try {
        $length = [uint32]$needed
        if (-not [ReaLabNativeAcl]::GetFileSecurity($path, 5, $ptr, $length, [ref]$needed)) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "GetFileSecurityW failed: Win32 $code"
        }
        $bytes = [byte[]]::new([int]$needed)
        [Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $bytes.Length)
        return [Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }
}

$cases = @(
    @{ name = 'two-identical-system-aces';
       sddl = 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;SY)';
       expectedSids = @('S-1-5-18'); expectedNativeCount = 1 },
    @{ name = 'two-distinct-aces';
       sddl = 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)';
       expectedSids = @('S-1-5-18', 'S-1-5-32-544'); expectedNativeCount = 2 }
)
$measurements = @()
foreach ($case in $cases) {
    $path = Join-Path $workspace $case.name
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($case.sddl)
    if ($raw.DiscretionaryAcl.Count -ne 2) {
        throw 'Test input did not contain exactly two raw ACEs.'
    }
    $binary = [byte[]]::new($raw.BinaryLength)
    $raw.GetBinaryForm($binary, 0)
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($binary.Length)
    try {
        [Runtime.InteropServices.Marshal]::Copy($binary, 0, $ptr, $binary.Length)
        $security = [ReaLabNativeAcl+SecurityAttributes]::new()
        $security.nLength = [Runtime.InteropServices.Marshal]::SizeOf(
            [type][ReaLabNativeAcl+SecurityAttributes])
        $security.lpSecurityDescriptor = $ptr
        $security.bInheritHandle = $false
        if (-not [ReaLabNativeAcl]::CreateDirectory($path, [ref]$security)) {
            $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "CreateDirectoryW failed: Win32 $code"
        }
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr) }

    $native = Get-NativeSecurityDescriptor $path
    $actualSids = @($native.DiscretionaryAcl | ForEach-Object {
        $_.SecurityIdentifier.Value
    })
    $unexpectedSids = @($actualSids | Where-Object {
        $_ -notin $case.expectedSids
    })
    $observedUnique = @($actualSids | Sort-Object -Unique)
    $expectedUnique = @($case.expectedSids | Sort-Object -Unique)
    if ($native.Owner.Value -ne $identity -or
        $unexpectedSids.Count -gt 0 -or
        $native.DiscretionaryAcl.Count -ne $case.expectedNativeCount -or
        ($observedUnique -join ',') -ne ($expectedUnique -join ',') -or
        ([int]$native.ControlFlags -band
            [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw "Native readback differs from the explicit fixture policy: $path"
    }
    $measurements += [pscustomobject]@{
        test = $case.name
        input_ace_count = $raw.DiscretionaryAcl.Count
        native_readback_ace_count = $native.DiscretionaryAcl.Count
        expected_native_ace_count = $case.expectedNativeCount
        native_readback_sids = $actualSids
        owner_sid = $native.Owner.Value
        path = $path
    }
}
[ordered]@{
    tested_on = 'Windows native CreateDirectoryW / GetFileSecurityW'
    process_sid = $identity
    cases = $measurements
    evidence_directory = $workspace
    production_acl_changed = $false
} | ConvertTo-Json -Depth 5
