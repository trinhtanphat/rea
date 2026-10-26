# Fork-only Windows REA test lab

This is an operator runbook for testing **authorized** repositories and built artifacts
with the `trinhtanphat/rea` fork. It does not change upstream REA's provider,
security or agent-setup contracts.

## WIN11-181 isolation

- Working checkout: `C:\REA-LAB\rea`. The GitHub fork retains all upstream
  branches, tags and their reachable commit histories; this local checkout is
  deliberately single-branch and shallow for reduced network/disk use.
- `origin`: `https://github.com/trinhtanphat/rea.git`.
- `upstream`: `https://github.com/morluto/rea.git`.
- Portable pinned Node.js: `C:\REA-LAB\toolchains\node-v24.22.1-win-x64`.
  Its archive was checked against the official Node.js SHA-256 manifest.
  No machine-wide Node.js upgrade is needed.

Select the portable runtime **for this PowerShell session only**:

```powershell
$env:Path = "C:\REA-LAB\toolchains\node-v24.22.1-win-x64;$env:Path"
Set-Location C:\REA-LAB\rea
node --version
```

From the branch containing the preflight script, perform the read-only check:

```powershell
powershell.exe -NoProfile -File .\scripts\fork-lab-preflight.ps1
powershell.exe -NoProfile -File .\scripts\fork-lab-preflight.ps1 -TargetPath 'C:\path\to\authorized\artifact'
```

The check reports whether Node.js satisfies REA's declared engine ranges
and whether npm, Git and the selected local path exist. It does **not**
assert that native providers are installed or verified. It executes no target
code, writes no files and downloads nothing. A nonzero exit status means
the preflight requires attention.

## Observed Windows service-account limitation (2026-10-25)

On WIN11-181, Private Commander executes commands as
`NT AUTHORITY\SYSTEM`. REA 6.8.0 `doctor` passed the Node.js and
host checks, but its Windows native self-test reported
`Private DACL contains unexpected trustees ... (Win32 5): Access is denied`.
The same failure occurred with `TEMP`/`TMP` moved to `C:\REA-LAB\tmp`.
A local four-file JavaScript/Electron fixture was inventoried but analysis
returned `capability_unavailable` at the native runtime-control boundary.
**This is not a passing end-to-end REA analysis test.**

The preflight tool checks only basic prerequisites and now warns about
LocalSystem; a green prerequisite result is not a working analysis provider.
For actual analysis, use an authorized interactive user session or a
separate supported test VM, then re-run `rea doctor` and an offline fixture.
Do **not** weaken system temp-directory ACLs, bypass REA's safety self-test,
or change the production Private Commander service identity to force a pass.
## Offline static smoke check (verified on WIN11-181)

The synthetic fixture verifier checks one fully supported offline parser
without touching an installed application or relying on a native provider.

From the local checkout:

    powershell.exe -NoProfile -File .\scripts\fork-lab-static-smoke.ps1 -LabRoot C:\REA-LAB

The verifier constructs a 71-byte safetensors test file in a unique directory
under C:\REA-LAB\artifacts, invokes only inspect-model-artifact, checks the
Evidence JSON and returns fixture and Evidence SHA-256 hashes. Successful
checks require format=safetensors and exactly one declared F32 tensor named
weight with one parameter. The result deliberately says both native provider
and JavaScript application analysis remain unverified.

Executed on 2026-10-25: PowerShell parsed without errors, REA CLI exited 0,
and normalized Evidence matched the synthetic tensor declarations. This
validates the model-header reader, not native binary decompilation.

The native error "Private DACL contains unexpected trustees" observed under
LocalSystem is distinct from upstream issue #1701, which primarily concerns
deleting native self-test directories. The runner's current-user SID is S-1-5-18 (LocalSystem), identical
to the SYSTEM SID. Source inspection shows an identity-aliasing problem
in verifyPrivate: an ACE matching the user takes the first branch of an
if/else-if, so the separate SYSTEM flag cannot be set when both SIDs
coincide. However the **observed** error occurs at the preceding
AceCount==2 check, before that branch.

On 2026-10-26 a separate **native Win32** test supplied an explicit,
protected security descriptor with two full-access inheritable ACEs.
It called CreateDirectoryW, then GetFileSecurityW to read back the
native security descriptor (not a .NET-canonicalized ACL):

- With two identical SYSTEM (S-1-5-18) ACEs as input, the Windows file
  system returned **one** SYSTEM ACE.
- In the control with SYSTEM and BUILTIN\Administrators as distinct
  input ACEs, the native API returned **two** distinct ACEs.
- With SYSTEM plus the real non-SYSTEM SID of an existing interactive
  account, the native API also returned **two** distinct ACEs (optional
  `-AdditionalUserSid` argument). This uses a synthetic filesystem
  descriptor; it **does not** run the addon as that account.

The repeatable test is scripts/fork-lab-acl-native-proof.ps1, runnable
only under LocalSystem and limited to unique empty fixture directories
inside C:\REA-LAB\artifacts. It validates protected DACL, expected
trustees, owner and ACE count. This reproduces the identity/ACE-count
mechanism independently of REA. A rebuilt addon on draft PR #2 now
passes native self-test, 31 conformance checks and a four-file Electron
fixture under LocalSystem (details in docs/windows-localsystem-native-validation.md
on the patch branch), but an **actual normal-user addon run** remains
unverified. The attempt to send a Run-dialog shortcut to the existing
interactive desktop was refused by UIPI/elevation, with 0 input events
injected; we did not work around this boundary. An earlier read-only
sweep found no surviving rea-native-probe directories under
C:\Windows\Temp or C:\REA-LAB\tmp. Upstream issue #1701 describes a
distinct delete-by-handle symptom. Do not change production ACLs or
the desktop service identity based on this research.

A reproducible **same-host native addon A/B regression** is available
as `scripts/fork-lab-native-ab.ps1`. It requires explicitly provided
expected SHA-256 digests for the original and patched addon, copies
both modules into unique isolated fixture directories and runs the
same `inspect` native control under LocalSystem. The 2026-10-26 test
passed: published original exit 1 with exactly the historical private
DACL Win32 5 error; source-patched PR #2 addon exit 0 and
`privateDacl=true`. Both commands used pinned Node 24.22.1 and the
same isolated NTFS TEMP directory. Neither installed package was
overwritten. This is not evidence for non-SYSTEM integration or
real Ghidra/IDA/Hopper provider operation.

### Additional static-format probes (executed 2026-10-25)

A copy of the stock .NET 8 System.Runtime.dll (43,344 bytes) was placed only
in C:\REA-LAB\fixtures and processed with the isolated REA 6.8.0 CLI.

- inspect-managed-artifact: exit 0; provider rea-dotnet-static; returned PE/CLI
  identity, assembly metadata and references.
- inspect-pe-imports: exit 0; provider rea-pe-imports; returned PE import and
  delay-import inventory structure.
- The identical copied test file had SHA-256
  E044D7CAA0B903794245B593AE7EA793EE270374E2DAACB3035FA11031F7FB57.
- An initial attempt to parse the large Node.js executable with the default
  PE reader limit correctly failed because the file exceeds the 64 MiB budget.
  Using a smaller legitimate fixture avoided relaxing this safety limit.

These checks execute no inspected .NET assembly or PE binary. They prove
only the observed static parser outcomes; provider-backed deep decompilation,
target compatibility and JavaScript/Electron graph analysis remain unverified.
### Six-case static parser matrix

After the isolated REA 6.8.0 CLI is present, run:

    powershell.exe -NoProfile -File .\scripts\fork-lab-static-matrix.ps1 -LabRoot C:\REA-LAB

To compare with a **separate already-installed** patched REA CLI inside
the same lab without replacing the published package, use:

    powershell.exe -NoProfile -File .\scripts\fork-lab-static-matrix.ps1 -LabRoot C:\REA-LAB -CliPath C:\REA-LAB\runtime\node_modules\rea-agents-pr2\scripts\rea.mjs

The override is constrained to `scripts\rea.mjs` below the lab root
and the chosen CLI path is recorded in the JSON report. On 2026-10-26
both the original 6.8.0 CLI and isolated patched PR #2 CLI passed the
same six static-format parser cases (**12/12 assertions overall**).
This does not independently establish that optional analysis engines
are configured.

The script copies a locally installed stock System.Runtime.dll to an
isolated, uniquely named directory below C:\REA-LAB\artifacts, and creates
a synthetic 71-byte safetensors sample and two deliberately malformed
fixtures. It executes six parser-only commands: valid and invalid inputs
for safetensors, .NET/CLI identity, and Windows PE imports. It checks native
command exit codes, returned Evidence and error JSON, provider identifiers,
and expected model header facts. Reports contain SHA-256 hashes and input
scope; generated binaries and Evidence are not added to Git.

Real execution on WIN11-181 (2026-10-25): 6/6 passed. All valid cases
returned Evidence with exit 0; all malformed cases failed with exit 1.
The hardened runner uses a 45-second per-process deadline by default
(`-ProbeTimeoutSeconds` accepts 1–60), rejects Evidence over 4 MiB,
and checks exact format errors plus the SHA-256 and paths of its inputs.
The dedicated `scripts/fork-lab-bounded-runner.mjs` allows only three
static REA parser commands, does not use a shell, writes newly created
Evidence paths only, and bounds output **while streaming** (stdout 4 MiB,
stderr 256 KiB). It returns code 124 on timeout or 125 on output overflow.

The local helper regression suite is repeatable with:

    C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe scripts\fork-lab-bounded-runner-test.mjs C:\REA-LAB\artifacts

Executed on WIN11-181 (2026-10-26): the helper regression suite
passed 3/3 cases (stdout overflow, stderr overflow, 1-second timeout),
and the full static parser matrix passed again 6/6. A prior direct
1-second timeout check also failed closed with a nonzero exit, and
no related parser process remained in the subsequent process listing.
The deadline bounds the direct REA CLI process, not an arbitrary child
process family. The fixed parser-only test inputs did not launch targets.
Only the synthetic helper regression stubs are executed as mock CLI scripts.
This is repeatable source-independent offline smoke coverage. It does not
validate Ghidra, Hopper, IDA, JavaScript application analysis, native
runtime authority, or the suitability of unknown user-provided artifacts.

For an alternative .NET reference fixture, provide
-ManagedAssemblyPath with an absolute path to a permitted local assembly.
Keep sample files below the 64 MiB PE reader default and do not expand
runtime privileges to make a test pass.
## Independent current-user SID observer regression (2026-10-26)

The original Windows conformance test checked the observed `userIsSystem`
flag against **itself**. It now derives the expected token SID from a
separate Windows `whoami.exe /user /fo csv /nh` process, and asserts the
observed flag **and** expected 1-versus-2 ACE count against that
independent SID. The first code change is on draft PR #2, commit
`6216f8c`. The observed user identity was `S-1-5-18` under the
LocalSystem service runner.

The repeatable fault-injection test in
`scripts/fork-lab-sid-observer-negative.mjs` uses the separately staged,
exact PR #2 source verifier; it copies the four verifier helper modules
into two **new** artifacts trees, runs one original verifier and then
deliberately forges a **self-consistent but incorrect** `userIsSystem`
and ACE count in a copy of the PowerShell observation. A third run
places a **copy of the trusted Windows cmd.exe** under the fake name
`whoami.exe` in a dedicated lab directory prepended to the existing
Windows Path. The legitimate verifier must continue to find its SID
oracle by the absolute `SystemRoot\System32\whoami.exe` path, not
by PATH search. All executions use Node.js with `shell: false`,
bounded timeout/output and `C:\REA-LAB\tmp` against the hardened
REA test package.

    C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe scripts\fork-lab-sid-observer-negative.mjs C:\REA-LAB C:\REA-LAB\validation-pr2\scripts\verify-windows-native.mjs C:\REA-LAB\runtime\node_modules\rea-agents-pr2-hardened

Actual WIN11-181 results: the unmodified source verifier returned
**exit 0, 23 native/filesystem controls and 8 process checks pass**;
the deliberately forged observer returned **exit 1**, with the
`userIsSystem` assertion mismatch. The verifier with fake
`whoami.exe` prepended to the Windows Path **still returned exit 0**,
because it used the absolute system executable. The runner reported
`ok: true`, saved all three outputs in a new lab artifacts directory,
and did not modify installed packages, production ACLs, user tokens,
services or interactive desktop session. This is negative-test
coverage for the observer, not normal-user Windows token validation.

## Isolated native DACL rejection matrix (2026-10-26)

On WIN11-181, the **source-built PR #2** Windows native addon was tested
under LocalSystem with the directly exposed read-only
`cutter_bridge_verify_directory` operation. This permits precise checking
of security policy without running an unknown target or deploying the addon.

The repeatable test is `scripts/fork-lab-native-acl-negative.ps1`:

    powershell.exe -NoProfile -File .\scripts\fork-lab-native-acl-negative.ps1 -LabRoot C:\REA-LAB -PatchedAddonPath C:\REA-LAB\artifacts\native-pr2-hardened-3e375a39\rea-windows-x64.node -ExpectedAddonSha256 4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019

The script verifies the digest of the selected addon, creates twelve
unique test-owned directories under `C:\REA-LAB\artifacts`, and
independently reads Windows owner, DACL protection and ACE count.
Two valid cases are admitted: one protected full-control SYSTEM ACE,
and two identical SYSTEM ACEs canonicalized by Windows into one.
Ten negative cases are rejected with Win32 5: extra Administrators
trustee, missing inheritance, reduced rights, extra deny ACE,
unprotected DACL, wrong owner, inherit-only, unrelated trustee only,
unexpected NO_PROPAGATE_INHERIT flag, and unexpected INHERITED flag
on a protected root. Windows canonicalized a newly created
unprotected fixture to protected at creation, so that fixture alone
has inheritance re-enabled and read back before native verification.
No pre-existing or production ACL is modified.

The **original PR #2 patched addon** (SHA-256 starting `2ef81453`)
accepted the NO_PROPAGATE_INHERIT and INHERITED root flag cases.
PR #2 code commit `3e375a39` tightened `verifyPrivate` to demand
the exact OBJECT_INHERIT | CONTAINER_INHERIT flags **for runtime roots
only**, preserving the existing non-root child policy.
This updated addon was built on isolated MinGW on PVE161-HOST and
transferred with a hash-verified single-use lab channel.
Actual results on WIN11-181: **12/12 pass**, addon SHA-256
`4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019`.
The new build also passed Windows native conformance (23 filesystem
controls + 8 process checks), REA's official native artifact validator,
6/6 static parser cases, 6/6 artifact tamper-rejection tests, and
the synthetic four-file Electron analysis (exit 0).
The extra deny ACE and inherit-only ACE can fail during path admission;
other invalid cases reach the native root DACL verifier. None of this
establishes a non-SYSTEM user runtime or Ghidra/IDA/Hopper capability.

## Official native addon artifact integrity regression (2026-10-26)

The official REA verifier `scripts/verify-windows-native-artifact.mjs`
passed on both separately installed lab packages: the published REA 6.8.0
addon and the patched PR #2 addon. It verifies package/manifest identity,
Windows x64 PE32+ header, Node-API 8, ABI and SHA-256.

The repeatable **negative** suite is
`scripts/fork-lab-artifact-guards.ps1`:

    powershell.exe -NoProfile -File .\scripts\fork-lab-artifact-guards.ps1 -LabRoot C:\REA-LAB -PackageRoot C:\REA-LAB\runtime\node_modules\rea-agents-pr2

It creates unique fixture directories under `C:\REA-LAB\artifacts`,
copies only the verifier, metadata and native addon from the chosen lab
package, then tests six conditions without loading the native module:
one unmodified valid artifact, a wrong manifest digest, an incorrect
package version, an unsupported Node-API manifest version, a PE with its
machine architecture changed from x64 despite a recomputed honest digest,
and a damaged PE signature with a recomputed honest digest.
Valid cases must exit 0; every mutation must exit nonzero with the
expected error class. Each verifier subprocess has a 12-second timeout.

Actual results on WIN11-181: **6/6 patched PR #2**, **6/6 published
REA 6.8.0** (**12/12 assertions**). Both installed package binary
digests were checked afterward and remained unchanged. This verifies
the artifact policy did not regress in these test cases; it is not
a general malicious-binary sandbox or substitute for provider tests.

## Cross-Node native and Electron Evidence matrix (2026-10-26)

The pinned hardened Windows native addon (SHA-256
`4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019`)
was tested independently using both Node 24 executables already present
on WIN11-181, without modifying either Node installation, any running
Private Commander process, or the Windows system PATH:

- Private Commander Node `24.21.0` executable SHA-256:
  `ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32`.
- Portable REA-LAB Node `24.22.1` executable SHA-256:
  `d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5`.

The repeatable, single-command runner
`scripts/fork-lab-node-version-matrix.mjs` checks the actual executable
versions/digests and binary digest, then runs the **updated** Windows
source conformance verifier and the same four-file synthetic Electron
fixture under each Node version. It confines TEMP/TMP to
`C:\REA-LAB\tmp`, requires existing fixture cleanliness, uses
`shell:false` with a 90-second timeout and bounded output, and
writes separate unique evidence files under `C:\REA-LAB\artifacts`:

    C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe scripts\fork-lab-node-version-matrix.mjs C:\REA-LAB

**Observed (Windows LocalSystem, 2026-10-26): both Node versions
passed 23 filesystem/native controls + 8 process checks; both
returned Electron provider `rea-javascript-application` with exit 0.**
The actual Node stdout is UTF-8 and the two Electron Evidence streams
were byte-identical: **231335 bytes per run**, SHA-256
`1f7fb0067e70f0f3d59da984b4ed629d31c1f6ddd3d927d5ee5011eb07ee4049`.
Earlier PowerShell 5.1 redirected files were saved in a different
encoding (462674 bytes, SHA-256 starting `c764daf2`); this does not
represent a content discrepancy in the source JSON. Native temporary
fixture directories were cleaned. This is compatibility evidence
for these **two specific Node 24 builds**, not other majors or
execution under a non-SYSTEM Windows user.

## Real Ghidra 12.1.4 provider integration on Windows (2026-10-26)

The previous Ghidra blocker is **now resolved for one source-owned PE x64 DLL
under LocalSystem**. This is real Java/Ghidra analysis and decompilation,
not just static parsing or a provider health probe. No production service,
Windows account, system PATH/JAVA_HOME, or interactive desktop was changed.

| Fully validated archive | Bytes | Publisher SHA-256 |
| --- | ---: | --- |
| NSA Ghidra 12.1.4 PUBLIC ZIP | 569649598 | ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db |
| Amazon Corretto JDK 21.0.13.0.10 Windows x64 ZIP | 202668246 | abd264a79e07c64e19aaa705e5b8ea8db01d5213877b8ac0b855a94541a4b0fd |

Ghidra's first 495018176 bytes came from the previous GitHub download;
its remaining 74631422 bytes were retrieved as 72 verified-length HTTP
206 chunks from the SourceForge Ghidra project mirror on PVE161-HOST.
After concatenation, the **whole ZIP** exactly matched the official
NSA release asset SHA-256 above. Mirror content was never trusted
without this publisher-pinned full-file hash.

Amazon Corretto JDK 21 was downloaded from the official corretto.aws
resources endpoint to isolated PVE161 staging, verified against the
vendor's published latest_sha256 endpoint, transferred once over a
short-lived IP-restricted local link, and reverified on WIN11-181.
Both ZIPs passed traversal-path checks before extraction:

- Ghidra root: C:\REA-LAB\toolchains\ghidra1214-isolated\ghidra_12.1.4_PUBLIC
- Full JDK: C:\REA-LAB\toolchains\jdk21-corretto-isolated\jdk21.0.13_0

Java and Javac both report 21.0.13. The revised
scripts/fork-lab-ghidra-archives-preflight.ps1 accepts Ghidra 12.1.4
plus **either** checksum-valid 64-bit full-JDK ZIP (Corretto 21.0.13
or the earlier Temurin 21 fixture). Latest result: ready=true, exit 0.
The obsolete Temurin download is still named *.partial and is not used.

With scoped Java/Ghidra process environment, all individual Ghidra
rea doctor checks are healthy: Windows x64, version 12.1.4, headless
script, matching decompile.exe, full JDK 21 and Windows native
authority. Wide-audit doctor still exits 1 because optional providers
and client registrations such as Hopper/IDA/JADX are absent.

The source-owned fixture is scripts/fixtures/rea-ghidra-arithmetic.cpp.
Its 85850-byte PE32+ DLL was compiled using only the isolated MinGW
toolchain on PVE161 and **was never executed**. The exact DLL tested on
WIN11-181 has SHA-256:
f3b3bb1f7b97924ac6d366204152592ee2ce80a1a93061fccbf27e4524996f41.
A rebuild of the C++ fixture in a separate isolated staging directory
did **not** produce a byte-identical DLL, despite a disabled PE timestamp.
This test therefore pins the **actual inspected DLL bytes**, not an
unproved bit-for-bit reproducible PE build. Recompiled samples must be
re-hashed and separately admitted before running a new assertion set.
Local path: C:\REA-LAB\fixtures\ghidra-pe-arithmetic\rea_lab_arithmetic.dll.

Reproduce the bounded, real Ghidra integration test using:

    powershell.exe -NoProfile -File .\scripts\fork-lab-ghidra-real-provider.ps1 -LabRoot C:\REA-LAB

The script validates the official archive hashes plus the isolated
addon/fixture digest before calling the real REA CLI:

1. analyze --provider ghidra: exits 0 and returns a composed workflow
   with an upstream Ghidra provider profile reporting version 12.1.4.
2. search --kind procedures --mode regex: exits 0 and resolves both
   exported functions rea_lab_add and rea_lab_mix.
3. decompile <observed-address>: exits 0 and recovers the source-owned
   operation 'return param_2 + param_1 + 7;'.
4. File hashes, temporary native probes and Java/Node subprocesses are
   checked after execution: the DLL/addon are unchanged and no owned
   subprocess or probe remains.

**All six asserted phases of the integrated runner passed on WIN11-181.**
Captured JSON and stderr are stored under unique folders below
C:\REA-LAB\artifacts. Every REA process is limited to four logical
CPUs, BelowNormal priority, Java heap -Xmx1024m, bounded output and
150 seconds maximum. The tests do not install Ghidra/Java globally.

### Real REA/Ghidra MCP stdio (2026-10-26)

A **separate, actual MCP protocol run** now passes for the same
source-owned PE x64 DLL, with Ghidra 12.1.4, Corretto JDK 21.0.13
and the SHA-pinned hardened REA addon. The repeatable client is
`scripts/fork-lab-ghidra-mcp-smoke.mjs`:

    C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe scripts\fork-lab-ghidra-mcp-smoke.mjs C:\REA-LAB

This client starts an independent `rea-agents-pr2-hardened` **stdio
MCP server**, never editing the Private Commander MCP configuration.
It performs JSON-RPC `initialize` (negotiated protocol 2025-06-18),
`notifications/initialized`, `tools/list` (**229 advertised tools**),
then four supported **real** Ghidra MCP tool calls:

1. `open_binary` with the exact verified DLL path and `provider_id=ghidra`;
2. `binary_overview` with no arguments (the selected target is retained
   by the server, rather than passed to this tool);
3. `search_procedures` with pattern `rea_lab_`, finding both
   `rea_lab_add` and `rea_lab_mix`;
4. `procedure_pseudo_code` for `rea_lab_add`, recovering its
   source-owned `return ... + 7;` calculation.

**All four MCP calls PASS** under LocalSystem. The script verifies
the addon and DLL SHA-256 first; it asserts the returned Ghidra
provenance, names, pseudocode and absence of MCP error replies. It
stores the tool catalog, all four results, a summary and server stderr
under a unique `C:\REA-LAB\artifacts\ghidra-mcp-real-*` folder.
The successful run used protocol 2025-06-18, tool count 229 and
produced a 17155-byte normalized MCP `binary_overview` response
(SHA-256 `f4b0caa3fded4662fac3fc8b80933c824fc0587abafb3d92b061605e70f336b0`).
The successful fixture is under
`C:\REA-LAB\artifacts\ghidra-mcp-real-VLVf17`. All subprocesses
exited and no native probes remain. No account, Session 2 desktop,
system environment, installed provider or production MCP was altered.

**Remaining coverage:** a genuine non-SYSTEM Windows user token,
real IDA/Hopper integrations, and broader target formats/architectures
are unverified. The verified MCP scope is **these four Ghidra tools**
on one synthetic PE x64 DLL, not the complete 229-tool catalog.
Keep the fix PR draft.

## Ghidra 12.1.4 and JDK 21 lab archive readiness — historical preflight (2026-10-26)

REA 6.8.0 is verified against **Ghidra 12.1.x**, with real-provider
tests primarily using 12.1.4 and JDK 21. Ghidra 12.2 is a newer
release but is **not substituted** for the compatibility-pinned
12.1.4 lane. No Ghidra/JDK was installed, extracted, launched or
added to Windows system PATH/JAVA_HOME on WIN11-181 during this stage.

The official Windows x64 archive identifiers from the release providers:

| Artifact | Byte length | SHA-256 |
| --- | ---: | --- |
| Ghidra 12.1.4 PUBLIC 20260921 ZIP | 569649598 | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Temurin full JDK 21.0.12.1+1 x64 ZIP | 205073461 | `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` |

The JDK checksum and archive metadata came from the official
Adoptium release API; the Ghidra checksum came from the GitHub
release asset's published SHA-256 digest. Both downloads were
attempted with bounded, rate-limited `curl.exe` processes and a
dedicated `C:\REA-LAB\toolchains\downloads` directory.
GitHub/CDN delivery was too slow for a bounded lab run; the two
**identified lab download processes only** were stopped, and the
incomplete archives were named `*.zip.partial` to prevent their
use as valid packages. The existing fragments are not trusted.
No unrelated download or browser process was terminated.

`scripts/fork-lab-ghidra-archives-preflight.ps1` is a fully offline,
read-only readiness guard that verifies exact archive lengths and
release SHA-256 before any future extraction. It exits **2**
whenever any input is missing, partial or invalid:

    powershell.exe -NoProfile -File .\scripts\fork-lab-ghidra-archives-preflight.ps1 -LabRoot C:\REA-LAB

Observed on WIN11-181: **exit 2, ready=false**. After a bounded
HTTP 206 resume and another CDN throughput degradation, the most
recent incomplete archive sizes are Ghidra **495018176 / 569649598**
bytes and JDK **12480512 / 205073461** bytes (about 75 MB and
193 MB short, respectively). Only the exact lab curl process was
stopped; no download process remains. Neither partial archive has
passed integrity checks, so neither may be extracted or executed.
At **this earlier checkpoint**, no Ghidra provider execution had
been claimed. That preflight output is preserved in the lab's JSON
artifact history. See the verified real-Ghidra provider section
above for the subsequently completed ZIP/JDK acquisition and
PE x64 decompiler run. Non-SYSTEM user token, IDA and Hopper
integration tests are still release blockers.

## Testing a repository or a program

A GitHub source repository is not itself a native binary. First establish the
authorized scope and the question to investigate, then select the right input:

| Input | Appropriate REA workflow |
| --- | --- |
| Extracted JavaScript/Electron app, ASAR | Static JavaScript application analysis |
| Native PE/ELF/Mach-O executable | Configure a supported existing Hopper, Ghidra or IDA provider |
| .NET assembly | Static metadata/CIL inspection |
| Android APK | Supported APK static inspection; deeper JADX needs a JDK |
| Source-only repository | Inspect source normally; build **only in an isolated, approved environment** if a binary is needed |

Suggested order for each test: record the target SHA-256 and permissions;
start with offline/static inspection; preserve REA evidence and uncertainty;
separately verify consequential conclusions against assembly or behavior.
Avoid executing untrusted binaries on WIN11-181.

## Building and checking the REA fork

Check the current upstream `AGENTS.md`, `docs/testing.md` and
`docs/installation.md` before changing code. On a dedicated development
VM or isolated CI runner, use the pinned Node.js version:

```powershell
npm ci
npm run check:fast
npm run test:focused -- path/to/relevant/test.test.ts
```

Full REA suites may be resource intensive and many cases assume Linux/macOS.
The Windows source tree is not a substitute for verifying a real Ghidra, IDA,
Hopper, JADX or firmware toolchain. Do not run broad builds, test suites,
runtime captures, installers or agent setup on production hosts without a
resource and side-effect review.

Do not publish findings about proprietary inputs or connect a cloud-model agent
to sensitive evidence without reviewing data-transfer policy. Analysis and
evidence may be local while agent prompts/pseudocode still leave the host.

## Keeping the fork maintainable

Make changes on feature branches, test them, and review a pull request before
merging into `main`. Keep `upstream` as a separate read-only source for
normal operations; never force-push over upstream branches or tags. Upstream
sync should be deliberate and checked for conflicts rather than automatic.
