# Windows LocalSystem ACL fix — native build and verification record

> Scope: fork-only draft PR #2. Original LocalSystem source fix `6b3443a3b6dea831e27d8826f4650f72fd6a5d7b`; tightened protected-root ACE flags in source commit `3e375a39c17118638ae3df936cb18e0bd293b673`. Tested 2026-10-26.
> No native addon, account, service configuration, ACL, or global Node installation was changed in production.

## Issue and source patch

The Private Commander host on WIN11-181 executes as `NT AUTHORITY\\SYSTEM` (SID `S-1-5-18`). The published REA 6.8.0 addon fails native security admission with `Private DACL contains unexpected trustees` because the unpatched verifier requires exactly two ACEs for the current user and SYSTEM, which are the same SID in this process.

The independent readback proof in [draft PR #1](https://github.com/trinhtanphat/rea/pull/1) uses actual Win32 `CreateDirectoryW` and `GetFileSecurityW` APIs. Two identical SYSTEM full-control ACEs in the input returned **one** on NTFS; different SYSTEM + Administrators ACEs returned **two**. This PR's source change constructs one explicit ACE only if those principals are identical. Ordinary user accounts retain two ACEs and the native verifier still requires exact ACE count, owner, inheritance, mask, trustee and protected DACL.

## Two pinned Node 24 runtime regressions (lab PR #1 commit `725237c`)

The latest hardened Windows addon was tested on WIN11-181 under the
same LocalSystem token using **two separately installed, checksum-pinned
Node executables**. Neither executable or any production process was
modified:

| Node | Pinned executable SHA-256 | Windows native | Electron |
| --- | --- | --- | --- |
| Private Commander Node 24.21.0 | `ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32` | 23 filesystem + 8 process checks, pass | Exit 0 |
| REA-LAB portable Node 24.22.1 | `d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5` | 23 filesystem + 8 process checks, pass | Exit 0 |

The test is now a repeatable, bounded regression at
[`scripts/fork-lab-node-version-matrix.mjs`](https://github.com/trinhtanphat/rea/blob/chore/windows181-lab-preflight/scripts/fork-lab-node-version-matrix.mjs).
It verifies executable and addon digests, checks each Node version,
runs exact source native conformance and the four-file source-owned
Electron fixture, compares **raw UTF-8 JSON bytes**, and checks native
fixture cleanup. **Evidence is byte-identical across both Nodes**:
231,335 UTF-8 bytes, SHA-256
`1f7fb0067e70f0f3d59da984b4ed629d31c1f6ddd3d927d5ee5011eb07ee4049`.
The prior 462,674-byte PowerShell redirected Evidence was encoded
differently; it does not represent a different JSON result.
This verifies only these two Node 24 versions, not other Node majors
or non-SYSTEM token behavior.

## Lab engine acquisition status (historical pre-download checkpoint)

The release-pinned Ghidra 12.1.4 PUBLIC ZIP and Temurin JDK 21 x64 ZIP
have official upstream SHA-256 and size records in the lab preflight.
The HTTPS CDN was too slow for a bounded test, even with HTTP 206
continuation. Both identified lab-only downloads were stopped and
saved as **untrusted `.zip.partial`**, not installed, unpacked or run.

Latest partial bytes recorded on WIN11-181:
- Ghidra: 495,018,176 of 569,649,598 bytes.
- JDK: 12,480,512 of 205,073,461 bytes.

At that **historical checkpoint**, the SHA/length preflight
correctly returned **ready=false, exit code 2**. This was subsequently
superseded by the full NSA-hash-verified Ghidra 12.1.4 and official
Corretto JDK 21 acquisition described below, including passing
real PE x64 CLI and four-tool MCP tests.

## Independent Windows caller SID assertion (commit `6216f8c`)

The first revision of the Windows conformance verifier compared
`acl.userIsSystem` with **itself**, leaving the root ACE-count assertion
dependent on potentially self-consistent bad observations. Commit
`6216f8c4ee38e2b766c643bff3d66252bc34c536` now uses a separate,
bounded `whoami.exe /user /fo csv /nh` child process to determine the
current process SID independently of the .NET/PowerShell ACL observer.
The expected `userIsSystem` flag and expected **1 ACE for SYSTEM /
2 ACEs otherwise** derive from that independently measured SID.

On WIN11-181 (Windows LocalSystem SID `S-1-5-18`), the exact updated
source verifier was copied to an isolated validation workspace:
**exit 0**, `ok=true`, **23 native/filesystem controls and 8 process
checks passed**. Conformance output SHA-256:
`867ef230261b86fce09090a0dc1e43d4bdec51f598846901dab92e562fabce6f`.

The repeatable **fault-injection negative control** is committed to
[lab PR #1](https://github.com/trinhtanphat/rea/pull/1), commit
`c5c64b6`, as `scripts/fork-lab-sid-observer-negative.mjs`.
It creates two fresh validation workspaces containing the same source
verifier and helper modules. The unmodified verifier passed **31/31
assertions, exit 0**. A modified observer that falsely reports the
**opposite caller SID classification and matching wrong ACE count**
was rejected at the independent `userIsSystem` assertion with
**exit 1**. The test runner itself reported `ok=true`, and its
generated files remained below `C:\REA-LAB\artifacts`.
This validates that the assertion catches this injected observation
error; it is **not** a genuine non-SYSTEM login/host test.

## Updated protected-root ACE flag hardening (code commit `3e375a39`)

Further on-host ACL probes found that the **first** patched Windows addon
(SHA-256 `2ef814532639a53f6a490bc8631db96be8c59b2e1ce48ef863dbfdaadf1e65a6`)
admitted protected root directory DACLs with extraneous
`NO_PROPAGATE_INHERIT_ACE` or `INHERITED_ACE` flags. Those flags
differ from the exact `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`
configuration created by REA. The previous implementation verified
only that the necessary two inheritance flags were present.

In source commit `3e375a39c17118638ae3df936cb18e0bd293b673`,
`verifyPrivate` now requires **exactly** those two inheritance flags
for a protected private runtime root. The existing allowance for
non-root file/directory inheritance remains unchanged. This closes
the two newly discovered root-policy discrepancies, without expanding
any access rights.

### Hardened second-generation Windows addon

- Source commit: `3e375a39c17118638ae3df936cb18e0bd293b673`.
- Source `filesystem.cc` Git blob verified as
  `1c63fd0329bc8e0fb68b23dba9888e99ae531aa2` before build.
- Isolated build on PVE161-HOST using the same staged MinGW-w64 and
  Node.js toolchain, **repeated twice with byte-identical addon and
  manifest** (`cmp` passed).
- Output: REA 6.8.0 Windows x64 Node-API 8, 1,058,743 bytes.
- Hardened addon SHA-256:
  `4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019`.
- Hardened manifest SHA-256:
  `9b27a8888989695b87b4d841e2d12670a36a3521eeefcd49a7380bc3164a00a0`.
- Lab-only package: `C:\REA-LAB\runtime\node_modules\rea-agents-pr2-hardened`.
  The original published REA addon and the first PR #2 addon remain
  available separately with their original digests.
- A checksum-verified ZIP was delivered via a **single-use** listener
  restricted to WIN11-181. That listener closed after delivery.

**Verified on WIN11-181 under LocalSystem using the hardened addon:**

| Validation | Observed result |
| --- | --- |
| Expanded read-only native root ACL admission suite | **12/12 pass:** 2 admitted, 10 safely rejected |
| Source Windows native conformance | **23 filesystem controls + 8 process checks, `ok=true`, exit 0** |
| Official Windows native artifact manifest/PE validator | **Pass** |
| Six static parser cases | **6/6 pass** |
| Six artifact integrity and tamper rejection cases | **6/6 pass** |
| Four-file synthetic Electron app analysis | **Exit 0**, `rea-javascript-application` Evidence |

The expanded ACL test script is
[`scripts/fork-lab-native-acl-negative.ps1`](https://github.com/trinhtanphat/rea/blob/chore/windows181-lab-preflight/scripts/fork-lab-native-acl-negative.ps1)
on draft PR #1, source commit `2a82d2a`. The twelve cases include
two valid protected SYSTEM-only/duplicate-SYSTEM fixtures and ten
invalid fixtures: extra trustee, wrong inheritance, reduced mask,
extra deny ACE, unprotected DACL, wrong owner, inherit-only,
unrelated trustee, no-propagate ACE and inherited-marked ACE.
Windows canonicalizes duplicate SYSTEM ACEs into one.
All modified ACLs belong exclusively to newly created fixtures
under `C:\REA-LAB\artifacts`.

New conformance JSON SHA-256:
`1baa7837282b527831784f517f9c50ce6d1c646b9cff15185ec0a460b49acc4a`.

The Electron Evidence SHA-256 remains
`c764daf2c4a3126ffe48acb7e34eb69c47799399dbcedef34ea5af18b76570e6`.

The sections below record the **earlier** first-generation addon
and remain as an audit trail. The hardened SHA is the latest tested
candidate; do not substitute the earlier addon SHA when deploying or
running the expanded root-flag regression.

**Release limitation:** this is not a successful normal-user SID
execution test, Ghidra/IDA/Hopper validation, a resolved wide-audit
`rea doctor`, or CI coverage. **Keep PR #2 draft and do not deploy
to production** pending those independent checks.

## Isolated cross-build — PVE161-HOST

- Build environment: Debian 12, MinGW-w64 GCC 12-posix, official Node.js 24.22.1 x64 for Linux.
- Staging only: `/var/tmp/rea-native-build-20261026`.
- The MinGW compiler, associated libraries and Windows headers were downloaded from Debian's configured repositories and **extracted** into the staging tree via `dpkg-deb -x`. No `apt install`, package database update, Proxmox service restart or globally installed compiler.
- Node Linux archive's SHA-256 matched the official Node.js v24.22.1 `SHASUMS256.txt`.
- Seven downloaded source/build files were each checked against the exact Git blob SHA from fork commit `6b3443a`.
- **Reproducible build check, 2026-10-26:** ran the same builder a second time in the same isolated MinGW/Node staging environment. `cmp` confirmed both the rebuilt `.node` binary **and `manifest.json`** were byte-for-byte identical to the first run. Addon SHA-256 stayed `2ef814532639a53f6a490bc8631db96be8c59b2e1ce48ef863dbfdaadf1e65a6`. This verifies repeatability within this environment, not across independent compiler versions.
- Ran `node scripts/build-windows-native.mjs` with staging-only toolchain in `PATH`, `LD_LIBRARY_PATH` and `HOME`. The upstream build script fetches/verifies pinned Node 22.19.0 Node-API headers and cross-compiles the addon.

Build output:

| Item | Verified value |
| --- | --- |
| Addon | `rea-windows-x64.node` |
| Size | 1,058,743 bytes |
| SHA-256 | `2ef814532639a53f6a490bc8631db96be8c59b2e1ce48ef863dbfdaadf1e65a6` |
| Manifest SHA-256 | `e39dd542cd0db5af048555622527d60c6f87f9960f5e877b9a07e2ae88d39bcc` |
| Manifest | `packageVersion=6.8.0`, Windows x64, ABI 1, Node-API 8 |

The staged toolchain did not alter global MinGW availability.

## Windows 181 isolated verification

The artifact and manifest were transferred using a **single-use read-only server** restricted to client IP `103.9.156.181`; the temporary listener terminated after one successful transfer. The ZIP SHA-256, addon SHA-256 and manifest digest were independently validated on WIN11-181.

- Staged binary: `C:\REA-LAB\artifacts\native-pr2-6b3443`.
- Isolated REA package copy: `C:\REA-LAB\runtime\node_modules\rea-agents-pr2`, pointing at the same published `6.8.0` dependencies; only this copy's native addon and manifest were replaced.
- The original published package remained untouched with native-addon SHA-256 `6a015bfefee7fafb6cbaf659f040170848a45425bbcef6caf962fd39b6ff7b`.
- Process identity: `NT AUTHORITY\\SYSTEM`; process-local `TEMP`/`TMP` were set to `C:\REA-LAB\tmp`.

### Native direct self-test

`node C:\REA-LAB\artifacts\native-pr2-6b3443\inspect.cjs` using the pinned Node 24.22.1 returned exit 0 with `privateDacl`, `privateBridgeDescriptorAccess`, `atomicJobAssignment`, `killOnOwnerClose`, `protocolStdin`, `jobMemoryLimit` all true. Three additional **fresh-process** executions also passed 3/3, with zero residual `rea-native-probe-*` directories in lab temp.

### Official source Windows conformance, isolated

The **exact** `scripts/verify-windows-native.mjs` from patched commit `6b3443a` was copied to `C:\REA-LAB\validation-pr2\scripts` with its four local helper imports, and run as:

```powershell
& C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe `
  C:\REA-LAB\validation-pr2\scripts\verify-windows-native.mjs `
  C:\REA-LAB\runtime\node_modules\rea-agents-pr2
```

Returned **exit 0, `ok: true`**, reporting **23 filesystem/native controls and 8 process checks**. This includes strict protected DACL readback, forged handle rejection, source replacement/write denial, reparse/junction isolation, immutable snapshot digests, cleanup retry ownership, process descendants, Job Object termination, stdin and memory limit tests. Some process fields return structured results validated by the verifier rather than literal booleans.

Conformance Evidence SHA-256:
`769d15cd567697ac2cb919fa82652c9277f29527acac4a4463f59b189c6d020c`.

### JavaScript/Electron end-to-end regression

```powershell
& C:\REA-LAB\toolchains\node-v24.22.1-win-x64\node.exe `
  C:\REA-LAB\runtime\node_modules\rea-agents-pr2\scripts\rea.mjs `
  analyze-javascript-application C:\REA-LAB\fixtures\sample-electron-app --json
```

Returned **exit 0**, provider `rea-javascript-application`, structured Evidence with application inventory and graphs. This exact four-file synthetic fixture previously failed at native authority with `capability_unavailable`. Evidence output: 462,674 bytes, SHA-256:
`c764daf2c4a3126ffe48acb7e34eb69c47799399dbcedef34ea5af18b76570e6`.
There were no residual `rea-native-probe-*` or `rea-native-conformance-*` directories in the isolated lab temp after verification.

## Direct native addon A/B regression under LocalSystem

An automated same-host comparison was added to [lab PR #1](https://github.com/trinhtanphat/rea/pull/1) as `scripts/fork-lab-native-ab.ps1`. On 2026-10-26, both addon files were copied to unique isolated fixture directories and inspected with the same portable Node 24.22.1, the same LocalSystem token and `C:\\REA-LAB\\tmp`:

| Artifact | SHA-256 | Native result |
| --- | --- | --- |
| Original published REA 6.8.0 | `6a015bfefee7fafb6cbaf659f040170848a45425bbcef6caf962fd39b6ff7b` | **Exit 1**, historical `Private DACL contains unexpected trustees`, **Win32 5** |
| Source-patched PR #2 | `2ef814532639a53f6a490bc8631db96be8c59b2e1ce48ef863dbfdaadf1e65a6` | **Exit 0**, `privateDacl=true` and native capability inspection passes |

The script performs checksum assertions before loading the binary, preserves both installed addon files, writes only its own new lab fixture directories and returns a machine-checked JSON result. This directly demonstrates the specific LocalSystem native behavior change; it is not proof of operation under an ordinary Windows user token.

## Side-by-side static parser regression

The lab matrix on [draft PR #1](https://github.com/trinhtanphat/rea/pull/1) now accepts an explicitly selected `-CliPath` only for a REA `scripts\\rea.mjs` located under `C:\\REA-LAB`. The same six parser-only model-header / managed-.NET / PE valid-and-invalid cases were rerun on 2026-10-26 against both package copies:

- **Patched** `C:\\REA-LAB\\runtime\\node_modules\\rea-agents-pr2\\scripts\\rea.mjs`: **6/6 passed**.
- **Original** `C:\\REA-LAB\\runtime\\node_modules\\rea-agents\\scripts\\rea.mjs`: **6/6 passed**.

This is 12 successful assertions, confirming no observable regression in these three specific static parser commands. It does **not** prove all providers or a normal-user SID integration.

## Direct native private DACL rejection regression

A security-focused negative fixture suite was added to
[lab PR #1](https://github.com/trinhtanphat/rea/pull/1) as
`scripts/fork-lab-native-acl-negative.ps1` (commit `18f1fd6`).
It invokes the source-built patched addon directly through the
read-only `cutter_bridge_verify_directory` operation on six
**new synthetic directory fixtures** under `C:\\REA-LAB\\artifacts`.

2026-10-26, WIN11-181, LocalSystem token, addon SHA-256
`2ef814532639a53f6a490bc8631db96be8c59b2e1ce48ef863dbfdaadf1e65a6`:
**6/6 PASS**. The only admitted fixture had one protected, full-control,
inheritable SYSTEM ACE. Five disallowed cases were rejected with Win32 5:
an extra Administrators trustee, non-inheritable ACE, reduced-access
mask, extra deny ACE, and unprotected DACL.

The on-disk DACL owner and protection flags were independently checked
before the native calls. Windows made the initially unprotected fixture
protected during creation, so the test re-enabled inheritance on
**that newly created fixture only** and verified its resulting readback.
The extra-deny-ACE case was rejected during file open; the other
negative cases reached native policy checks. This tests rejection policy
as well as the original LocalSystem fix, but does not prove all host
accounts and providers are covered.

## Packaged native artifact verification and tamper rejection

Both lab packages were checked with the **shipping REA artifact verifier**
`scripts/verify-windows-native-artifact.mjs` (not merely an independent digest
comparison):

- Published REA 6.8.0 native addon: verifier **exit 0**.
- Isolated patched PR #2 addon: verifier **exit 0**, `packageVersion=6.8.0`,
  Windows x64 PE32+, Node-API 8, matching manifest SHA-256.

A separate mutation matrix is committed to [lab PR #1](https://github.com/trinhtanphat/rea/pull/1)
as `scripts/fork-lab-artifact-guards.ps1`. The matrix clones only the
manifest, package metadata, native addon and shipping verifier into unique
disposable lab fixtures. It verifies an intact addon passes and five
modifications **fail closed**: fake digest, wrong package version,
unsupported Node-API version, wrong PE machine architecture with a
recomputed correct digest, and corrupted PE header with a recomputed
correct digest. This tests the PE validation in addition to the hash gate.

On WIN11-181 (2026-10-26), the published package passed **6/6**, and the
isolated patched package passed **6/6** (12 assertions in total).
No original or patched package files were modified; the two source-addon
SHA-256 digests were checked again afterward. No addon from these mutated
fixtures was loaded as executable code.

## Real Ghidra 12.1.4 x64 PE provider proof — WIN11-181

**Newly verified (2026-10-26):** The isolated hardened Windows addon
also works with **real Ghidra 12.1.4** and a portable 64-bit full
Amazon Corretto JDK 21.0.13 on a synthetic source-owned PE x64 DLL.
This goes beyond the earlier LocalSystem native controls and JavaScript
fixture. The full repeatable regression was added to
[lab PR #1](https://github.com/trinhtanphat/rea/pull/1),
source commit af9cde39325235a01d65406d4dc423fb34415663.

### Verified engine acquisition

- NSA Ghidra 12.1.4 PUBLIC (569649598 ZIP bytes), publisher SHA-256
  ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db.
  The previous GitHub prefix was completed using 72 exact-range chunks
  from a SourceForge mirror; **the full reassembled ZIP** was checked
  against the official NSA digest before extraction.
- Amazon Corretto JDK 21.0.13.0.10 Windows x64 full ZIP
  (202668246 bytes), official SHA-256
  abd264a79e07c64e19aaa705e5b8ea8db01d5213877b8ac0b855a94541a4b0fd.
  The release checksum came from the publisher's latest_sha256
  endpoint; digest was verified before and after the temporary,
  one-use IP-limited transfer from PVE161 to WIN11-181.
- Ghidra and JDK were extracted only beneath C:\REA-LAB\toolchains.
  No system Java installation, persistent PATH or JAVA_HOME change,
  Windows service restart or production addon replacement was made.
- The updated offline archive preflight accepts Ghidra plus **any one**
  of the two publisher-hash-pinned full JDK 21 ZIP options, and now
  reports ready=true, exit 0. The old incomplete Temurin ZIP remains
  a separate .partial file and is **not used**.

### Real CLI and decompiler observations

The C++ fixture source in lab PR #1 exports rea_lab_add and
rea_lab_mix. An 85850-byte MinGW-built PE32+ Windows x64 DLL was
transferred as a hash-checked, never-executed fixture, SHA-256
f3b3bb1f7b97924ac6d366204152592ee2ce80a1a93061fccbf27e4524996f41.
A separate isolated rebuild of the source did **not** produce a
byte-identical DLL, even with a disabled PE timestamp. The real
Ghidra evidence therefore pins exactly the checked fixture bytes;
we **do not claim reproducible binary output** across staging
directories. Future recompiled DLLs must receive an independent digest.

All Ghidra-specific scoped doctor checks were **healthy**, including
the native Windows x64 decompile.exe, Ghidra 12.1.4 headless launcher,
JDK 21 and Windows native authority. The **wide** doctor audit still
exits nonzero due **other** unconfigured optional providers/clients;
do not claim all providers are healthy.

The source-owned Windows runner in PR #1,
scripts/fork-lab-ghidra-real-provider.ps1, ran **all six phases
successfully** with the source-built hardened addon:

1. Exact Ghidra/JDK archive and fixture/addon checksum validation.
2. Real public CLI analyze against the synthetic PE x64 DLL: exit 0,
   composed workflow Evidence with **upstream provider ghidra 12.1.4**.
3. Real public CLI symbol search: exit 0, direct ghidra Evidence
   identifying rea_lab_add and rea_lab_mix at observed addresses.
4. Real public CLI decompile by observed address: exit 0 and direct
   ghidra Evidence reconstructing
   'return param_2 + param_1 + 7;', matching the source fixture.
5. Original DLL and native addon digests unchanged after analysis.
6. **No residual owned Java/Node process or REA native probe**.

The runner keeps environment variables scoped to each new REA
process, uses four logical CPU cores, BelowNormal priority, Java heap
-Xmx1024m and bounded stdout/stderr + operation timeout, and writes
its JSON/stderr under unique C:\REA-LAB\artifacts folders. It neither
executes the target DLL nor modifies live apps or REA installations.

**Coverage boundaries:** this is actual Ghidra 12.1.4 integration
for a small PE x64 DLL under LocalSystem. It does **not** prove
ordinary-user Windows SID behavior, IDA/Hopper providers, all target
formats/architectures, or full REA MCP Ghidra workflows. These
remaining lanes stay open and both PRs remain draft.

## Real REA/Ghidra MCP stdio regression — WIN11-181

**Newly verified 2026-10-26:** Actual REA MCP stdio works with Ghidra
12.1.4, a portable Corretto JDK 21, and the source-built hardened Windows
addon on a source-owned PE x64 DLL. A repeatable bounded test was
committed to [lab PR #1](https://github.com/trinhtanphat/rea/pull/1)
at commit 01c32b4b8283e488e9589c43a07cb087ad5f13e2, file
scripts/fork-lab-ghidra-mcp-smoke.mjs.

The test SHA-pins the native addon and the DLL, starts its own
REA MCP server with process-local Ghidra/Java settings, negotiates
MCP protocol 2025-06-18, enumerates **229 tools**, then verifies:

1. open_binary with verified DLL path and provider_id ghidra;
2. binary_overview using the selected Ghidra-backed document;
3. search_procedures finding both rea_lab_add and rea_lab_mix;
4. procedure_pseudo_code reconstructing the expected +7 operation.

**All four MCP calls passed**. Overview response length was
17,155 JSON UTF-8 bytes; SHA-256
f4b0caa3fded4662fac3fc8b80933c824fc0587abafb3d92b061605e70f336b0.
Captured catalog, four MCP results, summary and stderr reside at
C:\REA-LAB\artifacts\ghidra-mcp-real-VLVf17.

No REA MCP was installed into Private Commander or the user's
interactive Session 2. No Windows account, global runtime,
production ACL or service configuration was changed. No owned
Java/Node process or native temporary probe remained after the
run.

This proves **four read-only Ghidra MCP tools on one synthetic
PE x64 DLL under LocalSystem**, not all 229 advertised tools,
a non-SYSTEM user, IDA/Hopper, or other target formats.

## Additional MCP fail-closed regression (lab PR #1 `075ed85`)

The isolated real Ghidra 12.1.4 MCP stdio test now includes a
**negative-then-positive same-session** transition. An `open_binary`
request for a unique **nonexistent file inside the lab** returned
an MCP error as required. Without restarting the MCP server, the
client then successfully opened the source-owned PE x64 DLL,
ran `binary_overview`, found `rea_lab_add` and `rea_lab_mix`
via `search_procedures`, and decompiled `rea_lab_add`
with `procedure_pseudo_code` to recover the `+7` operation.

All assertions passed on WIN11-181 under LocalSystem. Source:
[PR #1 regression runner](https://github.com/trinhtanphat/rea/blob/chore/windows181-lab-preflight/scripts/fork-lab-ghidra-mcp-smoke.mjs),
commit `075ed85293d5008b2c2fc2a43ecf508c26a236ca`.
The JSON evidence is preserved in
`C:\REA-LAB\artifacts\ghidra-mcp-real-v5o70r`.
This checks **rejecting a missing input and continuing with a
legitimate one**; it does not establish broader sandbox boundary
isolation or the safety of all REA MCP tools.

### Non-SYSTEM service-account attempt (not passed)

An isolated, temporary Windows Task Scheduler entry was used
to try a **LocalService** (`S-1-5-19`) identity probe without
accessing the interactive Admin Session 2 or creating a user.
The task returned `LastTaskResult=1` and **did not create the
expected identity-report file**. The temporary scheduled task was
then unregistered successfully. This establishes **no positive
non-SYSTEM native-addon coverage**; the reason for the task's
failure was not confirmed, and no further privilege/ACL workaround
was attempted. Do not conflate this with a normal Windows user test.

## SID oracle negative-control strengthening (lab commit `a81fe85`)

A four-lane Windows native verifier suite now passes on WIN11-181
under LocalSystem, based on the exact hardened PR #2 addon:

1. Unmodified independent-SID verifier: **23 filesystem/native
   checks plus 8 process checks PASS, exit 0**.
2. Fake *self-consistent* `userIsSystem` and ACE count in the
   observer: **rejected, exit 1**.
3. A fake `whoami.exe` prepended to PATH: **ignored**, source
   verifier still passes using the absolute System32 executable.
4. Source-level fault injection changing only the verifier's
   SID-oracle path to an absent lab directory: **rejected, exit 1**.

Source: [PR #1 runner](https://github.com/trinhtanphat/rea/blob/chore/windows181-lab-preflight/scripts/fork-lab-sid-observer-negative.mjs),
commit `a81fe85485d28c70ea60d938d601054684344b1e`.
Evidence directory:
`C:\REA-LAB\artifacts\native-sid-observer-v2Ap5O`.

**Important test-harness boundary:** replacing the actual Windows
`SystemRoot` process environment prevents Node 24.22.1's own
CSPRNG from initializing *before the verifier executes*. The
fourth test therefore modifies **only an isolated copy of the
verifier source**, keeping the real process environment untouched.
It tests fail-closed behavior of the source-level identity oracle,
not an external Windows `SystemRoot` fault.

### Non-SYSTEM service token: still not verified

Two isolated LocalService Task Scheduler identity attempts could
not produce a user-SID report (last task result 1). The second
attempt used valid script syntax and a narrowly scoped
`S-1-5-19` modify ACE **only on one disposable lab fixture
directory**. Even then no report appeared; the task was deleted
and its temporary explicit ACE removed successfully. Do not
claim normal-user or LocalService native conformance from
these attempts. No production directory ACL, persistent account
or interactive Session 2 setting was altered.

## REA MCP decompiler recovery and provider lifecycle (PR #1 `bdfa029`)

The isolated Ghidra 12.1.4 Windows PE x64 MCP runner was extended
to cover **same-session state recovery and clean provider closure**.
After rejecting a nonexistent DLL, the server still opened a
valid hash-pinned PE. A later `procedure_pseudo_code` call on
a deliberately nonexistent procedure returned an error as required;
a subsequent call for `rea_lab_add` **successfully recovered its
expected C pseudocode with `+7`**. The client then explicitly called
`close_binary` and verified `binary_session` reported both
`open=false` and `cleanup_pending=false`.

These assertions passed on WIN11-181 with REA MCP protocol
2025-06-18, Ghidra 12.1.4, portable JDK 21 and the unchanged
hardened PR #2 addon under LocalSystem. Captured outputs:
`C:\REA-LAB\artifacts\ghidra-mcp-real-ezWfr5`.
The repeatable source is
[PR #1 commit `bdfa029`](https://github.com/trinhtanphat/rea/pull/1).
No orphaned owned Ghidra/REA process or native probe remained, and
nothing was registered with production MCP or Session 2.

This is verified **for the selected PE x64 fixture and these MCP
operations only**, not a release proof for all advertised tools or
a Windows non-SYSTEM identity.

## Ghidra MCP reopen-after-close lifecycle (PR #1 `3d71508`)

An additional real LocalSystem Ghidra 12.1.4 stdio MCP regression
now verifies a **full reopen after a clean provider close** in the
**same REA server process**, using the same SHA-256-pinned source-owned
PE x64 DLL and hardened native addon.

The test follows this sequence: select binary, analyze, reject a
missing procedure, successfully decompile `rea_lab_add`, call
`close_binary`, verify `binary_session` reports
`open=false` and `cleanup_pending=false`, **reopen the identical
binary**, issue a second `binary_overview`, close again, and verify
the same two closed-session fields. The two overview JSON files are
**byte-identical** (SHA-256
`91215a33552ca3069cc2187363af4dfc1ab6c2a7fa3e7830e95894a287dd7a86`).
The final isolated output is
`C:\REA-LAB\artifacts\ghidra-mcp-real-qMb6J5`; no owned
Java/Node or native probe residue remained.

The repeatable test was committed in
[lab PR #1, commit `3d71508`](https://github.com/trinhtanphat/rea/pull/1),
under `scripts/fork-lab-ghidra-mcp-smoke.mjs`.
This is Windows LocalSystem / one x64 PE / Ghidra MCP only. A
genuine non-SYSTEM user token and IDA/Hopper are **not validated**.
There was no change to any live/private MCP connection.

## Git remote guard confirmation after Private Commander reconnect

On 2026-10-26, the WIN11-181 Private Commander tunnel recovered,
allowing direct reconciliation of the previously locally modified
lab files against lab PR #1's GitHub tree. Both locally modified
guard/sync scripts were **byte-identical** to the corresponding
remote blobs. The former six-case test source was backed up
before a non-forced local fast-forward to the eight-case GitHub
test. The source files were preserved in an isolated SHA-verified
lab backup and a recovery Git stash, with the local worktree
clean after synchronization.

The real Windows PowerShell 5.1 tests were then rerun against
the exact GitHub branch revision:
- `fork-lab-github-remote-guard-test.ps1`: **22/22 PASS**;
- `fork-lab-github-remote-endpoints-test.ps1`: **8/8 PASS**,
  including malicious `insteadOf` and `pushInsteadOf` rewrites;
- Four PowerShell lab guard/test scripts: **0 parser errors**.

**30/30 Git URL / effective endpoint tests PASS on WIN11-181**.
The latest checked isolated fixture directory is
`C:\REA-LAB\artifacts\fork-git-endpoint-check-721d77cabf0c427e9400c24a90eb4ad1`.
The lab PR #1 documentation was updated and pushed at
commit `fc44640e421f46162194010ca2a2c3be840c9808`.

This test protects the **lab fork synchronization utility**.
It does not prove a non-SYSTEM caller can run the native addon,
does not resolve optional IDA/Hopper providers, and does not
authorize merging PR #2 into `main` or changing live services.

## Reproducible Ghidra PE x64 builder and real Windows analysis — 2026-10-26

The lab PR #1 now contains
`scripts/fork-lab-ghidra-reproducible-pe.sh`, a reproducible,
**isolated** MinGW-w64 build check for the source-owned C++ test DLL.
The earlier DLL rebuild divergence was traced to the linker's
auto-selected **PE ImageBase**. Pinning
`-Wl,--image-base,0x180000000` alongside
`-Wl,--no-insert-timestamp` resolved this for the PVE161
toolchain.

The **exact tracked C++ source bytes**, SHA-256
`ddf7f6af4e9044a2adbd49224fe235e073da96dadb8308ed53faef3f56767b5f`,
were staged in PVE161's isolated lab. Two distinct invocations,
each compiling into two new directories, produced **four
byte-identical PE32+ AMD64 DLLs** of 85,853 bytes, all SHA-256
`8be0a6f9f9ae5a18e2dcf65f0e0b21d0034b968c6606fb112b07133f372da299`.
The verifier also checked the two export names, zero PE timestamp,
fixed ImageBase and that changing one byte alters the output.
PVE161 Evidence manifests:
`/var/tmp/rea-native-build-20261026/fixtures/pe-repro-cQy3lShm`
and
`/var/tmp/rea-native-build-20261026/fixtures/pe-repro-jrGlPByX`.

The same deterministic PE was transferred via a one-use restricted
internal HTTP listener into a **separate** fixture directory on
WIN11-181. Its destination SHA-256 was reverified and the
unchanged isolated hardened REA addon was used to invoke **real**
`rea analyze --provider ghidra --json`. This **passed, exit 0**:
the Evidence reported upstream **Ghidra 12.1.4** and matched the
deterministic PE SHA-256 above. Evidence file SHA-256:
`8d0ff274867a917ff31888d0ec953952492e9b04461f36c81996a6ffa78bdd1e`;
path
`C:\REA-LAB\artifacts\ghidra-deterministic-pe-analysis-20261026`.

**Full Windows Ghidra 12.1.4 regression on deterministic DLL:
6/6 PASS**, also completed later on 2026-10-26. The source-owned
Windows runner in lab PR #1 now accepts `-Deterministic`, selecting
only the separate 85,853-byte DLL path and its pinned SHA-256.
It passed verified official archives, actual `analyze`,
`search_procedures` for `rea_lab_add` and `rea_lab_mix`,
`decompile` at **0x180001370** reproducing
`return param_2 + param_1 + 7;`, and post-run file
integrity plus owned-process cleanup. The complete six-phase
summary and captured responses are at
`C:\REA-LAB\artifacts\ghidra-real-provider-d91ae23c0aed473aaf02ee9da2141d42`,
documented in [PR #1 commit `36d7c3fa`](https://github.com/trinhtanphat/rea/pull/1).

The original fixture and its previous **full** Ghidra CLI/MCP
regressions remain unchanged; the new DLL is not a replacement.
Proof of byte reproducibility is bound to **this isolated compiler,
source and environment**, not universal cross-compiler output.
Genuine non-SYSTEM Windows tokens, IDA/Hopper integrations and
other architectures remain unverified. Nothing was installed
globally or changed in desktop Session 2, production MCP,
game or service.

## Non-SYSTEM Windows service token conformance and normal-user admission guard (2026-10-26)

An isolated, short-lived, noninteractive Windows Task Scheduler
invocation on WIN11-181 ran the exact PR #2 Windows native source verifier
with the hardened addon under **NT AUTHORITY\LOCAL SERVICE**, SID
**S-1-5-19**, Session **0**. The real native process returned **exit 0**,
with **23 filesystem/native controls and 8 process checks (31/31 PASS)**.
The native Evidence JSON SHA-256 was
22179bcf73395a91688446900148d64250176aa0f4f554d1bd87decb52c05cb2.
Evidence lives exclusively in
C:\REA-LAB\artifacts\localservice-native-4278e73a5da84cfd9253e446d6399b54.
Only a newly created lab-owned artifacts subdirectory was granted
LOCAL SERVICE modify access. The temporary task was unregistered after
completion; no Windows user account, production ACL, service, or Session 2
configuration changed.

**Classification caveat:** LOCAL SERVICE is a genuine non-SYSTEM
**service account**, not an ordinary Windows user's token. This
successful native conformance run cannot close the release requirement
for a normal interactive or legitimately launched user account.
The old normal-user lab launcher had rejected only
S-1-5-18, so it could mislabel service principals as ordinary users.
The script scripts/verify-windows-normal-user-lab.ps1 now rejects
S-1-5-18, S-1-5-19, S-1-5-20 and any token carrying the
Windows SERVICE group S-1-5-6 **before creating output
or executing the verifier**. PowerShell parse plus git diff --check
passed; SYSTEM and actual LOCAL SERVICE invocation both failed closed
with the expected **exit 2**. The temporary LOCAL SERVICE guard task was
also removed after testing; guard Evidence:
C:\REA-LAB\artifacts\rea-pr2-service-guard-20261026\guard-summary.json.
This guard has not been positively exercised under a legitimate
ordinary Windows user token, so both PRs remain Draft and undeployed.

## Remaining validation and release boundaries

- `rea doctor` in wide audit mode still reports `healthy=false` / `environment_healthy=false` due **other** optional engines and registrations (such as Hopper/IDA/JADX). Ghidra 12.1.4 with JDK 21 is **now present in the isolated lab** and all Ghidra-specific scoped doctor checks are healthy, with a real PE x64 CLI analysis/search/decompile passing. **Do not report the entire wide audit as healthy**.
- The patched addon has **not** been executed under a distinct ordinary Windows user SID. A further native API proof using the real SID of an existing non-SYSTEM interactive account as an **explicit ACL trustee** returned two distinct ACEs for that SID and SYSTEM (3/3 ACL readback cases now pass). This remains a synthetic DACL case, not a native addon run under that user's token.
- An authenticated interactive `Admin` session 2 is present on WIN11-181. An attempted direct desktop `WIN+R` input returned `SendInput inserted 0/4 events; UIPI/elevation may be blocking desktop input`. No further UI/privilege workaround was attempted. The existing user session was not altered.
- A reusable, fail-closed non-SYSTEM conformance launcher is added as `scripts/verify-windows-normal-user-lab.ps1`. It requires an explicit isolated lab package, source verifier, Node path and artifact SHA-256, and uses the caller's normal token without changing accounts or ACLs. PowerShell 5.1 syntax checks **passed**; LocalSystem and a real LocalService service-token invocation were both **rejected with exit 2**. The underlying native verifier separately passed 31/31 under LocalService, but the **positive ordinary-user execution remains unverified**, so do not mark the normal-user requirement complete.
- Real **Ghidra 12.1.4 PE x64 CLI and four-tool MCP stdio** analysis/search/decompile are now **verified** under LocalSystem only. Broader Ghidra MCP tools and target families, IDA/Hopper workflows, extended product CI, GitHub Actions and production service installation remain **unverified**.
- The upstream Win32 5 *delete-by-handle* report (#1701) describes a different symptom and is not marked fixed by this PR.
- **Do not merge or deploy into the live game, Private Commander, global tools or fork main merely because the LocalSystem and one real Ghidra PE x64 lane pass.** Keep draft until the genuine normal-user token test, other required provider regressions, a reviewed diff and a deliberate merge decision.
