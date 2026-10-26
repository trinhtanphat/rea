# Windows LocalSystem ACL fix — native build and verification record

> Scope: fork-only draft PR #2. Original LocalSystem source fix `6b3443a3b6dea831e27d8826f4650f72fd6a5d7b`; tightened protected-root ACE flags in source commit `3e375a39c17118638ae3df936cb18e0bd293b673`. Tested 2026-10-26.
> No native addon, account, service configuration, ACL, or global Node installation was changed in production.

## Issue and source patch

The Private Commander host on WIN11-181 executes as `NT AUTHORITY\\SYSTEM` (SID `S-1-5-18`). The published REA 6.8.0 addon fails native security admission with `Private DACL contains unexpected trustees` because the unpatched verifier requires exactly two ACEs for the current user and SYSTEM, which are the same SID in this process.

The independent readback proof in [draft PR #1](https://github.com/trinhtanphat/rea/pull/1) uses actual Win32 `CreateDirectoryW` and `GetFileSecurityW` APIs. Two identical SYSTEM full-control ACEs in the input returned **one** on NTFS; different SYSTEM + Administrators ACEs returned **two**. This PR's source change constructs one explicit ACE only if those principals are identical. Ordinary user accounts retain two ACEs and the native verifier still requires exact ACE count, owner, inheritance, mask, trustee and protected DACL.

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

## Remaining validation and release boundaries

- `rea doctor` in wide audit mode still reports `healthy=false` / `environment_healthy=false` because optional analysis engines (notably Ghidra) and registrations are **not configured** on WIN11-181. That does not contradict the separately passing native self-test and JavaScript fixture. **Do not report the entire doctor as healthy**.
- The patched addon has **not** been executed under a distinct ordinary Windows user SID. A further native API proof using the real SID of an existing non-SYSTEM interactive account as an **explicit ACL trustee** returned two distinct ACEs for that SID and SYSTEM (3/3 ACL readback cases now pass). This remains a synthetic DACL case, not a native addon run under that user's token.
- An authenticated interactive `Admin` session 2 is present on WIN11-181. An attempted direct desktop `WIN+R` input returned `SendInput inserted 0/4 events; UIPI/elevation may be blocking desktop input`. No further UI/privilege workaround was attempted. The existing user session was not altered.
- A reusable, fail-closed non-SYSTEM conformance launcher is added as `scripts/verify-windows-normal-user-lab.ps1`. It requires an explicit isolated lab package, source verifier, Node path and artifact SHA-256, and uses the caller's normal token without changing accounts or ACLs. PowerShell 5.1 syntax check **passed** and a LocalSystem invocation was **rejected with exit 2**. Its **positive non-SYSTEM execution remains unverified**, so do not mark the normal-user requirement complete.
- Ghidra/IDA/Hopper workflows, extended product CI, GitHub Actions and installation into a production service remain **unverified**.
- The upstream Win32 5 *delete-by-handle* report (#1701) describes a different symptom and is not marked fixed by this PR.
- **Do not merge or deploy into the live game, Private Commander, global tools or fork main merely because the LocalSystem lane passes.** Keep draft until normal-user and relevant provider regression, a reviewed diff and a deliberate merge decision.
