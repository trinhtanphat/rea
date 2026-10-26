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
