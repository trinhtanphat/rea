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
deleting native self-test directories. One possible explanation is that the
runner's current-user SID and the SYSTEM SID coincide. This remains a
hypothesis without a rebuilt addon and an independent Windows DACL readback.
Do not change production access controls based only on this observation.
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
