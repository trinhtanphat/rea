# Windows LocalSystem ACL fix — native build and verification record

> Scope: fork-only draft PR #2, commit `6b3443a3b6dea831e27d8826f4650f72fd6a5d7b`, tested 2026-10-26.
> No native addon, account, service configuration, ACL, or global Node installation was changed in production.

## Issue and source patch

The Private Commander host on WIN11-181 executes as `NT AUTHORITY\\SYSTEM` (SID `S-1-5-18`). The published REA 6.8.0 addon fails native security admission with `Private DACL contains unexpected trustees` because the unpatched verifier requires exactly two ACEs for the current user and SYSTEM, which are the same SID in this process.

The independent readback proof in [draft PR #1](https://github.com/trinhtanphat/rea/pull/1) uses actual Win32 `CreateDirectoryW` and `GetFileSecurityW` APIs. Two identical SYSTEM full-control ACEs in the input returned **one** on NTFS; different SYSTEM + Administrators ACEs returned **two**. This PR's source change constructs one explicit ACE only if those principals are identical. Ordinary user accounts retain two ACEs and the native verifier still requires exact ACE count, owner, inheritance, mask, trustee and protected DACL.

## Isolated cross-build — PVE161-HOST

- Build environment: Debian 12, MinGW-w64 GCC 12-posix, official Node.js 24.22.1 x64 for Linux.
- Staging only: `/var/tmp/rea-native-build-20261026`.
- The MinGW compiler, associated libraries and Windows headers were downloaded from Debian's configured repositories and **extracted** into the staging tree via `dpkg-deb -x`. No `apt install`, package database update, Proxmox service restart or globally installed compiler.
- Node Linux archive's SHA-256 matched the official Node.js v24.22.1 `SHASUMS256.txt`.
- Seven downloaded source/build files were each checked against the exact Git blob SHA from fork commit `6b3443a`.
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

## Remaining validation and release boundaries

- `rea doctor` in wide audit mode still reports `healthy=false` / `environment_healthy=false` because optional analysis engines (notably Ghidra) and registrations are **not configured** on WIN11-181. That does not contradict the separately passing native self-test and JavaScript fixture. **Do not report the entire doctor as healthy**.
- The patched addon has not been tested under a distinct ordinary Windows user SID.
- Ghidra/IDA/Hopper workflows, extended product CI, GitHub Actions and installation into a production service remain **unverified**.
- The upstream Win32 5 *delete-by-handle* report (#1701) describes a different symptom and is not marked fixed by this PR.
- **Do not merge or deploy into the live game, Private Commander, global tools or fork main merely because the LocalSystem lane passes.** Keep draft until normal-user and relevant provider regression, a reviewed diff and a deliberate merge decision.
