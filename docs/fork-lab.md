# Fork-only Windows REA test lab

This is an operator runbook for testing **authorized** repositories and built artifacts
with the \`trinhtanphat/rea\` fork. It does not change upstream REA's provider,
security or agent-setup contracts.

## WIN11-181 isolation

- Working checkout: \`C:\REA-LAB\rea\`. The GitHub fork retains all upstream
  branches, tags and their reachable commit histories; this local checkout is
  deliberately single-branch and shallow for reduced network/disk use.
- \`origin\`: \`https://github.com/trinhtanphat/rea.git\`.
- \`upstream\`: \`https://github.com/morluto/rea.git\`.
- Portable pinned Node.js: \`C:\REA-LAB\toolchains\node-v24.22.1-win-x64\`.
  Its archive was checked against the official Node.js SHA-256 manifest.
  No machine-wide Node.js upgrade is needed.

Select the portable runtime **for this PowerShell session only**:

\`\`\`powershell
$env:Path = "C:\REA-LAB\toolchains\node-v24.22.1-win-x64;$env:Path"
Set-Location C:\REA-LAB\rea
node --version
\`\`\`

From the branch containing the preflight script, perform the read-only check:

\`\`\`powershell
powershell.exe -NoProfile -File .\scripts\fork-lab-preflight.ps1
powershell.exe -NoProfile -File .\scripts\fork-lab-preflight.ps1 -TargetPath 'C:\path\to\authorized\artifact'
\`\`\`

The check reports whether Node.js satisfies REA's declared engine ranges
and whether npm, Git and the selected local path exist. It does **not**
assert that native providers are installed or verified. It executes no target
code, writes no files and downloads nothing. A nonzero exit status means
the preflight requires attention.

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

Check the current upstream \`AGENTS.md\`, \`docs/testing.md\` and
\`docs/installation.md\` before changing code. On a dedicated development
VM or isolated CI runner, use the pinned Node.js version:

\`\`\`powershell
npm ci
npm run check:fast
npm run test:focused -- path/to/relevant/test.test.ts
\`\`\`

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
merging into \`main\`. Keep \`upstream\` as a separate read-only source for
normal operations; never force-push over upstream branches or tags. Upstream
sync should be deliberate and checked for conflicts rather than automatic.
