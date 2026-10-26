#!/usr/bin/env node
/**
 * Isolated Windows REA native+Electron consistency check across two Node builds.
 *
 * Usage: node scripts/fork-lab-node-version-matrix.mjs
 *   C:\REA-LAB
 *
 * Only uses pinned node executables and a fixed four-file source-owned
 * Electron fixture, not an untrusted external target.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";

assert.equal(process.platform, "win32", "Windows x64 required");
const lab = resolve(process.argv[2] ?? "C:\\REA-LAB");
assert.ok(lab.toLowerCase().endsWith("\\rea-lab"), "Use an existing REA-LAB root.");
const addon = join(lab, "runtime", "node_modules", "rea-agents-pr2-hardened",
                   "native", "windows", "build", "rea-windows-x64.node");
const cli = join(lab, "runtime", "node_modules", "rea-agents-pr2-hardened",
                 "scripts", "rea.mjs");
const verifier = join(lab, "validation-pr2", "scripts",
                      "verify-windows-native.mjs");
const target = join(lab, "fixtures", "sample-electron-app");
const tmp = join(lab, "tmp");
const workspace = await mkdtemp(join(lab, "artifacts", "rea-node-version-matrix-"));
const nodes = [
  {
    label: "Private Commander Node 24.21.0",
    version: "v24.21.0",
    path: "C:\\ProgramData\\PrivateCommander\\win181\\node\\node-v24.21.0-win-x64\\node.exe",
    sha: "ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32",
  },
  {
    label: "REA-LAB Node 24.22.1",
    version: "v24.22.1",
    path: join(lab, "toolchains", "node-v24.22.1-win-x64", "node.exe"),
    sha: "d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5",
  },
];
const sha256File = async (file) => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
};
assert.equal(await sha256File(addon),
  "4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019",
  "The source-built patched addon must be pinned and isolated.");
const env = { ...process.env, TEMP: tmp, TMP: tmp };
const invoke = (bin, args, timeout = 90_000) => {
  const proc = spawnSync(bin, args, {
    shell: false, windowsHide: true, encoding: "utf8", env,
    timeout, maxBuffer: 4 * 1024 * 1024,
  });
  if (proc.error) throw proc.error;
  return proc;
};
const leftovers = async () =>
  (await readdir(tmp)).filter((name) =>
    /^rea-native-(?:probe|conformance)-/u.test(name)).sort();
const initialLeftovers = await leftovers();
assert.deepEqual(initialLeftovers, [],
  "Refusing to ignore preexisting native test residue.");
const results = [];
for (let i = 0; i < nodes.length; i++) {
  const node = nodes[i];
  assert.equal(await sha256File(node.path), node.sha, "Unexpected Node executable SHA");
  const version = invoke(node.path, ["--version"], 15_000);
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), node.version);
  const conformance = invoke(node.path, [verifier, join(lab, "runtime",
                            "node_modules", "rea-agents-pr2-hardened")]);
  assert.equal(conformance.status, 0,
    "Windows native conformance failed: " + conformance.stderr.slice(-1000));
  const native = JSON.parse(conformance.stdout);
  assert.equal(native.ok, true);
  const nativeControls = Object.keys(native.controls).length;
  const processChecks = Object.keys(native.processes).length;
  assert.ok(nativeControls >= 23 && processChecks >= 8);
  const output = invoke(node.path,
    [cli, "analyze-javascript-application", target, "--json"]);
  assert.equal(output.status, 0,
    "Electron fixture failed: " + output.stderr.slice(-1000));
  const evidence = JSON.parse(output.stdout);
  assert.equal(evidence.provider.id, "rea-javascript-application");
  const hash = createHash("sha256").update(output.stdout).digest("hex");
  await writeFile(join(workspace, "node-" + i + "-conformance.json"),
                  conformance.stdout, { flag: "wx" });
  await writeFile(join(workspace, "node-" + i + "-electron.json"),
                  output.stdout, { flag: "wx" });
  results.push({ label: node.label, nodeVersion: node.version,
    nodeSha256: node.sha, nativeControls, processChecks,
    evidenceBytes: Buffer.byteLength(output.stdout, "utf8"),
    evidenceSha256: hash, conformancePassed: true, electronPassed: true });
}
assert.equal(results[0].evidenceSha256, results[1].evidenceSha256,
  "Electron Evidence differs across Node minor/patch releases.");
assert.equal(results[0].evidenceBytes, results[1].evidenceBytes);
assert.deepEqual(await leftovers(), initialLeftovers,
  "Owned native test directories leaked into REA-LAB temp.");
const summary = {
  ok: true, testedAs: "LocalSystem", sourceAddonSha256: await sha256File(addon),
  results, evidenceIdenticalAcrossNodeVersions: true,
  workspace, modifiedGlobalNode: false, productionServicesChanged: false,
};
await writeFile(join(workspace, "summary.json"), JSON.stringify(summary, null, 2) + "\n",
                { flag: "wx" });
process.stdout.write(JSON.stringify(summary) + "\n");