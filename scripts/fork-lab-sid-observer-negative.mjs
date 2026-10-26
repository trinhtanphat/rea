#!/usr/bin/env node
/**
 * Assert that the REA Windows ACL observer independently checks the caller SID.
 * Run the original conformance verifier and a deliberately forged observer.
 * Only disposable fixture files under REA-LAB/artifacts are created.
 *
 * Usage: node scripts/fork-lab-sid-observer-negative.mjs <lab> <verifier.mjs> <package>
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, dirname, resolve, sep } from "node:path";

assert.equal(process.platform, "win32", "This test requires real Windows.");
const [rootArg, verifierArg, packageArg] = process.argv.slice(2);
assert.ok(rootArg && verifierArg && packageArg, "Expected lab root, source verifier and package.");
const lab = resolve(rootArg);
const source = resolve(verifierArg);
const pkg = resolve(packageArg);
const underLab = (p) => p.toLowerCase().startsWith((lab + sep).toLowerCase());
assert.ok(underLab(source) && underLab(pkg), "Verifier and package must be inside the REA lab.");
assert.equal(source.split(sep).at(-1), "verify-windows-native.mjs");
const code = await readFile(source, "utf8");
const anchor = "    assert.deepEqual(acl, {";
assert.equal(code.split(anchor).length, 2, "Expected one ACL assertion anchor.");
assert.match(code, /userIsSystem: callerIsSystem/u, "Expected independent token-SID assertion.");
const workspace = await mkdtemp(join(lab, "artifacts", "native-sid-observer-"));
const helpers = [
  "windows-protocol-input.mjs",
  "windows-job-memory-limit.mjs",
  "windows-volume-root-append-lease.mjs",
  "verifier-cleanup.mjs",
];
const originalDir = join(workspace, "original", "scripts");
const forgedDir = join(workspace, "forged", "scripts");
for (const dest of [originalDir, forgedDir]) {
  await mkdir(join(dest, "lib"), { recursive: true });
  for (const file of helpers)
    await copyFile(join(dirname(source), "lib", file), join(dest, "lib", file));
}
const altered = code.replace(anchor,
  "    const forgedAcl = { ...acl, userIsSystem: !callerIsSystem, count: callerIsSystem ? 2 : 1 };\n" +
  "    assert.deepEqual(forgedAcl, {");
const originalScript = join(originalDir, "verify-windows-native.mjs");
const forgedScript = join(forgedDir, "verify-windows-native.mjs");
await writeFile(originalScript, code, { flag: "wx" });
await writeFile(forgedScript, altered, { flag: "wx" });
const env = { ...process.env, TEMP: join(lab, "tmp"), TMP: join(lab, "tmp") };
const run = (script) => {
  const result = spawnSync(process.execPath, [script, pkg], {
    env, encoding: "utf8", shell: false, windowsHide: true,
    timeout: 90_000, maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  return result;
};
const positive = run(originalScript);
assert.equal(positive.status, 0, "Positive verifier failed: " + positive.stderr.slice(-1500));
const parsed = JSON.parse(positive.stdout);
assert.equal(parsed.ok, true);
assert.ok(Object.keys(parsed.controls).length >= 20);
assert.ok(Object.keys(parsed.processes).length >= 8);
const negative = run(forgedScript);
assert.notEqual(negative.status, 0, "Forged ACL observer unexpectedly passed.");
assert.match(negative.stderr, /userIsSystem/u, "Expected SID mismatch, not unrelated failure.");
assert.match(negative.stderr, /AssertionError/u);
await writeFile(join(workspace, "positive.json"), positive.stdout, { flag: "wx" });
await writeFile(join(workspace, "negative.stderr.txt"), negative.stderr, { flag: "wx" });
const summary = {
  ok: true,
  sourceVerifierSha256: createHash("sha256").update(code).digest("hex"),
  positive: { exitCode: positive.status, controls: Object.keys(parsed.controls).length,
    processChecks: Object.keys(parsed.processes).length, passed: true },
  negative: { exitCode: negative.status, forgedSidAndAceCountRejected: true },
  workspace,
  productionFilesModified: false,
};
await writeFile(join(workspace, "summary.json"), JSON.stringify(summary, null, 2) + "\n", {flag: "wx"});
process.stdout.write(JSON.stringify(summary) + "\n");