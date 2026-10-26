#!/usr/bin/env node
/**
 * Local bounded-runner regression tests. No network access, installers,
 * production artifacts or third-party binaries are involved.
 *
 * Usage: node scripts/fork-lab-bounded-runner-test.mjs C:\\REA-LAB\\artifacts
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

const artifacts = process.argv[2];
if (process.argv.length !== 3 || !artifacts || !isAbsolute(artifacts)) {
  throw new Error("Provide an absolute, dedicated test-artifacts directory");
}
assert.ok(statSync(artifacts).isDirectory(), "Artifacts root must exist");
const directory = join(artifacts, `runner-selftest-${randomUUID()}`);
mkdirSync(directory, { recursive: false });
const runner = fileURLToPath(new URL("./fork-lab-bounded-runner.mjs", import.meta.url));

const fixtures = [
  { name: "stdout-overflow", code: 125, source: 'process.stdout.write("X".repeat(5*1024*1024));' },
  { name: "stderr-overflow", code: 125, source: 'process.stderr.write("E".repeat(400*1024));' },
  { name: "deadline", code: 124, source: "setTimeout(() => {}, 20000);" },
];
const records = [];
for (const fixture of fixtures) {
  const stub = join(directory, fixture.name + ".mjs");
  const stdout = join(directory, fixture.name + ".json");
  const stderr = join(directory, fixture.name + ".stderr.txt");
  writeFileSync(stub, fixture.source, { flag: "wx" });
  const run = spawnSync(process.execPath, [
    runner,
    stub,
    "inspect-model-artifact",
    stub,
    stdout,
    stderr,
    "1",
  ], {
    cwd: directory,
    windowsHide: true,
    encoding: "utf8",
    timeout: 8_000,
    maxBuffer: 16 * 1024,
  });
  assert.equal(run.error, undefined, `Regression runner failed: ${fixture.name}`);
  assert.equal(run.status, fixture.code, `Unexpected code for ${fixture.name}: ${run.stderr}`);
  const stdoutBytes = statSync(stdout).size;
  const stderrBytes = statSync(stderr).size;
  assert.ok(stdoutBytes <= 4 * 1024 * 1024, "stdout budget bypassed");
  assert.ok(stderrBytes <= 256 * 1024, "stderr budget bypassed");
  records.push({
    test: fixture.name,
    expected_exit_code: fixture.code,
    observed_exit_code: run.status,
    stdout_bytes: stdoutBytes,
    stderr_bytes: stderrBytes,
    passed: true,
  });
}
process.stdout.write(JSON.stringify({
  passed: true,
  suite: "rea-static-runner-resource-guards",
  tests_passed: records.length,
  tests: records,
  evidence_dir: directory,
  fixture_only: true,
  production_target_executed: false,
}, null, 2) + "\n");
