#!/usr/bin/env node
/**
 * Bounded REA parser runner for the Windows fork lab.
 * Usage: node fork-lab-bounded-runner.mjs <rea.mjs> <operation> <input>
 *        <stdout.json> <stderr.txt> <timeout-seconds>
 *
 * No shell; executes only the installed REA CLI for one allowlisted
 * static parser. Writes no more than 4 MiB stdout and 256 KiB stderr,
 * and never replaces existing output files.
 */
import { spawn } from "node:child_process";
import { closeSync, openSync, writeSync } from "node:fs";
import { isAbsolute, dirname, resolve } from "node:path";

const MAX_STDOUT = 4 * 1024 * 1024;
const MAX_STDERR = 256 * 1024;
const ALLOWED = new Set([
  "inspect-model-artifact",
  "inspect-managed-artifact",
  "inspect-pe-imports",
]);
const [cli, operation, target, stdoutPath, stderrPath, rawSeconds] =
  process.argv.slice(2);
const seconds = Number(rawSeconds);
if (
  process.argv.length !== 8 ||
  !ALLOWED.has(operation) ||
  ![cli, target, stdoutPath, stderrPath].every((path) => path && isAbsolute(path)) ||
  dirname(resolve(stdoutPath)) !== dirname(resolve(stderrPath)) ||
  stdoutPath === stderrPath ||
  !Number.isInteger(seconds) ||
  seconds < 1 ||
  seconds > 60
) {
  console.error("Invalid bounded REA parser invocation");
  process.exitCode = 125;
} else {
  let stdoutFd;
  let stderrFd;
  try {
    stdoutFd = openSync(stdoutPath, "wx", 0o600);
    stderrFd = openSync(stderrPath, "wx", 0o600);
    const child = spawn(
      process.execPath,
      [cli, operation, target, "--format", "json"],
      {
        shell: false,
        windowsHide: true,
        cwd: dirname(resolve(stdoutPath)),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let failure = null;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let exited = false;
    const reject = (reason) => {
      if (failure !== null) return;
      failure = reason;
      try {
        child.kill();
      } catch {
        // Still fail closed if the OS refuses termination.
      }
    };
    const copyBounded = (chunk, outputFd, isStdout) => {
      const max = isStdout ? MAX_STDOUT : MAX_STDERR;
      const size = isStdout ? stdoutBytes : stderrBytes;
      if (size + chunk.byteLength > max) {
        reject(isStdout ? "stdout-budget" : "stderr-budget");
        return;
      }
      try {
        if (writeSync(outputFd, chunk) !== chunk.byteLength) {
          throw new Error("Short Evidence file write");
        }
      } catch (error) {
        reject(`output-write: ${error.message}`);
        return;
      }
      if (isStdout) stdoutBytes += chunk.byteLength;
      else stderrBytes += chunk.byteLength;
    };
    child.stdout.on("data", (chunk) => copyBounded(chunk, stdoutFd, true));
    child.stderr.on("data", (chunk) => copyBounded(chunk, stderrFd, false));
    child.on("error", (error) => reject(`spawn: ${error.message}`));
    const deadline = setTimeout(() => reject("timeout"), seconds * 1000);
    try {
      const code = await new Promise((resolveClose) => {
        child.once("close", (status) => {
          exited = true;
          resolveClose(status);
        });
      });
      if (failure !== null) {
        console.error(`REA static probe blocked: ${failure}`);
        process.exitCode = failure === "timeout" ? 124 : 125;
      } else {
        process.exitCode = Number.isInteger(code) ? code : 125;
      }
    } finally {
      clearTimeout(deadline);
      if (!exited) {
        try { child.kill(); } catch { /* bounded caller handles errors */ }
      }
    }
  } catch (error) {
    console.error(`REA bounded runner failed: ${error.message}`);
    process.exitCode = 125;
  } finally {
    if (stdoutFd !== undefined) closeSync(stdoutFd);
    if (stderrFd !== undefined) closeSync(stderrFd);
  }
}
