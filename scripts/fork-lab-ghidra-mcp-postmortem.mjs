#!/usr/bin/env node
// Read-only postmortem for the REA-LAB Ghidra stdio MCP smoke runner.
// Accept only direct evidence directory names under the pinned REA-LAB artifacts root.
import assert from "node:assert/strict";
import { readFile, realpath } from "node:fs/promises";
import { join, resolve, dirname } from "node:path";

const lab = resolve(process.argv[2] ?? "C:\\REA-LAB");
assert.equal(lab.toLowerCase(), "c:\\rea-lab", "Only C:\\REA-LAB is allowed");
const names = process.argv.slice(3);
assert.ok(names.length >= 1 && names.length <= 12,
  "Usage: node fork-lab-ghidra-mcp-postmortem.mjs C:\\REA-LAB ghidra-mcp-real-NAME [...]");
const artifacts = await realpath(join(lab, "artifacts"));
const smoke = await readFile(join(lab, "rea", "scripts", "fork-lab-ghidra-mcp-smoke.mjs"), "utf8");
const deadlineMatch = smoke.match(/const overviewAfterReopen\s*=\s*await request\("tools\/call",\s*\{name:"binary_overview",arguments:\{\}\},(\d+)\)/u);
assert.ok(deadlineMatch, "Could not safely infer the actual second-overview test deadline");
const secondOverviewClientDeadlineMs = Number(deadlineMatch[1]);
assert.ok(Number.isSafeInteger(secondOverviewClientDeadlineMs) && secondOverviewClientDeadlineMs > 0);
const results = [];
for (const name of names) {
  assert.match(name, /^ghidra-mcp-real-[a-zA-Z0-9]{4,32}$/u, "Use an evidence basename only");
  const dir = await realpath(join(artifacts, name));
  assert.equal(dirname(dir).toLowerCase(), artifacts.toLowerCase(), "Evidence outside artifacts");
  const stderrText = await readFile(join(dir, "stderr.txt"), "utf8");
  assert.ok(Buffer.byteLength(stderrText) <= 1024*1024, "Oversize stderr evidence");
  const lines = stderrText.split(/\r?\n/u).flatMap(line => {
    if (!line.startsWith("{")) return [];
    try { return [JSON.parse(line)]; } catch { return []; }
  });
  const events = lines.filter(x => x?.layer === "server" &&
    x.tool === "binary_overview" && typeof x.durationMs === "number");
  const overview = events.map((x, i) => ({
    attempt: i + 1,
    status: x.status,
    serverElapsedMs: Math.round(x.durationMs),
    serverCompletedAt: typeof x.time === "number" ? new Date(x.time).toISOString() : null,
    ...(i === 1 ? {
      clientDeadlineMs:secondOverviewClientDeadlineMs,
      exceededClientBudgetByMs: Math.round(x.durationMs-secondOverviewClientDeadlineMs),
    } : {})
  }));
  const optional = async (file) => {
    try { return JSON.parse(await readFile(join(dir, file), "utf8")); }
    catch(e) { if(e.code === "ENOENT") return null; throw e; }
  };
  const timings = await optional("rpc-timings.json");
  const summary = await optional("summary.json");
  results.push({
    evidence:name,
    summaryPassed:summary?.passed === true ? true : summary === null ? null : false,
    rpcTimingAvailable:timings !== null,
    rpcRecordedCount:Array.isArray(timings?.requests) ? timings.requests.length : null,
    overview,
    ...(overview.length > 1 && overview[1].status !== "ok" ?
      {secondOverviewUnsuccessful:true, rootCauseEstablished:false} : {}),
    ...(overview.length > 1 && overview[1].serverElapsedMs > secondOverviewClientDeadlineMs ?
      {serverResponseAfterClientBudget:true} : {}),
  });
}
console.log(JSON.stringify({ok:true, evidenceCount:results.length,
  deadlineSource:"fork-lab-ghidra-mcp-smoke.mjs", secondOverviewClientDeadlineMs,
  observations:results, note:"Server-side time above client budget is timing evidence, not root-cause attribution."},null,2));
