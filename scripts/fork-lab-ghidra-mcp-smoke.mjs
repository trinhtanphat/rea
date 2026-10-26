#!/usr/bin/env node
/**
 * Real REA MCP stdio smoke against the source-owned PE x64 fixture.
 * Constrains input paths, pins native addon/target digests, scopes environment,
 * sends initialize -> tools/list -> one read-only binary_overview request.
 * Does not register MCP with any agent or touch desktop/session 2.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import readline from "node:readline";

assert.equal(process.platform, "win32", "Windows-only lab smoke");
const root = resolve(process.argv[2] ?? "C:\\REA-LAB");
assert.equal(root.toLowerCase(), "c:\\rea-lab", "Unexpected lab root");
const pkg = join(root, "runtime", "node_modules", "rea-agents-pr2-hardened");
const native = join(pkg, "native", "windows", "build", "rea-windows-x64.node");
const target = join(root, "fixtures", "ghidra-pe-arithmetic", "rea_lab_arithmetic.dll");
const cli = join(pkg, "scripts", "rea.mjs");
const ghidra = join(root, "toolchains", "ghidra1214-isolated", "ghidra_12.1.4_PUBLIC");
const jdk = join(root, "toolchains", "jdk21-corretto-isolated", "jdk21.0.13_0");
const tmp = join(root, "tmp");
const expectedNative = "4eb3ecf392d78f379f7105820ff07cdfda62996ae02e7c1c1abfd463f9313019";
const expectedTarget = "f3b3bb1f7b97924ac6d366204152592ee2ce80a1a93061fccbf27e4524996f41";
async function sha(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
assert.equal(await sha(native), expectedNative);
assert.equal(await sha(target), expectedTarget);
const workspace = await mkdtemp(join(root, "artifacts", "ghidra-mcp-real-"));
const env = { ...process.env, JAVA_HOME: jdk, GHIDRA_INSTALL_DIR: ghidra,
              REA_ANALYSIS_PROVIDER: "ghidra", JAVA_TOOL_OPTIONS: "-Xmx1024m",
              TEMP: tmp, TMP: tmp };
const key = Object.keys(env).find(x => x.toLowerCase() === "path") ?? "Path";
env[key] = join(jdk, "bin") + ";" + (env[key] ?? "");
const child = spawn(process.execPath, ["--max-old-space-size=1024", cli, "mcp"], {
  cwd: workspace, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false,
});
let stderr = "";
let diagnostics = [];
child.stderr.setEncoding("utf8");
child.stderr.on("data", data => {stderr = (stderr + data).slice(-500000);});
const pending = new Map();
let nextId = 0;
const reader = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
reader.on("line", line => {
  try {
    const m = JSON.parse(line);
    if (m.id === undefined) { diagnostics.push(m.method ?? "notification"); return; }
    const wait = pending.get(m.id);
    if (wait) {pending.delete(m.id);clearTimeout(wait.timer); wait.resolve(m);}
  } catch(err) {diagnostics.push("INVALID_JSON:" + String(err).slice(0,200));}
});
function request(method, params, ms) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {pending.delete(id);reject(Error("MCP timeout " + method));},ms);
    pending.set(id, {resolve, reject, timer});
    child.stdin.write(JSON.stringify({jsonrpc:"2.0",id,method,params})+"\n");
  });
}
function notify(method,params={}) {
  child.stdin.write(JSON.stringify({jsonrpc:"2.0",method,params})+"\n");
}
let successful = false;
try {
  const init = await request("initialize",
    {protocolVersion:"2025-06-18", capabilities:{}, clientInfo:{name:"rea-181-lab",version:"1.0"}}, 35000);
  assert.ok(init.result?.protocolVersion, "MCP initialization failed: "+JSON.stringify(init.error));
  notify("notifications/initialized");
  const list = await request("tools/list", {}, 35000);
  assert.ok(Array.isArray(list.result?.tools), "No MCP catalog: " + JSON.stringify(list.error));
  const tools = list.result.tools;
  const selected = tools.find(t=> t.name==="binary_overview");
  const meta = selected && {name:selected.name, description:selected.description?.slice(0,200),
      inputSchema:selected.inputSchema};
  const metadata = {protocolVersion:init.result.protocolVersion, toolCount:tools.length,
    ghidraTools:tools.filter(t=>/binary_overview|analyze_function|decompile|read_bytes|search_procedures/i.test(t.name)).map(t=>t.name),
    selectedTool:meta, toolNames:tools.map(t=>t.name),
    targetTools:tools.filter(t=>/target|document|session|project|provider|bind|open|select|attach/i.test(t.name))
      .map(t=>({name:t.name,description:t.description?.slice(0,140),inputSchema:t.inputSchema})),
    workerPid:child.pid};
  await writeFile(join(workspace,"catalog.json"),JSON.stringify(metadata,null,2)+"\n",{flag:"wx"});
  assert.ok(selected, "Expected binary_overview MCP tool not found");
  // The REA MCP catalog binds a selected document through open_binary.
  // binary_overview intentionally has an empty parameter object.
  const openTool = tools.find(t=>t.name==="open_binary");
  assert.ok(openTool?.inputSchema?.properties?.path, "REA open_binary schema missing path");
  assert.ok(openTool?.inputSchema?.properties?.provider_id, "REA open_binary schema missing provider_id");
  // Fail-closed negative control: the server must refuse a missing path,
  // without acquiring a target, before we select the real owned PE sample.
  const missing=join(root,"fixtures","ghidra-pe-arithmetic",
    ".never-exists-"+process.pid+".dll");
  const rejected=await request("tools/call",
    {name:"open_binary",arguments:{path:missing,provider_id:"ghidra"}},20000);
  assert.ok(rejected.error || rejected.result?.isError===true,
    "REA MCP unexpectedly accepted an absent PE fixture");
  await writeFile(join(workspace,"rejected-missing-target.json"),
    JSON.stringify(rejected,null,2)+"\n",{flag:"wx"});
  const open = await request("tools/call",
    {name:"open_binary",arguments:{path:target,provider_id:"ghidra"}},125000);
  assert.ok(open.result, "MCP open_binary RPC error: "+JSON.stringify(open.error));
  assert.notEqual(open.result.isError,true,"MCP open_binary refused: "+JSON.stringify(open.result).slice(0,1800));
  await writeFile(join(workspace,"open-result.json"),JSON.stringify(open.result,null,2)+"\n",{flag:"wx"});
  const result=await request("tools/call",{name:selected.name,arguments:{}},125000);
  assert.ok(result.result,"MCP tool returned RPC error: "+JSON.stringify(result.error));
  assert.notEqual(result.result.isError,true,"MCP binary_overview error: "+JSON.stringify(result.result).slice(0,1900));
  const content=JSON.stringify(result.result);
  assert.ok(/ghidra/i.test(content),"Ghidra provenance absent in MCP tool output");
  assert.ok(content.includes("rea_lab_arithmetic.dll") || content.includes(expectedTarget),
    "Owned sample provenance absent in MCP output");
  await writeFile(join(workspace,"tool-result.json"),JSON.stringify(result.result,null,2)+"\n",{flag:"wx"});
  const searchTool=tools.find(t=>t.name==="search_procedures");
  assert.ok(searchTool?.inputSchema?.properties?.pattern,"Missing search_procedures pattern schema");
  const search=await request("tools/call",
    {name:"search_procedures",arguments:{pattern:"rea_lab_"}},120000);
  assert.ok(search.result && !search.result.isError,
    "MCP search_procedures failed: "+JSON.stringify(search.error??search.result).slice(0,1300));
  const searchText=JSON.stringify(search.result);
  assert.ok(searchText.includes("rea_lab_add") && searchText.includes("rea_lab_mix"),
    "MCP symbol search did not find the two source-owned exports");
  await writeFile(join(workspace,"search-result.json"),JSON.stringify(search.result,null,2)+"\n",{flag:"wx"});
  const pseudoTool=tools.find(t=>t.name==="procedure_pseudo_code");
  assert.ok(pseudoTool?.inputSchema?.properties?.procedure,"Missing procedure_pseudo_code schema");
  // Missing procedure must return a tool error without corrupting the
  // selected document. The subsequent valid decompile is the recovery check.
  const missingProcedure="rea_lab_this_function_does_not_exist";
  const rejectedProcedure=await request("tools/call",
    {name:"procedure_pseudo_code",arguments:{procedure:missingProcedure}},120000);
  assert.ok(rejectedProcedure.error || rejectedProcedure.result?.isError===true,
    "Missing procedure unexpectedly produced a successful pseudocode result.");
  await writeFile(join(workspace,"rejected-missing-procedure.json"),
    JSON.stringify(rejectedProcedure,null,2)+"\n",{flag:"wx"});
  const pseudo=await request("tools/call",
    {name:"procedure_pseudo_code",arguments:{procedure:"rea_lab_add"}},120000);
  assert.ok(pseudo.result && !pseudo.result.isError,
    "MCP procedure_pseudo_code failed: "+JSON.stringify(pseudo.error??pseudo.result).slice(0,1400));
  const pseudoText=JSON.stringify(pseudo.result);
  assert.ok(pseudoText.includes("rea_lab_add") && /return[^;]*\+[^;]*7/u.test(pseudoText),
    "MCP Ghidra pseudocode did not reconstruct the source-owned +7 function");
  await writeFile(join(workspace,"pseudocode-result.json"),JSON.stringify(pseudo.result,null,2)+"\n",{flag:"wx"});
  // Use REA's own lifecycle operation to release the Ghidra provider,
  // rather than relying exclusively on stdin EOF/process termination.
  const closeTool=tools.find(t=>t.name==="close_binary");
  assert.ok(closeTool,"REA MCP close_binary tool missing");
  const closed=await request("tools/call",
    {name:"close_binary",arguments:{}},30000);
  assert.ok(closed.result && !closed.result.isError,
    "MCP close_binary failed: "+JSON.stringify(closed.error??closed.result).slice(0,1300));
  await writeFile(join(workspace,"closed-binary.json"),
    JSON.stringify(closed.result,null,2)+"\n",{flag:"wx"});
  const session=await request("tools/call",
    {name:"binary_session",arguments:{}},20000);
  assert.ok(session.result && !session.result.isError,
    "MCP binary_session after close failed: "+JSON.stringify(session.error??session.result).slice(0,1300));
  const closedState=session.result.structuredContent?.result;
  assert.equal(closedState?.open,false,"The MCP binary remains open after close_binary.");
  assert.equal(closedState?.cleanup_pending,false,
    "The MCP binary session still has pending cleanup.");
  await writeFile(join(workspace,"post-close-session.json"),
    JSON.stringify(session.result,null,2)+"\n",{flag:"wx"});
  const summary={passed:true, protocolVersion:init.result.protocolVersion, toolCount:tools.length,
    toolsPassed:["open_binary","binary_overview","search_procedures","procedure_pseudo_code"],
    targetSha256:expectedTarget, addonSha256:expectedNative,
    overviewBytes:Buffer.byteLength(content), overviewSha256:createHash("sha256").update(content).digest("hex"),
    missingTargetRejected:true, missingProcedureRejected:true,
    recoveredAfterMissingProcedure:true, closeBinaryPassed:true,
    postCloseSessionQueryPassed:true, searchFoundBothFunctions:true, pseudocodeAdd7:true,
    outputDir:workspace, session2Touched:false, productionMcpConfigured:false};
  await writeFile(join(workspace,"summary.json"),JSON.stringify(summary,null,2)+"\n",{flag:"wx"});
  successful=true;
  console.log(JSON.stringify(summary));
} finally {
  try {child.stdin.end();} catch {}
  await new Promise(resolve => {
    if(child.exitCode!==null) return resolve();
    const timer=setTimeout(()=>{try{const x=spawnSync("taskkill.exe",["/PID",String(child.pid),"/T","/F"],{windowsHide:true,timeout:7000});}catch{}resolve();},4000);
    child.once("exit",()=>{clearTimeout(timer);resolve();});
  });
  await writeFile(join(workspace,"stderr.txt"),stderr,{flag:"wx"});
  if(!successful)console.error("MCP_FAILED_METADATA="+JSON.stringify({workspace,diagnostics,stderrTail:stderr.slice(-1200)}));
}