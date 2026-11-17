// Run with: node --test adapters/opencode/veil-plugin.test.mjs
// The plugin against stub binaries: a veil that never answers must fail
// closed within VEIL_TIMEOUT_MS instead of blocking the host forever, and a
// long history answer (well over Node's default 1 MiB maxBuffer) must pass.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Mirrors internal/problem.TypeBase in the Go binary.
const TYPE_BASE = "tag:fullfran.github.io,2026:veil/problems/";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "veil-plugin-test-"));
process.on("exit", () => fs.rmSync(dir, { recursive: true, force: true }));

function stub(name, body) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, `#!/usr/bin/env node\n${body}\n`, { mode: 0o755 });
  return file;
}

let loads = 0;
async function pluginWith(binary, env = {}) {
  process.env.VEIL_BINARY = binary;
  Object.assign(process.env, env);
  const mod = await import(`./veil-plugin.js?load=${loads++}`);
  return mod.veil({ directory: dir });
}

test("a veil that never answers fails closed with VEIL_TIMEOUT", async () => {
  const hooks = await pluginWith(stub("hang.mjs", "setInterval(() => {}, 1000);"), { VEIL_TIMEOUT_MS: "300" });
  const started = Date.now();
  await assert.rejects(
    hooks["chat.message"]({ sessionID: "s" }, { parts: [{ type: "text", text: "hola" }] }),
    (err) => err.code === "VEIL_TIMEOUT" && err.type === `${TYPE_BASE}timeout`,
  );
  assert.ok(Date.now() - started < 5000, "the timeout must bound the call");
});

test("an answer over 1 MiB is read whole", async () => {
  const big = "x".repeat(3 * 1024 * 1024);
  const hooks = await pluginWith(
    stub("big.mjs", `process.stdin.resume(); process.stdin.on("end", () => process.stdout.write(JSON.stringify({ action: "rewrite", args: { "0": ${JSON.stringify("[DNI-001] ")} + "x".repeat(${big.length}) } })));`),
  );
  const output = { parts: [{ type: "text", text: "12345678Z" }] };
  await hooks["chat.message"]({ sessionID: "s" }, output);
  assert.equal(output.parts[0].text.length, "[DNI-001] ".length + big.length);
});

// A binary that fails writes one RFC 9457 problem line on stderr and exits
// nonzero; the plugin forwards its type and code instead of wrapping them.
function failingBinary(name, stderr, status = 1) {
  return stub(
    name,
    `process.stdin.resume(); process.stdin.on("end", () => { process.stderr.write(${JSON.stringify(stderr)}); process.exit(${status}); });`,
  );
}

const storeCorrupt = JSON.stringify({
  type: `${TYPE_BASE}store-corrupt`,
  title: "Pseudonym store is corrupt",
  detail: "x",
  code: "VEIL_STORE_CORRUPT",
}) + "\n";

test("a binary failure is forwarded with its problem type and code", async () => {
  const hooks = await pluginWith(failingBinary("corrupt.mjs", storeCorrupt));
  await assert.rejects(
    hooks["tool.execute.before"]({ sessionID: "s", tool: "bash" }, { args: { command: "echo hi" } }),
    (err) => err.code === "VEIL_STORE_CORRUPT" && err.type === `${TYPE_BASE}store-corrupt`,
  );
});

test("a nonzero exit without a problem line fails closed with VEIL_UNAVAILABLE", async () => {
  const hooks = await pluginWith(failingBinary("garbage.mjs", "panic: something\n", 2));
  await assert.rejects(
    hooks["chat.message"]({ sessionID: "s" }, { parts: [{ type: "text", text: "hola" }] }),
    (err) => err.code === "VEIL_UNAVAILABLE" && err.type === `${TYPE_BASE}unavailable`,
  );
});

test("an unparsable answer fails closed with VEIL_UNAVAILABLE", async () => {
  const hooks = await pluginWith(stub("notjson.mjs", `process.stdin.resume(); process.stdin.on("end", () => process.stdout.write("not json"));`));
  await assert.rejects(
    hooks["chat.message"]({ sessionID: "s" }, { parts: [{ type: "text", text: "hola" }] }),
    (err) => err.code === "VEIL_UNAVAILABLE" && err.type === `${TYPE_BASE}unavailable`,
  );
});

test("a failure on tool output withholds the output instead of leaking it", async () => {
  const hooks = await pluginWith(failingBinary("corrupt-after.mjs", storeCorrupt));
  const output = { output: "DNI 12345678Z", metadata: { output: "DNI 12345678Z" } };
  await hooks["tool.execute.after"]({ sessionID: "s", tool: "bash" }, output);
  assert.ok(!output.output.includes("12345678Z"), "the unchecked output must not stay in place");
  assert.ok(!output.metadata.output.includes("12345678Z"), "the stored duplicate must not keep it either");
  assert.ok(output.output.includes("VEIL_STORE_CORRUPT"), "the notice names the problem code");
});

test("a rewrite of tool output also replaces the copy OpenCode stores in metadata", async () => {
  const hooks = await pluginWith(
    stub("rewrite-after.mjs", `process.stdin.resume(); process.stdin.on("end", () => process.stdout.write(JSON.stringify({ action: "rewrite", args: { output: "DNI [DNI-001]" } })));`),
  );
  const output = { output: "DNI 12345678Z", metadata: { output: "DNI 12345678Z" } };
  await hooks["tool.execute.after"]({ sessionID: "s", tool: "bash" }, output);
  assert.equal(output.output, "DNI [DNI-001]");
  assert.equal(output.metadata.output, "DNI [DNI-001]", "the stored duplicate must not keep the real value");
});
