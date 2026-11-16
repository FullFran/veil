// Run with: node --test adapters/opencode/veil-plugin.test.mjs
// The plugin against stub binaries: a veil that never answers must fail
// closed within VEIL_TIMEOUT_MS instead of blocking the host forever, and a
// long history answer (well over Node's default 1 MiB maxBuffer) must pass.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
    (err) => err.code === "VEIL_TIMEOUT",
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
