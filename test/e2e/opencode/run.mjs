#!/usr/bin/env node
// Acceptance test for the OpenCode anonymizer: drives a real, installed
// OpenCode CLI against a local mock OpenAI-compatible provider (never a
// real model), with veil's real plugin (adapters/opencode/veil-plugin.js)
// and real binary wired in, and proves:
//
//   1. A DNI, IBAN, email, phone number and catalog name typed directly
//      into a prompt never reach the mock provider.
//   2. The same fixture, read from a file by the agent, never reaches the
//      mock provider either (tool.execute.after / messages.transform).
//   3. A file the agent writes, even one whose content the model only
//      ever saw as pseudonym tokens, ends up holding the REAL values on
//      disk (tool.execute.before rehydration).
//   4. Forcing the anonymizer itself to fail (an invalid VEIL_CATALOG)
//      blocks the very first request instead of quietly passing the
//      prompt through unfiltered: veil's fail-closed contract.
//
// See README.md in this directory for how to run this.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, "..", "..", "..");
const PLUGIN_PATH = join(REPO_ROOT, "adapters", "opencode", "veil-plugin.js");
const CATALOG_PATH = join(__dirname, "fixtures", "catalog.json");
const FIXTURE_PATH = join(__dirname, "fixtures", "client-notes.txt");

const FIXTURE_SECRETS = {
  name: "María Pérez",
  dni: "12345678Z",
  iban: "ES9121000418450200051332",
  email: "maria.perez@tecnisan.es",
  phone: "612345678",
};

let failures = 0;
function check(condition, message) {
  if (condition) {
    console.log(`  PASS: ${message}`);
  } else {
    console.error(`  FAIL: ${message}`);
    failures++;
  }
}

function readLogLines(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function logContainsAny(lines, needles) {
  const haystack = lines.map((l) => l.body || "").join("\n");
  return needles.filter((n) => haystack.includes(n));
}

async function waitForPort(child, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error("mock server did not report a port in time")), timeoutMs);
    child.stdout.on("data", (chunk) => {
      out += chunk.toString();
      const match = out.match(/MOCK_LISTENING (\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve(Number(match[1]));
      }
    });
    child.stderr.on("data", (chunk) => process.stderr.write(`[mock stderr] ${chunk}`));
  });
}

function runOpenCode({ prompt, env, cwd }) {
  const result = spawnSync("opencode", ["run", "--model", "mock/mock-model", "--dir", cwd, prompt], {
    cwd,
    env,
    encoding: "utf8",
    timeout: 60_000,
  });
  return result;
}

async function main() {
  console.log("Building veil...");
  const veilBinary = join(mkdtempSync(join(tmpdir(), "veil-e2e-bin-")), "veil");
  const build = spawnSync("go", ["build", "-o", veilBinary, "./cmd/veil"], { cwd: REPO_ROOT, encoding: "utf8" });
  if (build.status !== 0) {
    console.error(build.stdout, build.stderr);
    throw new Error("go build failed");
  }

  const root = mkdtempSync(join(tmpdir(), "veil-e2e-"));
  const xdgConfig = join(root, "xdg-config");
  const xdgData = join(root, "xdg-data");
  const xdgCache = join(root, "xdg-cache");
  const xdgState = join(root, "xdg-state");
  const project = join(root, "project");
  mkdirSync(join(xdgConfig, "opencode"), { recursive: true });
  mkdirSync(xdgData, { recursive: true });
  mkdirSync(xdgCache, { recursive: true });
  mkdirSync(xdgState, { recursive: true });
  mkdirSync(project, { recursive: true });
  copyFileSync(FIXTURE_PATH, join(project, "client-notes.txt"));

  console.log("Starting mock provider...");
  const requestLog = join(root, "requests.log");
  const mock = spawn("node", [join(__dirname, "mock-server.js")], {
    env: { ...process.env, MOCK_PORT: "0", MOCK_REQUEST_LOG: requestLog },
  });
  const port = await waitForPort(mock);
  console.log(`Mock provider listening on 127.0.0.1:${port}`);

  writeFileSync(
    join(xdgConfig, "opencode", "opencode.json"),
    JSON.stringify(
      {
        $schema: "https://opencode.ai/config.json",
        provider: {
          mock: {
            name: "Mock",
            npm: "@ai-sdk/openai-compatible",
            options: { baseURL: `http://127.0.0.1:${port}/v1`, apiKey: "dummy-not-a-real-key" },
            models: { "mock-model": { name: "mock-model" } },
          },
        },
        plugin: [PLUGIN_PATH],
        permission: { bash: "allow", edit: "allow" },
        autoshare: false,
      },
      null,
      2
    )
  );

  const baseEnv = {
    ...process.env,
    XDG_CONFIG_HOME: xdgConfig,
    XDG_DATA_HOME: xdgData,
    XDG_CACHE_HOME: xdgCache,
    XDG_STATE_HOME: xdgState,
    VEIL_BINARY: veilBinary,
    VEIL_CATALOG: CATALOG_PATH,
  };

  try {
    // --- Scenario 1: PII typed directly into the prompt -------------
    console.log("\nScenario 1: PII typed directly into the prompt");
    writeFileSync(requestLog, "");
    const promptText = `[SCENARIO_PROMPT] client is ${FIXTURE_SECRETS.name}, DNI ${FIXTURE_SECRETS.dni}, IBAN ${FIXTURE_SECRETS.iban}, email ${FIXTURE_SECRETS.email}, phone ${FIXTURE_SECRETS.phone}`;
    const r1 = runOpenCode({ prompt: promptText, env: baseEnv, cwd: project });
    check(r1.status === 0, `opencode run exits 0 (got ${r1.status}; stderr: ${r1.stderr})`);
    const leaked1 = logContainsAny(readLogLines(requestLog), Object.values(FIXTURE_SECRETS));
    check(leaked1.length === 0, `no request to the mock contains any raw fixture value (leaked: ${leaked1.join(", ") || "none"})`);

    // --- Scenario 2: PII read from a file -----------------------------
    console.log("\nScenario 2: PII read from a file by the agent");
    writeFileSync(requestLog, "");
    const r2 = runOpenCode({ prompt: "[SCENARIO_READ] please read client-notes.txt", env: baseEnv, cwd: project });
    check(r2.status === 0, `opencode run exits 0 (got ${r2.status}; stderr: ${r2.stderr})`);
    const leaked2 = logContainsAny(readLogLines(requestLog), Object.values(FIXTURE_SECRETS));
    check(leaked2.length === 0, `no request to the mock contains any raw fixture value from the file (leaked: ${leaked2.join(", ") || "none"})`);

    // --- Scenario 3: rehydration on write ------------------------------
    console.log("\nScenario 3: a file written by the agent contains the real values");
    writeFileSync(requestLog, "");
    const copyPath = join(project, "client-notes-copy.txt");
    if (existsSync(copyPath)) rmSync(copyPath);
    const r3 = runOpenCode({
      prompt: "[SCENARIO_WRITE] please read client-notes.txt and copy it to client-notes-copy.txt",
      env: baseEnv,
      cwd: project,
    });
    check(r3.status === 0, `opencode run exits 0 (got ${r3.status}; stderr: ${r3.stderr})`);
    const leaked3 = logContainsAny(readLogLines(requestLog), Object.values(FIXTURE_SECRETS));
    check(leaked3.length === 0, `no request to the mock contains any raw fixture value (leaked: ${leaked3.join(", ") || "none"})`);
    check(existsSync(copyPath), "client-notes-copy.txt was written");
    if (existsSync(copyPath)) {
      const written = readFileSync(copyPath, "utf8");
      const missing = Object.entries(FIXTURE_SECRETS).filter(([, value]) => !written.includes(value));
      check(missing.length === 0, `client-notes-copy.txt contains the real values, rehydrated (missing: ${missing.map(([k]) => k).join(", ") || "none"})`);
    }

    // --- Scenario 4: forced anonymizer failure fails closed -----------
    console.log("\nScenario 4: a forced anonymizer failure blocks instead of leaking");
    writeFileSync(requestLog, "");
    const brokenEnv = { ...baseEnv, VEIL_CATALOG: join(root, "does-not-exist.json") };
    const r4 = runOpenCode({ prompt: "[SCENARIO_PROMPT] hello", env: brokenEnv, cwd: project });
    check(r4.status !== 0, `opencode run exits non-zero when the anonymizer itself cannot start (got ${r4.status})`);
    const requests4 = readLogLines(requestLog);
    check(requests4.length === 0, `the mock provider is never contacted at all (got ${requests4.length} requests)`);
  } finally {
    mock.kill();
  }

  console.log(`\n${failures === 0 ? "ALL SCENARIOS PASSED" : `${failures} CHECK(S) FAILED`}`);
  if (failures === 0) {
    rmSync(root, { recursive: true, force: true });
  } else {
    console.error(`Left the run's scratch directory for inspection: ${root}`);
  }
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
