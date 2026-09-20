// OpenCode plugin shim for veil.
//
// OpenCode plugins are in-process JS/TS modules; this file implements
// tool.execute.before, spawns the veil binary with the "opencode" host
// argument, feeds it a small JSON description of the tool call on stdin,
// and either lets the call proceed, blocks it by throwing, or mutates
// output.args to rewrite it, based on veil's JSON response.
//
// Capability note: veil has no hook into the user's typed prompt on
// OpenCode. There is no documented tool.execute.before equivalent for
// prompt text, so prompt-level enforcement is unavailable on this host.
// See the repository README's capability matrix and "What this cannot
// do" section.
//
// This shim is a reference implementation of the JSON contract veil
// expects on OpenCode (internal/hosts/opencode in the Go module). The
// exact plugin loader function signature and export shape may need to be
// adjusted to match the OpenCode version installed; check the OpenCode
// plugin documentation for the current tool.execute.before signature.

const { spawnSync } = require("node:child_process");

const VEIL_BINARY = process.env.VEIL_BINARY || "veil";

function runVeil(payload) {
  const result = spawnSync(VEIL_BINARY, ["opencode"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
  });

  if (result.error) {
    throw new Error(`veil: failed to invoke binary "${VEIL_BINARY}": ${result.error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout || "{}");
  } catch (err) {
    throw new Error(`veil: could not parse veil output as JSON: ${result.stdout}`);
  }

  return parsed;
}

module.exports = {
  veil: {
    "tool.execute.before": async (input, output) => {
      const decision = runVeil({
        event: "tool.execute.before",
        tool: input.tool,
        args: output.args,
      });

      if (decision.action === "deny") {
        throw new Error(`veil blocked this call: ${decision.reason}`);
      }

      if (decision.action === "rewrite" && decision.args) {
        Object.assign(output.args, decision.args);
      }

      // decision.action === "allow": let the call proceed unchanged.
    },
  },
};
