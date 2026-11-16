// OpenCode plugin shim for veil.
//
// OpenCode plugins are in-process JS/TS modules. Each exported function
// is called once per plugin load with `{directory, ...}` and must return
// an object of hooks (see @opencode-ai/plugin's `Plugin` type). This file
// spawns the veil binary with the "opencode" host argument, feeds it a
// small JSON description of the event on stdin, and applies veil's
// verdict to whichever hook fired.
//
// Wire contract with the veil binary: every event sends `{event,
// sessionID, tool?, args?, fields?}` on stdin and reads back exactly one
// line of JSON on stdout: `{action: "allow"|"deny"|"rewrite", reason?,
// args?}`. `args` on the way back is a generic key/value map: for
// tool.execute.before it maps 1:1 onto the tool's own argument names; for
// every other hook it uses a key shape this file itself defined when
// building `fields` on the way in (see each hook below), and this file is
// the only thing that needs to understand that shape.
//
// FAIL-CLOSED CONTRACT (do not weaken this): runVeil() below only ever
// returns a decision whose `action` is exactly "allow", "deny", or
// "rewrite", read from stdout of a binary that exited 0. Any other
// outcome -- the binary missing, a nonzero exit, a non-JSON stdout, a
// missing or unrecognized `action` field -- is a thrown error carrying a
// stable `code` and problem `type` (see failure() below), not a fallback
// "allow". A nonzero exit forwards the binary's own RFC 9457 problem
// (its stderr line) unchanged. An earlier version of this file did not
// validate `action` at all: if the veil binary crashed and produced no
// output, `JSON.parse("" || "{}")` silently returned `{}`, and the
// `decision.action === "allow"` code path below fell through by default,
// letting the call proceed unfiltered. That is exactly the failure mode
// this project exists to prevent, so runVeil() now treats anything it
// cannot positively identify as an intentional allow as a block instead.
//
// Capability note: see the project README's capability matrix. It now
// reflects data verified against a real, installed OpenCode 1.18.32 (see
// downstream harness's integration notes, T1): chat.message can block
// (throw) or rewrite (mutate a part's text) the user's prompt;
// tool.execute.after can ONLY redact by mutating output.output (and
// output.metadata.output, when present) -- throwing there does not block
// anything, since the thrown text just becomes the tool's own result and
// the conversation continues with the tool call already executed;
// experimental.chat.messages.transform and experimental.chat.system.transform
// can both block (throw) or rewrite (mutate) what is resent to the model.

import { spawnSync } from "node:child_process";

const VEIL_BINARY = process.env.VEIL_BINARY || "veil";

// A history rewrite answers with every field, JSON-escaped: Node's default
// 1 MiB maxBuffer fails a long conversation for good (ENOBUFS).
const VEIL_MAX_BUFFER = 64 * 1024 * 1024;
// veil answers in milliseconds; without a timeout a stuck veil blocks the
// host process forever. VEIL_TIMEOUT_MS overrides the default.
const VEIL_DEFAULT_TIMEOUT_MS = 30_000;

// Problem type URIs share one base with the Go binary (internal/problem):
// an RFC 4151 tag URI, followed by the code without VEIL_, lowercased, "_"
// as "-".
const TYPE_BASE = "tag:fullfran.github.io,2026:veil/problems/";

function typeOf(code) {
  return TYPE_BASE + code.replace(/^VEIL_/, "").toLowerCase().replaceAll("_", "-");
}

// failure is a thrown error with a stable `code` and problem `type` a host
// branches on (never on the message). The plugin raises VEIL_TIMEOUT,
// VEIL_OUTPUT_TOO_LARGE and VEIL_UNAVAILABLE itself; every other code is
// forwarded from the binary's problem line.
function failure(code, message, type = typeOf(code)) {
  const err = new Error(message);
  err.code = code;
  err.type = type;
  return err;
}

// binaryProblem reads the RFC 9457 problem line a failing veil binary
// writes on stderr: the last non-empty line, when it is a JSON object
// with a string `type` and `code`. Anything else is not a problem veil
// reported, and the caller fails closed with VEIL_UNAVAILABLE.
function binaryProblem(stderr) {
  const line = (stderr || "").trim().split("\n").pop();
  try {
    const parsed = JSON.parse(line);
    if (parsed && typeof parsed.type === "string" && typeof parsed.code === "string") return parsed;
  } catch {
    // not a problem line
  }
  return null;
}

function runVeil(payload) {
  const result = spawnSync(VEIL_BINARY, ["opencode"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    maxBuffer: VEIL_MAX_BUFFER,
    timeout: Number(process.env.VEIL_TIMEOUT_MS) || VEIL_DEFAULT_TIMEOUT_MS,
    killSignal: "SIGKILL",
  });

  if (result.error && result.error.code === "ENOBUFS") {
    throw failure("VEIL_OUTPUT_TOO_LARGE", `veil: answer larger than ${VEIL_MAX_BUFFER} bytes, failing closed`);
  }
  if (result.error && result.error.code === "ETIMEDOUT") {
    throw failure("VEIL_TIMEOUT", `veil: no answer from binary "${VEIL_BINARY}" in time, failing closed`);
  }
  if (result.error) {
    throw failure("VEIL_UNAVAILABLE", `veil: failed to invoke binary "${VEIL_BINARY}": ${result.error.message}`);
  }

  // Every decision exits 0; a nonzero exit (or a kill) is a failure,
  // reported by the binary as one problem line on stderr.
  if (result.status !== 0) {
    const problem = binaryProblem(result.stderr);
    if (problem) {
      throw failure(problem.code, `veil: ${problem.title || problem.code}, failing closed`, problem.type);
    }
    throw failure("VEIL_UNAVAILABLE", `veil: binary failed without a problem report (exit ${result.status}), failing closed`);
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw failure("VEIL_UNAVAILABLE", "veil: could not parse veil output as JSON, failing closed");
  }

  if (!parsed || (parsed.action !== "allow" && parsed.action !== "deny" && parsed.action !== "rewrite")) {
    throw failure("VEIL_UNAVAILABLE", "veil: malformed or unrecognized response from binary, failing closed");
  }

  return parsed;
}

// blockingNotice renders the text veil substitutes for content it must
// block but cannot abort the request over (tool.execute.after: see the
// capability note above).
function blockingNotice(reason) {
  return `[veil blocked this tool output: ${reason || "policy violation"}]`;
}

// failureNotice replaces a tool output veil could not check. Throwing in
// tool.execute.after does not block anything (see the capability note
// above), so a failure there must withhold the output instead.
function failureNotice(err) {
  return `[veil could not check this tool output and withheld it (${err.code || "VEIL_UNAVAILABLE"})]`;
}

export const veil = async ({ directory }) => ({
  // The user's typed prompt. output.parts is the array of message
  // parts OpenCode is about to send; only text parts are scanned, each
  // keyed by its own index so a rewrite can be written back to the
  // exact part it came from.
  "chat.message": async (input, output) => {
    const fields = {};
    (output.parts || []).forEach((part, index) => {
      if (part.type === "text" && typeof part.text === "string") {
        fields[String(index)] = part.text;
      }
    });
    if (Object.keys(fields).length === 0) return;

    const decision = runVeil({ event: "chat.message", sessionID: input.sessionID, fields });

    if (decision.action === "deny") {
      // Verified in T1: throwing here aborts the whole request before
      // the model is ever contacted.
      throw new Error(`veil blocked this prompt: ${decision.reason}`);
    }
    if (decision.action === "rewrite" && decision.args) {
      for (const [index, text] of Object.entries(decision.args)) {
        const part = output.parts[Number(index)];
        if (part) part.text = text;
      }
    }
    // "allow": leave output.parts unchanged.
  },

  // A tool call's arguments, before it executes. Unchanged in shape
  // from before this PR: block by throwing, rewrite by mutating
  // output.args in place.
  "tool.execute.before": async (input, output) => {
    const decision = runVeil({
      event: "tool.execute.before",
      sessionID: input.sessionID,
      tool: input.tool,
      args: output.args,
    });

    if (decision.action === "deny") {
      throw new Error(`veil blocked this call: ${decision.reason}`);
    }
    if (decision.action === "rewrite" && decision.args) {
      Object.assign(output.args, decision.args);
    }
    // "allow": let the call proceed unchanged. Note that for a
    // write/edit/patch tool, veil's own Policy.Evaluate already
    // rehydrates any pseudonym token back to its real value as part of
    // building this same decision, so the file this tool writes gets
    // real data without this file needing to know anything about
    // rehydration itself.
  },

  // A tool's output, after it already executed. Verified in T1: only
  // mutating output.output (and its output.metadata.output duplicate,
  // when present -- OpenCode's own session storage keeps both, and
  // only mutating the first one still leaves the client's real data on
  // local disk) changes what is resent to the model and what is shown
  // in the tool's own display. Throwing here does NOT block anything:
  // the thrown text just becomes the tool's own result, and the
  // conversation continues with the real tool call already executed.
  "tool.execute.after": async (input, output) => {
    if (typeof output.output !== "string") return;

    let decision;
    try {
      decision = runVeil({
        event: "tool.execute.after",
        sessionID: input.sessionID,
        tool: input.tool,
        fields: { output: output.output },
      });
    } catch (err) {
      decision = { action: "withhold", err };
    }

    let newOutput = null;
    if (decision.action === "withhold") {
      newOutput = failureNotice(decision.err);
    } else if (decision.action === "deny") {
      newOutput = blockingNotice(decision.reason);
    } else if (decision.action === "rewrite" && decision.args && typeof decision.args.output === "string") {
      newOutput = decision.args.output;
    }
    // "allow": leave output.output unchanged.

    if (newOutput !== null) {
      output.output = newOutput;
      if (output.metadata && typeof output.metadata === "object" && typeof output.metadata.output === "string") {
        output.metadata.output = newOutput;
      }
    }
  },

  // Every text and tool-result part from prior turns OpenCode is about
  // to resend to the model. Keys are built here as
  // "<messageIndex>:<partIndex>:text" (a text part),
  // "<messageIndex>:<partIndex>:tool" (a tool part's state.output), or
  // "<messageIndex>:<partIndex>:input:<argName>" (a tool part's own
  // state.input argument, e.g. a write tool's "content"). This file --
  // and only this file -- needs to understand the shape; veil's Go side
  // just treats them as opaque field keys and substitutes text.
  //
  // state.input matters here too, not just state.output: a write tool's
  // arguments are rehydrated to real values by tool.execute.before (see
  // above) so the file on disk is correct, but that same real value then
  // sits in this tool call's own recorded state.input from then on. Left
  // unscanned, a later turn would resend that real value to the model
  // straight from history, quietly undoing the rewrite that protected it
  // the first time around. Scanning it here runs it back through the
  // exact same detectors, so it comes back out as the SAME pseudonym
  // token it had before (Policy's pseudonym store is idempotent per
  // original value within a session), not a leak and not a new token.
  "experimental.chat.messages.transform": async (input, output) => {
    const fields = {};
    const messages = output.messages || [];
    let sessionID;

    messages.forEach((message, messageIndex) => {
      sessionID = sessionID || message.info?.sessionID;
      (message.parts || []).forEach((part, partIndex) => {
        if (part.type === "text" && typeof part.text === "string") {
          fields[`${messageIndex}:${partIndex}:text`] = part.text;
        } else if (part.type === "tool" && part.state) {
          if (typeof part.state.output === "string") {
            fields[`${messageIndex}:${partIndex}:tool`] = part.state.output;
          }
          for (const [argName, argValue] of Object.entries(part.state.input || {})) {
            if (typeof argValue === "string") {
              fields[`${messageIndex}:${partIndex}:input:${argName}`] = argValue;
            }
          }
        }
      });
    });
    if (Object.keys(fields).length === 0) return;

    const decision = runVeil({ event: "experimental.chat.messages.transform", sessionID, fields });

    if (decision.action === "deny") {
      // Verified in T1: throwing here aborts the whole request too.
      throw new Error(`veil blocked this conversation history: ${decision.reason}`);
    }
    if (decision.action === "rewrite" && decision.args) {
      for (const [key, value] of Object.entries(decision.args)) {
        const [messageIndex, partIndex, kind, argName] = key.split(":");
        const part = messages[Number(messageIndex)]?.parts?.[Number(partIndex)];
        if (!part) continue;
        if (kind === "text") {
          part.text = value;
        } else if (kind === "tool" && part.state) {
          part.state.output = value;
          if (part.state.metadata && typeof part.state.metadata.output === "string") {
            part.state.metadata.output = value;
          }
        } else if (kind === "input" && part.state?.input) {
          part.state.input[argName] = value;
        }
      }
    }
  },

  // The system prompt, as an array of strings.
  "experimental.chat.system.transform": async (input, output) => {
    const fields = {};
    (output.system || []).forEach((line, index) => {
      if (typeof line === "string") fields[String(index)] = line;
    });
    if (Object.keys(fields).length === 0) return;

    const decision = runVeil({
      event: "experimental.chat.system.transform",
      sessionID: input.sessionID,
      fields,
    });

    if (decision.action === "deny") {
      // Verified in T1: throwing here aborts the whole request too.
      throw new Error(`veil blocked the system prompt: ${decision.reason}`);
    }
    if (decision.action === "rewrite" && decision.args) {
      for (const [index, text] of Object.entries(decision.args)) {
        output.system[Number(index)] = text;
      }
    }
  },
});
