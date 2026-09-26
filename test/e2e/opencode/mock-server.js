// Tiny local OpenAI-compatible mock HTTP server used by the acceptance
// test (run.mjs) to drive a real, installed OpenCode instance without
// ever calling a real model provider.
//
// It records every request body it receives to REQUEST_LOG (one JSON
// line per request), which is exactly what run.mjs inspects to prove the
// mock never received any of the fixture's personal data. Its scripted
// behavior is driven entirely by markers embedded in the first user
// message, so one server instance can serve every scenario in the suite:
//
//   [SCENARIO_PROMPT] - always replies with plain text; used to prove a
//     DNI/IBAN/email/phone/name typed directly into the prompt never
//     reaches this server.
//   [SCENARIO_READ]   - requests the "read" tool once, then replies with
//     plain text; used to prove a file's content never reaches this
//     server unredacted.
//   [SCENARIO_WRITE]  - requests "read", then requests a "write" tool
//     call whose content is exactly what the read tool's result looked
//     like by the time it reached the model (i.e. already tokenized),
//     simulating a model that faithfully echoes back what it was shown;
//     used to prove rehydration puts the real value in the file OpenCode
//     actually writes, not the token.
//
// Any other request (no recognized marker) just gets a plain-text reply.
const http = require("node:http");
const fs = require("node:fs");

const PORT = process.env.MOCK_PORT || 0;
const REQUEST_LOG = process.env.MOCK_REQUEST_LOG;
if (!REQUEST_LOG) {
  console.error("MOCK_REQUEST_LOG env var is required");
  process.exit(1);
}

function log(entry) {
  fs.appendFileSync(REQUEST_LOG, JSON.stringify(entry) + "\n");
}

function lastToolMessage(messages) {
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "tool") return messages[i];
  }
  return null;
}

function toolResultCount(messages) {
  return messages.filter((m) => m.role === "tool").length;
}

function firstUserText(messages) {
  const first = messages.find((m) => m.role === "user");
  return typeof first?.content === "string" ? first.content : "";
}

function sseChunk(res, obj) {
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

function streamToolCall(res, model, callID, name, args) {
  const base = { id: "mock-1", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model };
  sseChunk(res, {
    ...base,
    choices: [
      {
        index: 0,
        delta: {
          role: "assistant",
          content: null,
          tool_calls: [{ index: 0, id: callID, type: "function", function: { name, arguments: JSON.stringify(args) } }],
        },
        finish_reason: null,
      },
    ],
  });
  sseChunk(res, { ...base, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
  res.write("data: [DONE]\n\n");
  res.end();
}

function streamText(res, model, text) {
  const base = { id: "mock-1", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model };
  sseChunk(res, { ...base, choices: [{ index: 0, delta: { role: "assistant", content: text }, finish_reason: null }] });
  sseChunk(res, { ...base, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] });
  res.write("data: [DONE]\n\n");
  res.end();
}

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (chunk) => (body += chunk));
  req.on("end", () => {
    log({ ts: new Date().toISOString(), method: req.method, url: req.url, body });

    if (!req.url.includes("/chat/completions")) {
      if (req.url.includes("/models")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ object: "list", data: [{ id: "mock-model", object: "model" }] }));
        return;
      }
      res.writeHead(404);
      res.end("not found");
      return;
    }

    let parsed = {};
    try {
      parsed = JSON.parse(body);
    } catch {
      // fall through with an empty parsed body
    }
    const messages = parsed.messages || [];
    const model = parsed.model || "mock-model";
    const marker = firstUserText(messages);

    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });

    if (marker.includes("[SCENARIO_READ]")) {
      if (toolResultCount(messages) === 0) {
        streamToolCall(res, model, "call_1", "read", { filePath: "client-notes.txt" });
      } else {
        streamText(res, model, "done reading");
      }
      return;
    }

    if (marker.includes("[SCENARIO_WRITE]")) {
      const toolResults = toolResultCount(messages);
      if (toolResults === 0) {
        streamToolCall(res, model, "call_1", "read", { filePath: "client-notes.txt" });
      } else if (toolResults === 1) {
        const readResult = lastToolMessage(messages);
        const echoedContent = typeof readResult?.content === "string" ? readResult.content : "";
        streamToolCall(res, model, "call_2", "write", { filePath: "client-notes-copy.txt", content: echoedContent });
      } else {
        streamText(res, model, "done writing");
      }
      return;
    }

    // [SCENARIO_PROMPT], the title-generation call, and anything else:
    // always a plain-text reply.
    streamText(res, model, "ok");
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`MOCK_LISTENING ${server.address().port}`);
});
