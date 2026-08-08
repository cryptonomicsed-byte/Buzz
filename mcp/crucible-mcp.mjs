#!/usr/bin/env node
// crucible-mcp — an MCP server exposing Crucible to any agent that speaks MCP.
//
// Buzz already puts Goose, Codex and Claude Code in its channels through
// `buzz-acp`, and gives them shell and file tools through `buzz-dev-mcp`. This
// server adds the one surface those agents currently lack: a way to assert
// something in a form that can be checked, to check somebody else's assertion,
// and to ask what the room is actually entitled to believe.
//
// The tool list is not written here. It is fetched from `crucible tools` at
// startup and translated, so the CLI stays the single definition of what
// Crucible can do and this file cannot drift away from it.
//
//   node mcp/crucible-mcp.mjs
//
// Zero dependencies: MCP over stdio is JSON-RPC 2.0 with newline framing, and
// a server an agent is meant to trust is better off with no supply chain than
// with a convenient one.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROTOCOL_VERSION = "2025-06-18";

// A claim's author chooses its falsifier's fuel budget, and whoever probes it
// pays. The budget is capped, but a cap is not a deadline: without one, a single
// expensive claim occupies the server for as long as it likes.
const CALL_TIMEOUT_MS = Number(process.env.CRUCIBLE_TIMEOUT_MS ?? 20_000);

// Dispatching concurrently fixed head-of-line blocking, but sequential handling
// had been an accidental rate limit — N concurrent calls became N concurrent
// processes, each free to burn its fuel budget. A small permit pool keeps the
// fix without turning a probe flood into a fork bomb on the agent's machine.
const MAX_CONCURRENT = Math.max(1, Number(process.env.CRUCIBLE_MAX_CONCURRENT ?? 4));

const permits = {
  free: MAX_CONCURRENT,
  waiting: [],
  acquire() {
    if (this.free > 0) {
      this.free -= 1;
      return Promise.resolve();
    }
    return new Promise((release) => this.waiting.push(release));
  },
  release() {
    const next = this.waiting.shift();
    if (next) next();
    else this.free += 1;
  },
};

function findBinary() {
  const explicit = process.env.CRUCIBLE_BIN;
  if (explicit) return explicit;
  for (const profile of ["release", "debug"]) {
    const candidate = join(HERE, "..", "target", profile, "crucible");
    if (existsSync(candidate)) return candidate;
  }
  return "crucible";
}

const CRUCIBLE = findBinary();

/** Run one verb. Rejects with the CLI's own JSON error, which is already structured. */
function callCrucible(verb, input, timeoutMs = CALL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const child = spawn(CRUCIBLE, [verb], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    // Do not hold the event loop open on the timer alone.
    timer.unref?.();

    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(new Error(`cannot run ${CRUCIBLE}: ${e.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (timedOut) {
        return reject(
          new Error(
            `crucible ${verb} exceeded ${timeoutMs}ms and was stopped. A falsifier ` +
              `with a large fuel budget can take this long; lower the manifest's fuel, ` +
              `or raise CRUCIBLE_TIMEOUT_MS if the wait is expected.`,
          ),
        );
      }
      if (code === 0) {
        try {
          resolve(JSON.parse(out));
        } catch {
          reject(new Error(`crucible ${verb} produced unparseable output: ${out.slice(0, 400)}`));
        }
      } else {
        // Pass the CLI's own diagnosis through rather than paraphrasing it.
        let message = err.trim() || `crucible ${verb} exited ${code}`;
        try {
          const parsed = JSON.parse(err);
          message = [parsed.error, ...(parsed.context ?? [])].filter(Boolean).join(": ");
        } catch { /* not JSON; the raw text is the best we have */ }
        reject(new Error(message));
      }
    });
    // Some verbs (`tools`) answer without reading stdin and exit before we
    // finish writing. That closes the pipe under us, and an unhandled EPIPE
    // would take the whole server down over a request that in fact succeeded.
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(input ?? {}));
  });
}

/**
 * Translate the CLI catalogue into MCP tool descriptors.
 *
 * The CLI describes its arguments loosely ("hex", "unix", "0<p<1") because its
 * audience already has the docs open. MCP's audience is a model choosing a call
 * from a schema, so the shape is widened to an open object and the CLI's own
 * type hints are carried into the description — where a model will actually
 * read them — rather than being dropped for a stricter schema that would have
 * to be maintained twice and would drift.
 */
function toMcpTools(catalogue) {
  return catalogue.verbs.map((verb) => {
    const args = verb.input ?? {};
    const argLines = Object.entries(args).map(([k, v]) => `  ${k}: ${v}`);
    const description = argLines.length
      ? `${verb.summary}\n\nArguments:\n${argLines.join("\n")}`
      : verb.summary;

    return {
      name: `crucible_${verb.name.replace(/\./g, "_")}`,
      description,
      inputSchema: {
        type: "object",
        properties: Object.fromEntries(
          Object.keys(args).map((k) => [k, { description: String(args[k]) }]),
        ),
        additionalProperties: true,
      },
      _verb: verb.name,
    };
  });
}

let TOOLS = [];

const handlers = {
  initialize: () => ({
    protocolVersion: PROTOCOL_VERSION,
    capabilities: { tools: {} },
    serverInfo: { name: "crucible", version: "0.1.0" },
    instructions:
      "Crucible answers what a Buzz room is entitled to believe. Assert with " +
      "crucible_claim_build — every claim must ship a falsifier, a wasm predicate " +
      "that would return false if the claim were wrong. Check somebody else's " +
      "claim with crucible_probe_run, which runs that falsifier in a sandbox and " +
      "returns an attestation to sign with your Buzz key. Ask what is believed " +
      "with crucible_resolve; read n_eff, not the attestation count, because ten " +
      "agreeing copies of one agent are not ten witnesses. Only `supported` is " +
      "safe to act on: `contested` means the evidence is at war and `insufficient` " +
      "means nobody has checked. Read the `warnings` field: without a configured " +
      "roster, any key that can sign counts as a witness, so N fresh keypairs " +
      "read as N independent agents.",
  }),

  "tools/list": () => ({ tools: TOOLS.map(({ _verb, ...t }) => t) }),

  "tools/call": async ({ name, arguments: args }) => {
    const tool = TOOLS.find((t) => t.name === name);
    if (!tool) {
      const known = TOOLS.map((t) => t.name).join(", ");
      throw new Error(`unknown tool \`${name}\`; available: ${known}`);
    }
    await permits.acquire();
    let result;
    try {
      result = await callCrucible(tool._verb, args ?? {});
    } finally {
      permits.release();
    }
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      structuredContent: result,
    };
  },

  "notifications/initialized": () => null,
  ping: () => ({}),
};

function send(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

async function handle(request) {
  const handler = handlers[request.method];
  // Notifications carry no id and must never be answered.
  const isNotification = request.id === undefined || request.id === null;

  if (!handler) {
    if (isNotification) return;
    return send({
      jsonrpc: "2.0",
      id: request.id,
      error: { code: -32601, message: `method not found: ${request.method}` },
    });
  }

  try {
    const result = await handler(request.params ?? {});
    if (isNotification) return;
    send({ jsonrpc: "2.0", id: request.id, result: result ?? {} });
  } catch (e) {
    if (isNotification) return;
    // Report a failed tool call as a tool result, not a protocol error: the
    // model needs to see why its call was refused so it can fix the call.
    if (request.method === "tools/call") {
      send({
        jsonrpc: "2.0",
        id: request.id,
        result: {
          isError: true,
          content: [{ type: "text", text: e.message }],
        },
      });
    } else {
      send({
        jsonrpc: "2.0",
        id: request.id,
        error: { code: -32603, message: e.message },
      });
    }
  }
}

async function main() {
  try {
    TOOLS = toMcpTools(await callCrucible("tools", {}));
  } catch (e) {
    process.stderr.write(
      `crucible-mcp: could not read the tool catalogue from ${CRUCIBLE}: ${e.message}\n` +
        `Build it with \`cargo build --release -p crucible-cli\`, or set CRUCIBLE_BIN.\n`,
    );
    process.exit(1);
  }

  const lines = createInterface({ input: process.stdin });
  const inFlight = new Set();

  for await (const line of lines) {
    const text = line.trim();
    if (!text) continue;
    let request;
    try {
      request = JSON.parse(text);
    } catch {
      send({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "parse error" },
      });
      continue;
    }
    // Do not await: JSON-RPC responses carry their own id, so they may complete
    // in any order. Awaiting here would let one slow falsifier block every other
    // request behind it — including the cheap ones an agent is waiting on.
    const pending = handle(request).finally(() => inFlight.delete(pending));
    inFlight.add(pending);
  }
  await Promise.allSettled(inFlight);
}

main();
