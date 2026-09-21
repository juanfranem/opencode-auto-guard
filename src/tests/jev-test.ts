// tests/jev-test.ts
// Coverage for the fast structured judge (Jev) integration.
//
// What we verify here:
//   1. judgeWithFastModel sends the expected schema to /v1/systemone.
//   2. Auth header is set from the resolved key.
//   3. Schema-mapped responses: deny/ask/unsure → expected verdict shape.
//   4. Confidence thresholds: low confidence falls back (null), high
//      confidence yields a verdict.
//   5. Errors: network failure, non-2xx, malformed JSON, missing
//      `answers`, missing verdict, missing key all return null.
//   6. Timeout via AbortController triggers when the upstream hangs.
//
// Run with: bun src/tests/jev-test.ts
//
// This file does NOT exercise the full permission hook end-to-end
// (that's covered by evasion-test.ts); it focuses on the function in
// isolation so we can iterate on the schema mapping without spinning
// up the whole plugin.

import { judgeWithFastModel, type FastJudgeVerdict } from "../judge-fast";

let pass = 0;
let fail = 0;

function ok(name: string, cond: boolean, detail = ""): void {
  if (cond) {
    pass++;
    console.log(`  \u2713 ${name}`);
  } else {
    fail++;
    console.log(`  \u2717 ${name} ${detail}`);
  }
}

function section(title: string): void {
  console.log(`\n\u2500\u2500 ${title} \u2500\u2500`);
}

type FetchCall = {
  url: string;
  init: RequestInit;
  body: any;
};

let nextResponse = "";
let nextStatus = 200;
let nextDelayMs = 0;
let calls: FetchCall[] = [];

function mockFetch(): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const bodyText = init?.body ? String(init.body) : "";
    let parsed: any = null;
    try {
      parsed = JSON.parse(bodyText);
    } catch {}
    calls.push({ url, init: init ?? {}, body: parsed });

    if (nextDelayMs > 0) {
      // Honor the AbortSignal so timeout tests can actually abort the
      // mock. Without this, our fake fetch ignores ctrl.abort() and the
      // timeout assertion never trips.
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(resolve, nextDelayMs);
        if (init?.signal) {
          if (init.signal.aborted) {
            clearTimeout(t);
            reject(new DOMException("aborted", "AbortError"));
            return;
          }
          init.signal.addEventListener("abort", () => {
            clearTimeout(t);
            reject(new DOMException("aborted", "AbortError"));
          });
        }
      });
    }

    return new Response(nextResponse || "{}", {
      status: nextStatus,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}

// =================== 1. Request shape ===================

section("Request shape — endpoint, schema, auth header");

{
  calls = [];
  nextResponse = JSON.stringify({
    answers: [{ id: "verdict", type: "choice", value: "ask", confidence: 0.9 }],
  });
  globalThis.fetch = mockFetch();

  const v = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "test-key-abc",
    5000,
    "auto",
    ["git status", "npm install foo"],
  );

  ok("returns a verdict", v !== null);
  ok("verdict is ask", v?.decision === "ask");
  ok("verdict confidence preserved", v?.confidence === 0.9);
  ok("single call made", calls.length === 1);
  ok("endpoint is /v1/systemone", calls[0]?.url === "https://opencode.ai/zen/v1/systemone");
  ok(
    "Authorization header is set",
    (calls[0]?.init.headers as Record<string, string>)?.Authorization === "Bearer test-key-abc",
  );
  ok(
    "Content-Type is json",
    (calls[0]?.init.headers as Record<string, string>)?.["Content-Type"] === "application/json",
  );
  ok("model id in body", calls[0]?.body?.model === "opencode/jev-1.13-free");
  ok("agent in state", calls[0]?.body?.state?.agent === "auto");
  ok(
    "two questions sent",
    Array.isArray(calls[0]?.body?.questions) && calls[0].body.questions.length === 2,
  );
  ok(
    "verdict question is a choice with unsure escape hatch",
    calls[0]?.body?.questions?.[1]?.type === "choice" &&
      Array.isArray(calls[0]?.body?.questions?.[1]?.options) &&
      calls[0].body.questions[1].options.includes("unsure"),
  );
  ok("is_dangerous is a null question", calls[0]?.body?.questions?.[0]?.type === "null");
  ok(
    "resources capped at 500 chars in state",
    Array.isArray(calls[0]?.body?.state?.commands) &&
      calls[0].body.state.commands.every((c: string) => c.length <= 500),
  );
}

// =================== 2. Verdict mapping ===================

section("Verdict mapping — deny / ask / unsure");

async function runOnce(answers: unknown): Promise<FastJudgeVerdict | null> {
  calls = [];
  nextResponse = JSON.stringify({ answers });
  globalThis.fetch = mockFetch();
  return judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    5000,
    "build",
    ["x"],
  );
}

{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "deny", confidence: 0.95 }]);
  ok("deny verdict mapped", v?.decision === "deny" && v.confidence === 0.95);
}
{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "ask", confidence: 0.8 }]);
  ok("ask verdict mapped", v?.decision === "ask" && v.confidence === 0.8);
}
{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "unsure", confidence: 0.4 }]);
  ok("unsure → null (lets LLM judge take over)", v === null);
}
{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "MAYBE", confidence: 0.7 }]);
  ok("unknown verdict value → null", v === null);
}

// =================== 3. Confidence clamping ===================

section("Confidence clamping + missing confidence");

{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "deny", confidence: 1.5 }]);
  ok("confidence >1 → clamped to 1", v?.confidence === 1);
}
{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "deny", confidence: -0.2 }]);
  ok("confidence <0 → clamped to 0", v?.confidence === 0);
}
{
  const v = await runOnce([{ id: "verdict", type: "choice", value: "deny" }]);
  ok(
    "missing confidence → 0 (still a verdict, but caller thresholds will reject)",
    v?.confidence === 0,
  );
}

// =================== 4. Missing key ===================

section("No key → skip (returns null)");

{
  globalThis.fetch = mockFetch();
  calls = [];
  const v = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    undefined,
    5000,
    "auto",
    ["git status"],
  );
  ok("returns null when no api key", v === null);
  ok("did not call fetch without a key", calls.length === 0);
}

// =================== 5. Error paths ===================

section("Error paths — non-2xx, malformed JSON, missing fields");

async function runWithStatus(status: number, body: string): Promise<FastJudgeVerdict | null> {
  calls = [];
  nextStatus = status;
  nextResponse = body;
  globalThis.fetch = mockFetch();
  return judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    5000,
    "auto",
    ["x"],
  );
}

{
  nextStatus = 500;
  const v = await runWithStatus(500, "{}");
  ok("HTTP 500 → null", v === null);
}
{
  nextStatus = 401;
  const v = await runWithStatus(401, "{}");
  ok("HTTP 401 → null", v === null);
}
{
  const v = await runWithStatus(200, "not json");
  ok("malformed JSON → null", v === null);
}
{
  const v = await runWithStatus(200, JSON.stringify({}));
  ok("missing `answers` → null", v === null);
}
{
  const v = await runWithStatus(200, JSON.stringify({ answers: [] }));
  ok("empty `answers` → null", v === null);
}
{
  const v = await runWithStatus(
    200,
    JSON.stringify({ answers: [{ id: "other", type: "null", value: true }] }),
  );
  ok("verdict answer missing → null", v === null);
}
{
  const v = await runWithStatus(
    200,
    JSON.stringify({ answers: [{ id: "verdict", type: "null", value: true, confidence: 0.9 }] }),
  );
  ok("verdict answer of wrong type → null", v === null);
}

// =================== 6. Timeout ===================

section("Timeout — AbortController kicks in");

{
  calls = [];
  nextDelayMs = 200; // > timeout
  nextResponse = JSON.stringify({ answers: [{ id: "verdict", value: "ask", confidence: 0.9 }] });
  globalThis.fetch = mockFetch();

  const start = Date.now();
  const v = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    50, // 50ms timeout
    "auto",
    ["x"],
  );
  const elapsed = Date.now() - start;

  ok("returns null on timeout", v === null);
  ok("aborted before upstream delay finished", elapsed < 200, `(elapsed=${elapsed}ms)`);
}

// =================== Summary ===================

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
