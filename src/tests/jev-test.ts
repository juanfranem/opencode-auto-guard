// tests/jev-test.ts
// Coverage for the fast structured judge (Jev) integration.
//
// What we verify here:
//   1. judgeWithFastModel sends the expected schema to /v1/systemone.
//   2. The body strips OpenCode's `opencode/` provider prefix so the
//      wire carries the bare model id Jev expects.
//   3. Auth header is set from the resolved key.
//   4. Schema-mapped responses: deny/ask → expected verdict shape.
//   5. Diagnostic telemetry: HTTP/parse/network failures each come
//      back as a distinct discriminated `kind` with status, body or
//      error kind captured, instead of the previous opaque null.
//   6. Timeout via AbortController becomes a `network_error` whose
//      errorKind says AbortError (so users can tell a timeout from
//      a DNS failure from a TLS handshake failure in the audit log).
//
// Run with: bun src/tests/jev-test.ts

import { judgeWithFastModel, stripOpencodePrefix, type FastJudgeResult } from "../judge-fast";

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
let nextBodyReadShouldThrow = false;
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

    const resp = new Response(nextResponse || "{}", {
      status: nextStatus,
      headers: { "Content-Type": "application/json" },
    });
    // For the parse-error-body-read test only — strip the body mid-stream
    // by stubbing the body getter.
    if (nextBodyReadShouldThrow) {
      Object.defineProperty(resp, "text", {
        value: async () => {
          throw new DOMException("network hangup", "AbortError");
        },
      });
    }
    return resp;
  }) as unknown as typeof fetch;
}

// =====================================================================
// 0. Pure helper — prefix stripping
// =====================================================================

section("Prefix stripping (`opencode/` is removed at the wire)");

ok(
  '"opencode/jev-1.13-free" → "jev-1.13-free"',
  stripOpencodePrefix("opencode/jev-1.13-free") === "jev-1.13-free",
);
ok('"jev-1.13-free" is idempotent', stripOpencodePrefix("jev-1.13-free") === "jev-1.13-free");
ok(
  '"zai-coding-plan/glm-5.3-flash" untouched',
  stripOpencodePrefix("zai-coding-plan/glm-5.3-flash") === "zai-coding-plan/glm-5.3-flash",
);
ok(
  'case-sensitive: "Opencode/..." untouched',
  stripOpencodePrefix("Opencode/jev-1.13-free") === "Opencode/jev-1.13-free",
);
ok(
  '"opencode/" alone strips to "" (empty model surfaces as a wire-level API error, not silent keep)',
  stripOpencodePrefix("opencode/") === "",
);
ok('"" → ""', stripOpencodePrefix("") === "");

// =====================================================================
// 1. Request shape
// =====================================================================

section("Request shape — endpoint, schema, auth header");

{
  calls = [];
  nextResponse = JSON.stringify({
    model: "jev-1.13-free",
    answers: {
      verdict: { type: "choice", choice: "ask", confidence: 0.9 },
    },
  });
  globalThis.fetch = mockFetch();

  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free", // user-config style, with `opencode/` prefix
    "test-key-abc",
    5000,
    "auto",
    ["git status", "npm install foo"],
  );

  ok("returns a verdict", r?.kind === "verdict");
  const v = r?.kind === "verdict" ? r : null;
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
  ok(
    "model id stripped of opencode/ prefix on the wire",
    calls[0]?.body?.model === "jev-1.13-free",
  );
  ok("agent in state", calls[0]?.body?.state?.agent === "auto");

  // questions is a map keyed by question id, not an array
  const q = calls[0]?.body?.questions;
  ok(
    "questions is an object with exactly two ids (is_dangerous, verdict)",
    !!q && !Array.isArray(q) && typeof q.is_dangerous === "object" && typeof q.verdict === "object",
  );
  ok("is_dangerous uses noul type (probability in [0,1])", q?.is_dangerous?.type === "noul");
  ok(
    "verdict uses choice type with criteria map",
    q?.verdict?.type === "choice" &&
      typeof q.verdict.criteria === "object" &&
      !Array.isArray(q.verdict.criteria),
  );
  ok(
    "verdict criteria expose unsure escape hatch",
    q?.verdict?.criteria?.unsure !== undefined &&
      q?.verdict?.criteria?.deny !== undefined &&
      q?.verdict?.criteria?.ask !== undefined,
  );
  ok(
    "resources capped at 500 chars in state",
    Array.isArray(calls[0]?.body?.state?.commands) &&
      calls[0].body.state.commands.every((c: string) => c.length <= 500),
  );
}

{
  // Idempotent: user wrote the bare id, no stripping needed.
  calls = [];
  nextResponse = JSON.stringify({
    answers: { verdict: { type: "choice", choice: "ask", confidence: 0.7 } },
  });
  globalThis.fetch = mockFetch();
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "jev-1.13-free", // already stripped
    "k",
    5000,
    "auto",
    ["x"],
  );
  ok(
    "body.model is bare when input has no opencode/ prefix",
    calls[0]?.body?.model === "jev-1.13-free" && r?.kind === "verdict",
  );
}

{
  // Other providers pass through untouched.
  calls = [];
  nextResponse = JSON.stringify({
    answers: { verdict: { type: "choice", choice: "ask", confidence: 0.7 } },
  });
  globalThis.fetch = mockFetch();
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "zai-coding-plan/glm-5.3-flash",
    "k",
    5000,
    "auto",
    ["x"],
  );
  ok(
    "body.model preserves unknown provider prefixes",
    calls[0]?.body?.model === "zai-coding-plan/glm-5.3-flash" && r?.kind === "verdict",
  );
}

// =====================================================================
// 2. Verdict mapping (happy path)
// =====================================================================

section("Verdict mapping — deny / ask / unsure");

async function runOnce(answers: unknown): Promise<FastJudgeResult | null> {
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
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", confidence: 0.95 } });
  ok(
    "deny verdict mapped",
    r?.kind === "verdict" && r.decision === "deny" && r.confidence === 0.95,
  );
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "ask", confidence: 0.8 } });
  ok("ask verdict mapped", r?.kind === "verdict" && r.decision === "ask" && r.confidence === 0.8);
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "unsure", confidence: 0.4 } });
  ok(
    "unsure → parse_error with reason=unknown_choice=unsure",
    r?.kind === "parse_error" && r.reason === "unknown_choice=unsure",
  );
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "MAYBE", confidence: 0.7 } });
  ok(
    "unknown verdict value → parse_error with reason=unknown_choice=maybe",
    r?.kind === "parse_error" && r.reason === "unknown_choice=maybe",
  );
}

// =====================================================================
// 3. Confidence clamping + field fallbacks
// =====================================================================

section("Confidence clamping + lenient probability-name fallback");

{
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", confidence: 1.5 } });
  ok("confidence >1 → clamped to 1", r?.kind === "verdict" && r.confidence === 1);
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", confidence: -0.2 } });
  ok("confidence <0 → clamped to 0", r?.kind === "verdict" && r.confidence === 0);
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "deny" } });
  ok(
    "missing confidence → 0 (still a verdict, but caller thresholds will reject)",
    r?.kind === "verdict" && r.confidence === 0,
  );
}
{
  // Some Jev-style responses use `probability` instead of `confidence`.
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", probability: 0.62 } });
  ok("`probability` field is honoured", r?.kind === "verdict" && r.confidence === 0.62);
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", prob: 0.31 } });
  ok("`prob` field is honoured", r?.kind === "verdict" && r.confidence === 0.31);
}
{
  const r = await runOnce({ verdict: { type: "choice", choice: "deny", probability: 7 } });
  ok(
    "`probability` >1 clamps to 1 (no silent renormalization)",
    r?.kind === "verdict" && r.confidence === 1,
  );
}

// =====================================================================
// 4. is_dangerous (noul) does not poison the verdict
// =====================================================================

section("is_dangerous answer (noul) is ignored — only verdict gates the decision");

{
  const r = await runOnce({
    is_dangerous: { type: "noul", noul: 0.96 },
    verdict: { type: "choice", choice: "ask", confidence: 0.55 },
  });
  ok(
    "verdict still resolves to ask even when is_dangerous.noul is high",
    r?.kind === "verdict" && r.decision === "ask" && r.confidence === 0.55,
  );
}
{
  const r = await runOnce({ is_dangerous: { type: "noul", noul: 0.0 } });
  ok(
    "missing verdict → parse_error (is_dangerous alone can't decide)",
    r?.kind === "parse_error" && r.reason === "missing_verdict",
  );
}

// =====================================================================
// 5. Missing key — the one path that still returns null
// =====================================================================

section("No key → skip (returns null)");

{
  globalThis.fetch = mockFetch();
  calls = [];
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    undefined,
    5000,
    "auto",
    ["git status"],
  );
  ok("returns null when no api key", r === null);
  ok("did not call fetch without a key", calls.length === 0);
}

// =====================================================================
// 6. Error paths — discriminated kinds, with diagnostic payloads
// =====================================================================

section("Error paths — http_error captures status + body, parse_error captures reason + body");

async function runWithStatus(status: number, body: string): Promise<FastJudgeResult | null> {
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
  const r = await runWithStatus(500, '{"error":"upstream blew up"}');
  ok("HTTP 500 → http_error", r?.kind === "http_error" && r.status === 500);
  ok(
    "HTTP 500 body is captured and truncated",
    r?.kind === "http_error" && r.body.includes("upstream blew up"),
  );
}
{
  nextStatus = 401;
  const r = await runWithStatus(401, "unauthorized");
  ok("HTTP 401 → http_error", r?.kind === "http_error" && r.status === 401);
}
{
  const r = await runWithStatus(200, "not json");
  ok(
    "malformed JSON → parse_error with reason=json_parse",
    r?.kind === "parse_error" && r.reason === "json_parse",
  );
  ok(
    "malformed JSON body is captured (so users can eyeball upstream gibberish)",
    r?.kind === "parse_error" && r.body.includes("not json"),
  );
}
{
  const r = await runWithStatus(200, JSON.stringify({}));
  ok(
    "missing `answers` → parse_error with reason=missing_answers",
    r?.kind === "parse_error" && r.reason === "missing_answers",
  );
}
{
  const r = await runWithStatus(200, JSON.stringify({ answers: {} }));
  ok(
    "empty `answers` map → parse_error with reason=missing_verdict",
    r?.kind === "parse_error" && r.reason === "missing_verdict",
  );
}
{
  const r = await runWithStatus(
    200,
    JSON.stringify({ answers: { is_dangerous: { type: "noul", noul: 0.5 } } }),
  );
  ok(
    "verdict answer missing → parse_error with reason=missing_verdict",
    r?.kind === "parse_error" && r.reason === "missing_verdict",
  );
}
{
  // An unusual choice type (not "choice", not "noul") — verify the parser
  // distinguishes the two shape failure modes (type mismatch vs missing).
  const r = await runWithStatus(
    200,
    JSON.stringify({ answers: { verdict: { type: "noul", noul: 0.9 } } }),
  );
  ok(
    "verdict answer of wrong type → parse_error with reason=wrong_verdict_type=noul",
    r?.kind === "parse_error" && r.reason === "wrong_verdict_type=noul",
  );
}
{
  // Body-read failure (e.g. connection reset mid-stream on the response):
  // we still classify as http_error so the upstream network glitch is
  // visible, but the body is captured as empty rather than lost.
  nextStatus = 503;
  nextResponse = "ignored";
  nextBodyReadShouldThrow = true;
  calls = [];
  globalThis.fetch = mockFetch();
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    5000,
    "auto",
    ["x"],
  );
  nextBodyReadShouldThrow = false;
  ok(
    "HTTP 5xx with body-read failure → http_error (status still captured)",
    r?.kind === "http_error" && r.status === 503,
  );
  ok(
    "HTTP 5xx with body-read failure → body is empty but not lost",
    r?.kind === "http_error" && r.body === "",
  );
}

// =====================================================================
// 7. Body truncation at the audit boundary
// =====================================================================

section("Body truncation — large bodies get capped at 150 chars + ellipsis");

{
  const huge = "X".repeat(1000);
  nextStatus = 500;
  calls = [];
  globalThis.fetch = mockFetch();
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    5000,
    "auto",
    ["x"],
  );
  // Run a separate test for body content
  nextResponse = huge;
  const r2 = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    5000,
    "auto",
    ["x"],
  );
  ok(
    "1KB HTTP error body is truncated to 150 chars + trailing ellipsis",
    r2?.kind === "http_error" && r2.body.length === 151 && r2.body.endsWith("…"),
  );
  void r;
}

// =====================================================================
// 8. Network errors — discriminated with AbortError vs ECONNRESET etc.
// =====================================================================

section("Network errors — fetch rejection becomes network_error with kind+message");

{
  // Timeout: the mock honors the AbortSignal and rejects with
  // DOMException("aborted", "AbortError").
  calls = [];
  nextDelayMs = 200;
  nextResponse = JSON.stringify({
    answers: { verdict: { type: "choice", choice: "ask", confidence: 0.9 } },
  });
  globalThis.fetch = mockFetch();

  const start = Date.now();
  const r = await judgeWithFastModel(
    "https://opencode.ai/zen/v1/systemone",
    "opencode/jev-1.13-free",
    "k",
    50,
    "auto",
    ["x"],
  );
  const elapsed = Date.now() - start;

  ok(
    "timeout → network_error with AbortError kind",
    r?.kind === "network_error" && r.errorKind.startsWith("AbortError"),
  );
  ok("timeout doesn't hang past the limit", elapsed < 200, `(elapsed=${elapsed}ms)`);
}

// =====================================================================
// Summary
// =====================================================================

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
