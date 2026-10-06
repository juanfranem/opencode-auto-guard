# Security Model

## What opencode-auto-guard does

The plugin sits between OpenCode and the underlying tool calls. Every time
the agent wants to run a shell command, read or edit a file, or fetch a URL,
the plugin evaluates the action against a deterministic classifier and,
optionally, an LLM judge.

The classification result is one of three effects:

- **allow** — proceed without asking the user
- **ask** — prompt the user for confirmation
- **deny** — block outright

The plugin can change a `deny` to nothing (because an explicit `deny` is
final and the hook does not even fire). It can change `ask` to `allow` or
`deny`. It can change `allow` to `ask` or `deny`. This last case is what
defends against malicious tool calls that exploit over-permissive config.

## Defense layers

```
+-------------------------------------------+
| OpenCode permission engine                |
| (deny rules are final, hooks don't fire)  |
+-------------------------------------------+
                  |
                  v
+-------------------------------------------+
| opencode-auto-guard: permission.ask hook  |
|                                           |
| 1. Session limits                         |
|    - maxDenials / maxActions / maxDuration|
|    - Only risky actions are counted        |
|                                           |
| 2. Self-protection                        |
|    - read/edit on plugin files -> deny    |
|                                           |
| 3. Webfetch / Websearch                   |
|    - trusted domain check                 |
|                                           |
| 4. Shell classification                   |
|    a. Hard deny patterns                  |
|    b. Hard ask patterns                   |
|    c. Fast classifier (no LLM)            |
|    d. Network egress extraction           |
|       (curl, wget, ssh, nc, ...)          |
|    e. Fast structured judge (Jev)         |
|       - runs only when no LLM judge slot  |
|         would otherwise burn on the case  |
|       - 5 s timeout, free on OpenCode Zen |
|       - falls through to LLM judge on     |
|         error, unsure, or low confidence  |
|       - never elevates ask → allow        |
|    f. LLM judge for ambiguous cases       |
|       - rate-limited per session (20)     |
|       - skipped if fast judge decided     |
|    g. Per-agent escalation (build)        |
|    h. Per-agent tightening (no auto-allow)|
+-------------------------------------------+
                  |
                  v
+-------------------------------------------+
| opencode-auto-guard: tool.execute.before  |
|                                           |
| - TOCTOU re-check via fs.realpath         |
| - apply_patch protected-path scanning     |
+-------------------------------------------+
                  |
                  v
+-------------------------------------------+
| opencode-auto-guard: tool.execute.after   |
|                                           |
| - Wrap webfetch output from non-trusted   |
|   URLs in <untrusted-source> tags to      |
|   defend against prompt injection         |
+-------------------------------------------+
```

## What is covered

- **Command-line obfuscation**: `pwsh -EncodedCommand`, `base64 -d | bash`,
  `FromBase64String`, `printf \\x...`, `$()` with base64 content, and any
  base64-looking string >100 chars (which catches `-EncodedCommand`
  payloads after the flag is stripped).
- **Pipe-to-shell**: `curl ... | bash`, `wget ... | sh`, `iwr ... | iex`,
  `fetch ... | bash`, `node -e` with URL.
- **Destructive shell**: `rm -rf /`, `rm -rf ~`, `Remove-Item -Recurse -Force`,
  `find -exec`, `xargs rm`, `tar --checkpoint-action=exec`.
- **Dangerous builtins**: `reg delete`, `Format-Volume`, `mkfs`, `dd if=...`,
  `:(){:|:&};:`, `cacls`, `takeown`.
- **Privileged operations**: `sudo`, `set-executionpolicy bypass`,
  `--privileged` Docker, `--network host`, volume mounts of `C:` or `/`.
- **Network egress in shell**: any shell command using `curl`, `wget`, `ssh`,
  `scp`, `rsync`, `nc`, `ncat`, `nslookup`, `dig`, `ping`, `tracert`,
  `httpx`, `httpie` has its hosts (URLs and `user@host` patterns, including
  jump hosts in `-J`) extracted and validated against `trustedDomains`.
  Non-trusted hosts force `ask`.
- **Path tampering**: the plugin's own files (config, source code, audit
  logs) cannot be read or modified by the agent session.
- **Symlink swap (TOCTOU)**: the `tool.execute.before` hook re-checks the
  target via `realpath` immediately before the tool executes.
- **Prompt injection in URLs**: `webfetch` to non-trusted domains requires
  user confirmation. The agent sees the URL but cannot bypass the check by
  reformulating it.
- **Prompt injection via webfetch content**: the `tool.execute.after` hook
  wraps the output of non-trusted `webfetch` calls in
  `<untrusted-source url="...">...</untrusted-source>` markers, signalling
  to the agent that the content is data, not instructions.
- **Repeated bypass attempts**: three consecutive denials pause the session.
  250 counted actions or 30 minutes — same. The agent cannot grind through
  the guard. Counting is scoped to risky actions only (`bash`, `edit`,
  `write`, `apply_patch`, `webfetch`, `websearch`, `subagent`) so that
  benign read-only actions do not exhaust the budget.
- **Cost attacks via LLM judge**: the LLM judge is rate-limited to 20 calls
  per session. Beyond that, ambiguous cases fall back to `ask` directly
  without consuming the judge budget.
- **Free fast judge as a second opinion**: when `fastJudgeModel` is set, a
  structured-decision model (e.g. Jev on OpenCode Zen) runs **before** the
  LLM judge for ambiguous shell commands. High-confidence verdicts short-
  circuit and skip the LLM judge entirely, conserving the rate-limited LLM
  budget. Low confidence or `unsure` outcomes fall through to the existing
  LLM judge — never replace it. The fast judge itself can only **deny** or
  keep **ask**; it never elevates `ask → allow`. See `README.md` for the
  exact stacking and the trust caveats from the published Jev test report.
- **Audit log unbounded growth**: the hash-chained audit auto-rotates at
  10,000 entries. Older entries are archived under
  `guard:audit-archive-${date}-${n}` keys with a pointer record so the
  chain can be reconstructed across rotations.

## Generic, declarative download adapters

Each entry of the `downloads` map enables one opt-in tool named
`auto_guard_download_<id>`, with permission `<id>_download`. Permissions do
NOT introduce an exception to `HARD_DENY`, do NOT expand `trustedDomains`,
and are always escalated to `ask` (an existing `deny` is preserved). They
bypass neither session limits nor the confirmation boundary. Each call is
audited under `<id>_download_permission` and `<id>_download_result`
without recording UUIDs, slug keys, source URLs, or raw destination input.

With only `enabled`, `host` and `root`, an adapter uses **host mode**:
input is exactly `{ url, filename }`. Every GET path/query on that exact
HTTPS host is authorized for download, subject to confirmation and shared
protections. Other hosts, subdomains, non-default ports, credentials,
fragments, raw whitespace/control characters and backslashes are rejected.
URL building revalidates the host restriction. Filenames are safe lowercase
basenames (max 128 characters); path traversal, trailing dots, alternate
streams and Windows device names are rejected. Arbitrary extensions are
allowed. Host mode does not expand shell or general web-fetch allowlists.

Host mode defaults to **no content-type check and no content validation**.
This is broader trust than template mode: malicious or executable content
may be downloaded from an approved host. Approval is not content trust and
does not authorize execution. Explicit `expectedContentType` and/or
`contentValidator` constraints are still honored. Partial template configs
with `fields` but no `pathTemplate` fail compilation, not silently broaden.

Supplying `pathTemplate` selects **template mode**. Inputs are restricted to a strict
key/value shape per field (`"uuid" | "num" | "slug" | "hex32" | "hex64"
| { "enum": [...] }`); the regexes never match `/`, `?`, `#`, `\`,
whitespace or NUL, and the LLM cannot smuggle a path fragment into a
placeholder. The path template is a literal `/path` with `{key}`
placeholders that MUST match declared field names; unknown or missing
placeholders fail compilation. The destination directory is the only
filesystem side effect, and the host is fixed in config — never
parameterized at call time.

Content shape is fixed per value of `contentValidator` to one of the
shipped palette:

- `png`: signature, IHDR (width × height ≤ 400), non-interlaced, depth
  / colour / channels table, IDAT/IEND order, chunk CRCs, scanline
  size and filter range after zlib inflation.
- `jpeg`: SOI/EOI, SOF segment width and height ≤ 400; entropy
  decoding is NOT attempted, but post-SOF scanning rejects payloads
  with no EOI.
- `webp`: RIFF/WEBP header, VP8/VP8L/VP8X dim ≤ 400; the validator
  walks chunks but does not decode entropy, so non-image data is
  rejected as "Unknown WebP chunk".
- `text/plain`: strict UTF-8 (fatal decode), no NUL bytes.
- `none`: identity; only the size cap and an optional `expectedContentType`
  constrain content (host mode omits the type check by default).

Adding a new validator is a code change shipped in the plugin; the
config cannot. The defense contract that ALL content validators
inherit:

- When `expectedContentType` is declared, its content-type header is
  required and anything else is rejected. Template mode requires this knob.
- Streamed body capped at 1 MiB regardless of headers.
- 30-second network timeout (configurable per adapter up to 60s).
- GET only, `redirect: error`, `credentials: omit`.
- Absolute, non-network, no-dot-segment destination root.
- Symlink / junction ancestor walk rejected.
- Canonical path + inode identity checked before, during, and after
  download.
- `protectedPaths` rejected at the root and the destination.
- Exclusive `O_CREAT | O_EXCL` write — never overwrites an existing
  target, including a file another concurrent call created.
- Failed writes clean up only the inode obtained by our exclusive
  open, never a prior file.

These are defense-in-depth filesystem checks, not OS sandboxing: a
privileged or hostile local process able to rename directory ancestors
between syscalls is outside the guarantee. Symlinks/junctions,
canonical path and inode identity differences are checked; the plugin
does not enumerate every Windows reparse-point tag. Use an ordinary
local directory rather than virtual/cloud-backed storage. Only the
network phase has a deadline; OS filesystem calls are not forcibly
terminated with a racing timer, which could leave writes running
after cleanup. The executor performs stricter path checks than the
generic file-tool hook, so the generic `execute.before` hook is not
used for these tools. Newer tool contexts expose a cancellation signal;
older SDKs retain the bounded timeout but cannot propagate session
cancellation to the executor. Remote data is never executed. Users
must review assets before integrating them.

## Generic `safe-download` primitive

`src/safe-download.ts` is the source-agnostic primitive (`safeDownloadFile`)
that backs every download adapter. It owns the cross-adapter defense
contract: non-network download root, no dot segments, symlink-free
ancestor walk, canonical path + inode identity check, fixed-origin GET
with `redirect: error` and `credentials: omit`, configurable network
timeout, streamed size cap (1 MiB), exact-match `expectedContentType`
content-type, exclusive `O_CREAT | O_EXCL` write, post-write identity
recheck, and cleanup that only removes the inode our own open created.
Adapters compose this primitive by supplying `validateInput`,
`buildUrl`, and a content validator (chosen from the closed palette in
`src/content-validators.ts`). The adapter layer is the only place that
sees the host and the path template; the primitive never sees them.

## What is NOT covered

- **Network-level exfiltration.** The plugin can only see what OpenCode
  asks the agent to do. If the agent runs an outbound HTTP request via a
  tool that bypasses OpenCode (e.g., a custom MCP server), the plugin
  cannot see it. Mitigate with network namespaces, egress filtering, or
  container isolation.
- **Filesystem isolation.** The plugin can deny access to specific paths,
  but cannot enforce read-only mounts. Mitigate with `bwrap`, `sandbox-exec`,
  AppContainer, or run the agent in an ephemeral container.
- **Credential scoping.** The plugin does not manage credentials. Use
  least-privilege IAM, short-lived tokens, and per-project service
  accounts.
- **The agent's reasoning.** The plugin cannot verify that the agent's
  *intent* matches the user's *intent*. It only evaluates concrete tool
  calls. A determined agent could perform a sequence of allowed actions
  that, together, achieve an undesired outcome.
- **Off-host tools.** MCP servers can hide arbitrary side effects behind
  innocuous tool names. Pin MCP server versions, hashes, and review their
  source.
- **The base64 obfuscation detection limits.** The fast classifier checks
  for raw base64 shape, not for decoded semantics. If the attack encodes a
  payload in a way that does not match `[A-Za-z0-9+/]{100,}=*` (e.g.,
  split into pieces, hex-encoded), the classifier misses it. The LLM judge
  catches most of these because it sees the actual decoded intent.
- **The LLM judge itself.** A determined attacker with prompt-injection
  skills can sometimes persuade the LLM judge to deny the wrong thing or
  to misclassify. Mitigate with the `pin` option (locks plugin code) and
  by keeping the judge model separate from the agent's main model.

## Threat model assumptions

- The OpenCode binary is trusted and uncompromised.
- The user's home directory permissions are sane (others cannot write to
  `~/.config/opencode/`).
- The LLM judge, if enabled, is reached via a TLS-protected endpoint.
- The user does not manually edit `~/.config/opencode/plugins/auto-guard.ts`
  during a session (changes only take effect on next OpenCode restart).

## Out of band: the hash chain

Every decision is written to a tamper-evident log:

```
guard:audit-0000000001 -> { ... prevHash: "sha256:0..." hash: "sha256:..." }
guard:audit-0000000002 -> { ... prevHash: "sha256:..." hash: "sha256:..." }
...
guard:audit-head       -> { n: ..., hash: "sha256:..." }
```

If anyone modifies an entry after the fact, the chain breaks. To verify
externally (e.g., from a separate process), read `guard:audit-head`, then
walk backwards computing and comparing hashes.

This is not a substitute for OS-level immutability — an attacker with
filesystem write access can rewrite both the chain and the head pointer.
But it provides forensic value if logs are exported before an attack, or
if a separate verifier (cron job, audit script) compares against an
external store.

## Reporting vulnerabilities

Open a private advisory on GitHub (preferred, avoids exposing a personal
email in the repo):

  https://github.com/juanfranem/opencode-auto-guard/security/advisories/new

Alternatively, email the address listed on the GitHub profile. Please do
not file public issues for security bugs.
