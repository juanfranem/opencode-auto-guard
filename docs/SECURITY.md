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
|    e. LLM judge for ambiguous cases       |
|       - rate-limited per session          |
|    f. Per-agent escalation (build)        |
|    g. Per-agent tightening (no auto-allow)|
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
- **Audit log unbounded growth**: the hash-chained audit auto-rotates at
  10,000 entries. Older entries are archived under
  `guard:audit-archive-${date}-${n}` keys with a pointer record so the
  chain can be reconstructed across rotations.

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

Email: security@your-domain.example (replace before publishing).

Please do not file public issues for security bugs.
