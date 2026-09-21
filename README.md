# opencode-auto-guard

[![CI](https://github.com/juanfranem/opencode-auto-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/juanfranem/opencode-auto-guard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/opencode-auto-guard)](https://www.npmjs.com/package/opencode-auto-guard)

Security guard plugin for [OpenCode](https://opencode.ai) v2.

Adds a deterministic fast classifier plus an optional LLM judge in front of
every shell command, file edit, and webfetch. Designed to be conservative
by default: when in doubt, deny.

## What it does

| Layer | Behavior |
|---|---|
| Self-integrity | Refuses to register hooks if a `pin` mismatch is detected. |
| Self-protection | `read`/`edit`/`write`/`apply_patch` over the plugin's own files → **deny**. |
| Webfetch / Websearch | Only trusted domains pass without asking. Others → **ask**. |
| Webfetch delimiters | Output from non-trusted sources is wrapped in `<untrusted-source url="...">...</untrusted-source>` so the agent treats it as data, not instructions. |
| Shell — fast classifier | Pure-code patterns (no LLM). Catches obfuscation, pipe-to-shell, `rm -rf /`, `find -exec`, `tar --checkpoint-action=exec`, long base64 payloads. |
| Shell — network egress | If a shell command uses `curl`, `wget`, `ssh`, `nc`, etc., the host is extracted and validated against `trustedDomains`. Non-trusted → **ask**. |
| Shell — strong judge (optional) | LLM call for ambiguous cases. Can only **deny** or keep **ask**. Never **allow**. Rate-limited to 20 calls per session. |
| Per-agent policy | In `build`/`plan`, the plugin **never** elevates `ask → allow`. Only the `auto` agent gets allowlist-driven auto-approval. |
| Session limits | 3 denials / 250 counted actions → session pauses. Plus context-based: pauses when the main agent's context reaches 60% of the model's context window (or your `maxContextUsage`). Risky actions (`bash`, `edit`, `write`, `apply_patch`, `webfetch`, `websearch`, `subagent`) are counted; read-only actions are not. |
| Context handoff | When the context guard fires, the plugin dumps the conversation to disk and auto-invokes the `compact-context-guard` skill, which writes a structured markdown handoff so the user can continue in a fresh session. See [Context handoff](#context-handoff-compact-context-guard). |
| Audit | Hash-chained tamper-evident log of every decision. Auto-rotates at 10,000 entries (keeps 5,000 most recent + archives older). |
| TOCTOU | `tool.execute.before` hook re-checks file paths via `realpath` to detect symlink swap. |
| `isSafeCached` | Module-level LRU+TTL cache (default 60s, 1000 entries) for `isSafe()` results — reduces CPU on repeated safe commands. |

## Install

### From GitHub Releases (recommended, no auth needed for public install)

Pick a tag from <https://github.com/juanfranem/opencode-auto-guard/releases>
and use the GitHub tarball URL:

```bash
opencode plugin add github:juanfranem/opencode-auto-guard#v0.1.0
```

The release workflow attaches the package tarball to each GitHub
Release, so any tag you `git push` is automatically installable.

### From GitHub Packages

```bash
opencode plugin add @juanfranem/opencode-auto-guard
```

Requires that your OpenCode install can reach `npm.pkg.github.com`.
For a public package on GitHub Packages, configure an `.npmrc` with the
registry before installing:

```ini
# ~/.npmrc or %USERPROFILE%\.npmrc
@juanfranem:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=<your-github-token-with-read:packages>
```

If you don't have a token, prefer the GitHub Releases install above.

### From a local clone (during development)

```bash
git clone https://github.com/juanfranem/opencode-auto-guard.git
cd opencode-auto-guard
opencode plugin add file://.
```

Then add the plugin to your `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "@juanfranem/opencode-auto-guard",
      "options": {
        "judge": true,
        "model": "anthropic/claude-sonnet-4-5",
        "strictBuild": true,
        "trustedDomains": ["github.com", "example.com"],
        "pin": "sha256:..."
      }
    }
  ]
}
```

> **Note:** even when installed from a GitHub Release tarball, the
> plugin's npm name remains `@juanfranem/opencode-auto-guard`. Use that
> string in `opencode.jsonc` regardless of how you installed it.

## Options

All options are optional. Defaults are conservative.

| Option | Type | Default | Description |
|---|---|---|---|
| `judge` | boolean | `true` | Enable the LLM judge for ambiguous cases. |
| `model` | string | default model | Model used by the judge. Format `provider/model`. |
| `strictBuild` | boolean | `true` | In `build`, force `ask` on `ALWAYS_ASK` patterns even if global config says allow. |
| `trustedDomains` | string[] | built-in list | Domains that pass through `webfetch`/`websearch` without asking. |
| `protectedPaths` | string[] | plugin files | Absolute paths that are denied for `read`/`edit`/`write`. |
| `maxDenials` | number | `3` | Session pauses after this many denials. |
| `maxActions` | number | `250` | Session pauses after this many counted actions. |
| `maxContextUsage` | number | `0.6` | Pause when the main agent's context reaches this fraction of the model's context window (0–1). 0 disables. |
| `maxDurationMs` | number | `0` | Legacy time-based pause. 0 disables. Use `maxContextUsage` instead. |
| `compactSessionsDir` | string | `~/.config/opencode/opencode-auto-guard/sessions` | Where the `compact-context-guard` skill writes its raw dumps and refined handoff documents. |
| `compactOnContextGuard` | boolean | `true` | When the context guard fires, dump the conversation and auto-invoke the `compact-context-guard` skill in the paused session. Set `false` to disable. |
| `tempDir` | string | `~/.config/opencode/opencode-auto-guard/tmp` | Scratch directory the auto agent uses for intermediate output (compiled artefacts, test fixtures, logs). Created on plugin startup; not in the protected-paths list. |
| `fastJudgeModel` | string | unset | Optional fast structured judge (e.g. `opencode/jev-1.13-free`). Runs BEFORE the LLM judge for ambiguous shell commands; free and ~70–500 ms typical. Falls back to the LLM judge on error, low confidence, or when no API key is configured. Requires `OPENCODE_ZEN_API_KEY` env var or `fastJudgeApiKey`. |
| `fastJudgeEndpoint` | string | `https://opencode.ai/zen/v1/systemone` | Endpoint for the structured judge. Override only if you self-host a "system one"-compatible model. |
| `fastJudgeApiKey` | string | unset | Bearer token for the structured judge. Falls back to `OPENCODE_ZEN_API_KEY` env var. |
| `fastJudgeTimeoutMs` | number | `5000` | Per-request timeout for the fast judge. Jev is fast; 5 s is a generous ceiling. |
| `fastJudgeConfidenceDeny` | number | `0.75` | Minimum confidence (0–1) for the fast judge to issue a `deny`. Below this, falls through to the LLM judge. |
| `fastJudgeConfidenceAsk` | number | `0.6` | Minimum confidence for the fast judge to short-circuit an `ask`. Below this, the LLM judge still gets the case. |
| `pin` | string | unset | SHA-256 of `index.ts` + `rules.ts`. If set and mismatch → plugin disables. |

## Fast structured judge (Jev)

For shell commands that fall through to the ambiguous bucket, the
plugin can call a "system one" model (e.g. [Jev on OpenCode Zen](https://opencode.ai/docs/zen/))
**before** the LLM judge. The fast judge is free during the OpenCode
promo period, responds in ~70–500 ms, and returns typed decisions
instead of text. The LLM judge stays on as the safety net for cases
where Jev returns low confidence or `unsure`.

### Enable it

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "opencode-auto-guard",
      "options": {
        "judge": true,
        "fastJudgeModel": "opencode/jev-1.13-free",
        "judgeModel": "anthropic/claude-sonnet-4-5"
        // fastJudgeApiKey optional: falls back to OPENCODE_ZEN_API_KEY env var
      }
    }
  ]
}
```

### Auth

```powershell
$env:OPENCODE_ZEN_API_KEY = "your-zen-key"
# or set fastJudgeApiKey in opencode.jsonc
```

Without a key the fast judge is silently skipped and only the LLM judge
runs.

### How it stacks

```
shell command
   |
   v
HARD_DENY patterns?            -> deny
HARD_ASK / ALWAYS_ASK patterns?-> ask
fast classifier (no LLM)       -> deny / ask / (continue)
trusted-domain network check?  -> ask
auto allowlist (auto agent)?   -> allow
                                |
                  ambiguous (worst=ask)
                                |
                                v
                  fast structured judge (Jev)   <-- NEW
                  - 5s timeout
                  - free
                  - aborts to LLM on error / unsure / low conf
                                |
                  high-conf deny  -> deny  (LLM judge skipped)
                  high-conf ask   -> ask   (LLM judge skipped)
                  else                     -> LLM judge (existing)
```

### Caveats from the published test report

- **One injection test, not a guarantee.** Jev passed a basic
  prompt-injection attempt in the published tests, but a single test
  does not prove resistance to more sophisticated injection
  techniques. We still treat Jev's output as data, not authority.
- **Forced-choice without `unsure` is dangerous.** The published
  report shows that without an "other" / "unsure" option the model
  picks a confident-wrong answer. We always include `unsure` in the
  question schema; on `unsure` we fall through to the LLM judge.
- **Confidence ≠ accuracy.** Treat Jev's confidence score as a
  threshold for *when to ask for a second opinion*, not as a measure of
  how correct the verdict is. The plugin audits every decision with the
  raw confidence so you can tune `fastJudgeConfidenceDeny` /
  `fastJudgeConfidenceAsk` against your own workload.
- **Negation is the failure mode to watch.** The report showed Jev
  parses "I'm not asking for a refund" correctly, but a single example
  doesn't generalise. If you see Jev missing negations in your own
  audit log, raise `fastJudgeConfidenceDeny`.

## Get the current pin

After installing, compute and pin the hash:

```powershell
$index = Get-FileHash "$env:USERPROFILE\.config\opencode\node_modules\opencode-auto-guard\src\index.ts" -Algorithm SHA256
$rules = Get-FileHash "$env:USERPROFILE\.config\opencode\node_modules\opencode-auto-guard\src\rules.ts" -Algorithm SHA256
$combined = [System.BitConverter]::ToString((
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes($index.Hash + "|" + $rules.Hash)
  )
)) -replace "-", ""
"sha256:$combined"
```

Set the result as `options.pin`. If someone replaces either file, the plugin
won't register and OpenCode will silently fall back to your base permissions.

## Context handoff (compact-context-guard)

Long sessions run out of context. When that happens the guard denies
the offending action and, by default, also asks OpenCode to activate a
skill called `compact-context-guard` so the user can keep going in a
fresh session without losing the thread.

What the plugin does when the context guard fires:

1. **Deny** the action that crossed `maxContextUsage`.
2. **Dump** the conversation: `ctx.session.context({ sessionID })` is
   serialised to
   `~/.config/opencode/opencode-auto-guard/sessions/<session-id>/raw-<timestamp>.json`.
3. **Rewrite** the registered skill's `content` with the concrete paths
   and timestamps for this invocation.
4. **Invoke** the skill via `ctx.session.skill({ sessionID, id: "compact-context-guard" })`.

What the skill does (read by the agent on its next turn):

1. `read` the raw dump.
2. `write` a refined markdown compact to
   `~/.config/opencode/opencode-auto-guard/sessions/<session-id>/compact-<timestamp>.md`.
3. Tell the user the absolute path of the compact.

The refined compact follows a fixed structure the next agent
recognises so it can pick the work back up cheaply:

- `# Compact Session: <title>` + metadata blockquote
- `## Original Goal`
- `## Where We Are Now` (✅ done / 🔄 in progress / ❌ blocked / ⏭️ next)
- `## Key Decisions Made`
- `## Files Touched`
- `## Pending Questions / Blockers`
- `## Recommended Next Steps`
- `## Context the Next Agent Needs`
- `## Environment Notes`

Disable the auto-invoke with `compactOnContextGuard: false`, or change
the output directory with `compactSessionsDir`. The plugin still
registers the skill (and ships a standalone `agents/compact-context-guard.md`)
so you can invoke it manually with `compact-context-guard` at any time.

The skill is invoked once per session — once the guard has fired, the
plugin stops re-invoking it on subsequent denials while the session
stays paused. If the user wants a fresher compact, they can run the
skill again manually.

## Agent: Auto mode

The package ships an agent definition at `agents/auto.md`. OpenCode v2 does
not allow plugins to register agents via `ctx.agent.transform` (no `add`
method on `AgentEditor`), so you need to install it manually.

The auto agent has a known scratch directory:

```
~/.config/opencode/opencode-auto-guard/tmp/
```

The plugin creates it on startup. Use it for compiled artefacts, test
fixtures, intermediate logs — anything that has to live on disk but is
not part of the user's project. Subdirectories inside it are still
subject to the regular per-action checks (self-protection, shell
classification, network egress); only the TMP root itself gets the
implicit "temp files live here" semantics. See `agents/auto.md` for
the rules the auto agent follows when writing there.

**One-time setup**:

```powershell
# Copy the agent definition
Copy-Item "$env:USERPROFILE\.config\opencode\node_modules\opencode-auto-guard\agents\auto.md" `
  -Destination "$env:USERPROFILE\.config\opencode\agents\auto.md"
```

Then add it to your `opencode.jsonc`:

```jsonc
{
  "agents": {
    "auto": {
      "mode": "primary",
      "model": "anthropic/claude-sonnet-4-5",
      "prompt": "{file:./agents/auto.md}",
      "permissions": [
        { "action": "external_directory", "resource": "*", "effect": "ask" },
        { "action": "read", "resource": "*", "effect": "allow" },
        { "action": "edit", "resource": "*", "effect": "allow" },
        { "action": "glob", "resource": "*", "effect": "allow" },
        { "action": "grep", "resource": "*", "effect": "allow" },
        { "action": "shell", "resource": "*", "effect": "ask" },
        { "action": "webfetch", "resource": "*github.com*", "effect": "allow" },
        { "action": "webfetch", "resource": "*", "effect": "ask" }
      ]
    }
  }
}
```

In TUI, press **Tab** to switch between `build`, `plan`, and `auto`.

## What gets blocked

Examples of commands that **always** deny (regardless of config):

- `curl ... | bash` (or any pipe to `sh`, `pwsh`, `powershell`)
- `pwsh -EncodedCommand <base64>`
- `find / -exec rm {} \;`
- `xargs rm` / `xargs curl`
- `tar --checkpoint-action=exec='sh evil.sh'`
- `:(){:|:&};:` (fork bomb)
- `reg delete`, `Remove-Item -Recurse -Force \\`
- Reading or writing `auto-guard.ts`, `auto-guard-rules.ts`, `opencode.jsonc`, etc.

Examples of commands that **always** ask in `auto` agent:

- `git push`, `git commit`
- `docker run --privileged`
- `terraform apply`, `kubectl delete`, `aws s3 rm`
- `npm publish`, `cargo publish`
- `ssh user@host`, `scp ./secret user@host:/tmp/`

Examples of commands that **trigger the network egress check** (ask if host is not trusted):

- `curl https://internal-api.mycompany.com/data` (whitelist `mycompany.com` if legitimate)
- `wget https://unknown.example.com/installer`
- `ssh user@bastion.prod.example`
- `ssh -J user@jump user@dest`
- `nc evil.example.com 4444`
- `nslookup evil.example.com`

The plugin extracts the host from URL or `user@host` syntax (including jump hosts in `-J`) and applies the same `trustedDomains` policy used for `webfetch`.

## What does NOT get blocked

Out of scope by design. Combine with OS-level isolation for full coverage:

- Network-level exfiltration (use `bwrap`, `sandbox-exec`, AppContainer)
- Filesystem isolation (mount namespaces, chroot)
- Credential scoping (least-privilege IAM, short-lived tokens)
- The user can downgrade to `plan` mode and approve manually
- Adversarial context from webfetch (always treated as untrusted by the agent)

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full security model.

## Commands

### `/auto-guard-setup`

Interactive wizard that walks you through the plugin configuration and
writes the result back to `opencode.jsonc`. The agent asks the questions
one at a time using its native `question` tool, previews the new options,
then uses `read` + `edit` to update your config in place.

Questions asked:

1. LLM judge (yes / no, default yes)
2. Judge model (if Q1 = yes; `provider/model`, e.g. `anthropic/claude-sonnet-4-5`)
3. Strict build mode (yes / no, default yes)
4. Context usage limit (0.0–1.0, default `0.6`)
5. Max denials (default `3`)
6. Max actions (default `250`)
7. Extra trusted domains (comma-separated, optional)
8. Pin the plugin SHA-256 (advanced, default no)

After confirmation, the wizard shows the diff, writes the file, and reminds
you to restart opencode (options are read at startup).

## Development

```bash
# Install deps
bun install

# Run tests
bun src/tests/evasion-test.ts

# Type check
bun run typecheck

# Local install for testing
opencode plugin add file://.
```

## License

MIT
