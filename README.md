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
| Session limits | 3 denials / 250 counted actions / 30 min → session pauses. Only risky actions (`bash`, `edit`, `write`, `apply_patch`, `webfetch`, `websearch`, `subagent`) count. |
| Audit | Hash-chained tamper-evident log of every decision. Auto-rotates at 10,000 entries (keeps 5,000 most recent + archives older). |
| TOCTOU | `tool.execute.before` hook re-checks file paths via `realpath` to detect symlink swap. |
| `isSafeCached` | Module-level LRU+TTL cache (default 60s, 1000 entries) for `isSafe()` results — reduces CPU on repeated safe commands. |

## Install

### From npm (once published)

```bash
opencode plugin add opencode-auto-guard
```

### From git (during development)

```bash
opencode plugin add github:your-user/opencode-auto-guard
```

### From a local path

```bash
opencode plugin add "C:\path\to\opencode-auto-guard"
```

Then add the plugin to your `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "opencode-auto-guard",
      "options": {
        "judge": true,
        "model": "anthropic/claude-sonnet-4-5",
        "strictBuild": true,
        "trustedDomains": ["github.com", "mi-empresa.local"],
        "pin": "sha256:..."
      }
    }
  ]
}
```

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
| `maxActions` | number | `250` | Session pauses after this many actions. |
| `maxDurationMs` | number | `1800000` | Session pauses after this many ms. |
| `pin` | string | unset | SHA-256 of `index.ts` + `rules.ts`. If set and mismatch → plugin disables. |

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

## Agent: Auto mode

The package ships an agent definition at `agents/auto.md`. OpenCode v2 does
not allow plugins to register agents via `ctx.agent.transform` (no `add`
method on `AgentEditor`), so you need to install it manually.

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
