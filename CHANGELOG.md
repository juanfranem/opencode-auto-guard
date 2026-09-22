# Changelog

All notable changes to **opencode-auto-guard** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.3] — 2026-09-22

### Added

- **Auto-registration on first install.** `src/agent-registration.ts` runs from `setup()` and now (a) seeds `~/.config/opencode/agents/auto.md` from the bundled `agents/auto.md` the very first time the plugin starts in a fresh home directory, and (b) applies the canonical permission list through `ctx.agent.transform`. The previous manual `Copy-Item` + `opencode.jsonc` edit step is gone for users who accept the defaults. The flow runs **before** the self-integrity pin check so a missing `options.pin` still delivers the agent. Explicit `agents.auto` declarations in `opencode.jsonc` win — the plugin only fills in fields you left empty.
- **`AUTO_AGENT_ID` and `AUTO_AGENT_DEFAULT_PERMISSIONS`** constants exported from `src/rules.ts`. Single source of truth for the agent id and its default rule list; tests assert both.
- **`agent-registration` audit category.** `auto_agent_register` entries land in the hash-chained audit log on every `setup()` so you can verify what the plugin did (whether the file was written, whether the editor applied the defaults).
- **`test:agent-registration`** test script — exercises path helpers, the bundled-source resolution, idempotent seeding, the agent editor's permissive/rejective paths, the user-override guarantee, and end-to-end through `registerAutoAgent`.

### Changed

- `package.json` `files` manifest now ships `src/agent-registration.ts` alongside the other runtime modules.
- README "Auto mode" section rewritten: documents that the agent is auto-registered on first install, with the manual `opencode.jsonc` block now positioned as an **override** recipe rather than the install procedure. Pin hash path updated to the `@juanfranem/opencode-auto-guard` scope that matches the GitHub Packages name.

### Fixed

- README incorrectly claimed that "OpenCode v2 does not let plugins register agents through `ctx.agent.transform`" — this was true at the time of writing `0.1.0` but `@opencode/plugin@2.0.x` has exposed both `ctx.agent.transform` and `ctx.skill.transform` ever since, and the plugin already uses `ctx.skill.transform` for `compact-context-guard`. The "Auto mode" section is now aligned with the actual SDK surface.

## [0.1.2] — 2026-09-22

### Fixed

- **`/auto-guard-setup` failed at runtime** with `SchemaError(Expected string at ["text"])` after the v0.1.1 fix made `execute` actually push a prompt. The `SessionPromptInput` schema's `text` field is an indexed-access type that resolves to a plain `string`, but the wizard was passing `{ text: wizardPrompt }` (an object). Patched to pass `text: wizardPrompt` directly. `description` is kept as the picker-preview text so the wizard remains visible in the slash menu. End-to-end verified on OpenCode v2.0.12.

## [0.1.1] — 2026-09-21

### Fixed

- **`/auto-guard-setup` command did nothing.** The wizard instructions lived in the command's `description`, under the (wrong) assumption that OpenCode v2 would inject `description` into the agent's prompt when the slash command runs. In reality OpenCode v2 only invokes `execute(input)`; `description` is help text in the picker. `execute` now calls `ctx.session.prompt(...)` to push the wizard instructions into the session as a real user prompt. The `description` is kept as a preview in the slash menu so the user can see the wizard text and copy it manually if the prompt endpoint is unavailable.

## [0.1.0] — 2026-09-21

First public release.

### Added

- **Three-layer defense pipeline.** A pure-code fast classifier handles shell commands, webfetch, and file edits; network-domain validation runs as part of Layer 2; optional Layer 3 escalates ambiguous shell commands to a structured-decision judge (Jev) and then to an LLM judge. The LLM judge can **deny** or keep **ask** — it never promotes `ask → allow`.
- **Self-integrity and self-protection.** The plugin refuses to register hooks when a configured `pin` (SHA-256 of `index.ts` + `rules.ts`) does not match the installed files. Reads, edits, writes, and `apply_patch` over the plugin's own files or over `opencode.jsonc` are denied outright.
- **TOCTOU defence.** `tool.execute.before` re-checks file paths via `realpath` to detect symlink swap between read and write hooks.
- **Trusted-domain policy.** Single `trustedDomains` list drives `webfetch`, `websearch`, and shell-network egress (`curl`, `wget`, `ssh`, `nc`, jump hosts in `-J`, `nslookup`). Non-trusted destinations prompt the user.
- **Untrusted-source wrapping.** Output from non-trusted `webfetch` is wrapped in `<untrusted-source url="...">` so downstream turns treat it as data, not instructions.
- **Per-agent policy.** `build` and `plan` agents never elevate `ask → allow`. Only the `auto` agent uses the deterministic allowlist for auto-approval.
- **Session limits.** Session pauses after `3` denials, `250` counted actions, or when the main agent's context reaches `60 %` of the model window (configurable). Counted actions: `bash`, `edit`, `write`, `apply_patch`, `webfetch`, `websearch`, `subagent`. Read-only actions do not count.
- **Context handoff via `compact-context-guard`.** When the context guard fires, the conversation is dumped to `~/.config/opencode/opencode-auto-guard/sessions/<session-id>/raw-<timestamp>.json` and the `compact-context-guard` skill writes a structured markdown handoff (`compact-<timestamp>.md`) so you can resume in a fresh session without losing the thread.
- **`/auto-guard-setup` command.** Interactive wizard inside the agent that walks through every option one question at a time, previews the resulting `options` block, and writes it back to `opencode.jsonc` in place.
- **`auto` agent definition.** Bundled at `agents/auto.md` with a known scratch directory at `~/.config/opencode/opencode-auto-guard/tmp/`, kept separate from the user's project. Subdirectories inside are still subject to the regular per-action checks.
- **Audit log.** Hash-chained, tamper-evident log of every decision (allow / ask / deny). Auto-rotates at 10 000 entries, keeping the 5 000 most recent and archiving the rest.
- **LRU+TTL cache for `isSafe()`.** `60 s` TTL, 1 000 entries — reduces CPU on repeated safe commands.
- **Fast structured judge (Jev, optional).** Calls [OpenCode Zen's "system one" model](https://opencode.ai/docs/zen/) for ambiguous shell commands. ~70–500 ms, free during the OpenCode promo period, returns a typed verdict. Low-confidence and `unsure` cases fall through to the LLM judge. Tunable thresholds (`fastJudgeConfidenceDeny`, `fastJudgeConfidenceAsk`).
- **Test suites.** `bun src/tests/evasion-test.ts` (shell pattern evasion), `bun src/tests/jev-test.ts` (fast judge), `bun src/tests/compact-test.ts` (context handoff).
- **Dual publish.** Tag push → (a) GitHub Release with tarball + SHA-256 sidecar, (b) `npm.pkg.github.com` install path under `@juanfranem/opencode-auto-guard`.
- **GitHub Actions.** Biome lint + format check + tests + CodeQL in CI; release workflow attaches signed artefacts to each GitHub Release.

### Changed

- Replaced the time-based session pause (`maxDurationMs`) with a context-based pause (`maxContextUsage`). `maxDurationMs` is kept as a `0`-disabled legacy alias.
- `bun.lock` is now committed (Bun best practice — reproducible installs and `bun audit` in CI).
- `package.json` `files` manifest narrowed to the runtime source tree (`src/index.ts`, `src/rules.ts`, `src/judge-fast.ts`), `agents/`, `README.md`, `LICENSE`, `docs/`. Tests and dev config are excluded from the published package.

### Security

- See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model — what is enforced, what is **not** in scope (network-level exfiltration, filesystem isolation, credential scoping) and how to combine this plugin with OS-level isolation (`bwrap`, `sandbox-exec`, AppContainer, mount namespaces) for defence in depth.
- Publishing is fingerprinted (`publishConfig.access = "public"`, scope `@juanfranem`) and GitHub Release artefacts are produced by an audited workflow.
