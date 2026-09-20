// rules.ts
// Pure rules for the opencode-auto-guard plugin.
// No IO, no plugin context. Importable from tests.

import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";

// ============== Deterministic lists ==============

export const HARD_DENY = [
  "frombase64string",
  "encodedcommand",
  "-enc ",
  "-encodedcommand",
  "invoke-expression",
  "invoke-webrequest",
  "downloadstring",
  "downloadfile",
  "start-bitstransfer",
  "set-executionpolicy",
  "bypass",
  "reg delete",
  "format-",
  "mkfs",
  "dd if=",
  ":(){:|:&};:",
  "cacls ",
  "takeown ",
];

export const HARD_ASK = [
  "remove-item",
  "ri ",
  "rm -rf",
  "rmdir",
  " del ",
  "del /",
  "erase ",
  "docker run",
  "--privileged",
  "-v /",
  "-v c:",
  "-v c:/",
  "--network host",
  "docker rm",
  "docker rmi",
  "docker system prune",
  "docker volume rm",
  "git push",
  "git reset --hard",
  "git clean",
  "git rebase",
  "git commit",
  "net user",
  "net localgroup",
  "schtasks",
  "sc create",
  "new-service",
  "set-service",
  "stop-computer",
  "restart-computer",
  "curl ",
  "wget ",
  "ssh ",
  "ftp ",
];

// ALWAYS ask, even if config says allow. Designed to not break local dev but
// block access to external/public/sensitive infrastructure.
export const ALWAYS_ASK = [
  "terraform apply",
  "terraform destroy",
  "terraform import",
  "kubectl apply",
  "kubectl delete",
  "kubectl drain",
  "kubectl exec",
  "kubectl port-forward",
  "kubectl rollout",
  "aws s3 rm",
  "aws s3 sync",
  "aws ec2 terminate",
  "aws rds delete",
  "aws deploy",
  "gcloud compute instances delete",
  "gcloud sql instances delete",
  "az vm delete",
  "ansible-playbook",
  "pulumi up",
  "pulumi destroy",
  "npm publish",
  "pnpm publish",
  "yarn publish",
  "cargo publish",
  "dotnet nuget push",
  "twine upload",
  "pip upload",
  "gem push",
  "scp ",
  "rsync ",
  "ncat ",
  "nmap ",
];

export const SAFE_PREFIXES = [
  "dir",
  "ls",
  "get-childitem",
  "gci",
  "pwd",
  "get-location",
  "whoami",
  "type ",
  "cat ",
  "get-content",
  "gc ",
  "more ",
  "head ",
  "tail ",
  "echo ",
  "write-output",
  "write-host",
  "where ",
  "get-command",
  "test-path",
  "select-string",
  "cd ",
  "set-location",
  "push-location",
  "pop-location",
  "mkdir",
  "md ",
  "new-item",
  "copy-item",
  "copy ",
  "xcopy",
  "robocopy",
  "move-item",
  "move ",
  "rg ",
  "grep ",
  "find ",
  "fd ",
  "jq ",
  "git status",
  "git diff",
  "git log",
  "git show",
  "git branch",
  "git stash list",
  "git remote -v",
  "git rev-parse",
  "gh pr view",
  "gh issue view",
  "gh repo view",
  "gh run view",
  "gh auth status",
  "docker ps",
  "docker images",
  "docker inspect",
  "docker logs",
  "docker compose ps",
  "docker compose logs",
  "npm ",
  "npx ",
  "node ",
  "python ",
  "py ",
  "uv ",
  "pytest",
  "dotnet ",
  "cargo ",
  "go ",
];

// Pipeline-to-shell patterns (curl|sh, wget|sh, etc.).
export const PIPE_TO_SHELL = [
  /\bcurl\b[^|;&]*\|\s*(bash|sh|zsh|dash|ksh|pwsh|powershell|cmd)\b/i,
  /\bwget\b[^|;&]*\|\s*(bash|sh|zsh|dash|ksh|pwsh|powershell|cmd)\b/i,
  /\bcurl\b[^|;&]*\|\s*iex\b/i,
  /\bInvoke-Expression\b[^|;&]*\|\s*Invoke-WebRequest\b/i,
  /\bfetch\b[^|;&]*\|\s*(bash|sh|zsh)\b/i,
  /\bnode\s+-e\b[^|;&]*(?:https?:\/\/|curl|wget)/i,
];

// Obfuscation patterns.
export const OBFUSCATION = [
  /\bbase64\b[^|;&]*-d\b/i,
  /\bbase64\b[^|;&]*--decode\b/i,
  /\bFromBase64String\b/i,
  /\bEncodedCommand\b/i,
  /\$\(.*base64.*\)/i,
  /`.*base64.*`/i,
  /\bprintf\b[^|;&]*\\\\x/i,
  // Long base64 string (>100 chars). Captures the payload of -EncodedCommand
  // once unwrap() has stripped the flag but left the body.
  /^[A-Za-z0-9+/]{100,}={0,2}$/,
];

// Dangerous recursive removal patterns.
export const DANGEROUS_RM = [
  /\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+\/\s*(?!\w)/i,
  /\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+~(?:\s|$)/i,
  /\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+\.\.\s*$/i,
  /\bRemove-Item\b[^|;&]*-Recurse[^|;&]*-Force[^|;&]*\\?\s*$/i,
  /\bRemove-Item\b[^|;&]*-Force[^|;&]*-Recurse[^|;&]*\\?\s*$/i,
];

// find -exec / xargs that can escalate.
export const FIND_EXEC = [
  /\bfind\b[^|;&]*-exec\b/i,
  /\bfind\b[^|;&]*-execdir\b/i,
  /\bxargs\b[^|;&]*(?:rm|del|curl|wget|bash|sh|powershell)/i,
];

// tar with checkpoint execution.
export const TAR_CHECKPOINT = [
  /\btar\b[^|;&]*--checkpoint-action\s*=\s*exec/i,
  /\btar\b[^|;&]*--checkpoint\s*=\s*\d+.*--checkpoint-action/i,
];

// ============== Network tool detection ==============

// matches these tools as whole words, case-insensitive:
// curl, wget, ssh, scp, rsync, nc, ncat, nslookup, dig, ping,
// tracert, traceroute, httpx, httpie
export const NETWORK_TOOLS: RegExp =
  /\b(curl|wget|ssh|scp|rsync|nc|ncat|nslookup|dig|ping|tracert|traceroute|httpx|httpie)\b/i;

// extract unique hosts from a command string.
// sources:
//   - http(s)://host patterns (extract the host portion, lowercased)
//   - ssh invocations: any `@host` token found after `ssh` up to the next
//     command separator. captures jump hosts (`-J user@host`) and
//     multiple targets (`ssh user@host1 user@host2`).
// returns [] if none. deduplicates.
export function extractNetworkHosts(command: string): string[] {
  if (!command) return [];
  const hosts = new Set<string>();
  let m: RegExpExecArray | null;

  // 1) HTTP/HTTPS URLs
  const urlRe = /https?:\/\/([^/\s?#:[\]]+)/gi;
  while ((m = urlRe.exec(command)) !== null) {
    const host = m[1].toLowerCase().split(":")[0];
    if (host) hosts.add(host);
  }

  // 2) ssh invocations: capture args until the next shell separator
  //    (`;`, `&`, `|`, newline) or end of string. Then within those
  //    args, pick up every `@host` token.
  const sshInvRe = /\bssh\b([^\n;&|]*)/gi;
  while ((m = sshInvRe.exec(command)) !== null) {
    const args = m[1];
    const atRe = /@(\S+)/g;
    let am: RegExpExecArray | null;
    while ((am = atRe.exec(args)) !== null) {
      const host = am[1].split(/[\s:"']/)[0].toLowerCase();
      if (host) hosts.add(host);
    }
  }

  return [...hosts];
}

// ============== Session state ==============

export interface ContextBaseline {
  /** Real token count observed at the baseline anchor (e.g. after compaction). */
  tokens: number;
  /** Number of messages in the conversation at the baseline anchor. */
  messagesLength: number;
  /** Provider/model id at the baseline anchor, so model switches reset cleanly. */
  modelKey: string;
}

export interface SessionState {
  denials: number;
  totalActions: number;
  startTime: number;
  /** Last computed context usage in tokens (baseline + estimated delta). */
  contextTokens: number;
  /** Model's context window (in tokens) at the time of the last measurement. */
  contextLimit: number;
  /** contextTokens / contextLimit, in [0, 1]. 0 if limit unknown. */
  contextPct: number;
  /** Anchor for incremental token estimation; undefined means no baseline yet. */
  contextBaseline?: ContextBaseline;
  /**
   * True once the context guard has fired the compact-context-guard skill
   * for this session. Prevents the skill from being re-invoked on every
   * subsequent denial while the session is paused.
   */
  contextCompactTriggered: boolean;
}

export function newSession(): SessionState {
  return {
    denials: 0,
    totalActions: 0,
    startTime: Date.now(),
    contextTokens: 0,
    contextLimit: 0,
    contextPct: 0,
    contextCompactTriggered: false,
  };
}

// ============== Token estimation ==============

/** Average chars per token used by the cheap estimator. Mixed English/code ~4. */
const CHARS_PER_TOKEN = 4;

/**
 * Best-effort count of the textual content of a message.
 * Accepts the loose shape OpenCode uses for messages: a string content,
 * an array of parts with `text`/`content` fields, or anything else.
 * Returns 0 for unknown shapes rather than throwing.
 */
export function sumMessageChars(msg: unknown): number {
  if (!msg) return 0;
  const m = msg as { content?: unknown; text?: unknown };
  const c = m.content ?? m.text;
  if (typeof c === "string") return c.length;
  if (Array.isArray(c)) {
    let total = 0;
    for (const part of c) {
      if (typeof part === "string") {
        total += part.length;
      } else if (part && typeof part === "object") {
        const p = part as { text?: unknown; content?: unknown };
        if (typeof p.text === "string") total += p.text.length;
        if (typeof p.content === "string") total += p.content.length;
      }
    }
    return total;
  }
  return 0;
}

/**
 * Estimate the token count of a conversation by summing message chars
 * and dividing by CHARS_PER_TOKEN. Returns 0 for empty input.
 *
 * This is an approximation: real tokenizers (cl100k, o200k) give
 * ±20% error on mixed English/code. Good enough for context-budget
 * guards where the threshold has slack.
 */
export function estimateTokens(messages: ReadonlyArray<unknown>): number {
  if (!messages || messages.length === 0) return 0;
  let chars = 0;
  for (const m of messages) chars += sumMessageChars(m);
  return Math.ceil(chars / CHARS_PER_TOKEN);
}

// ============== Setup wizard ==============

export interface SetupWizardOptions {
  /** Absolute path to the user's opencode.jsonc. */
  configPath?: string;
  /** Optional snapshot of the current options to weave into the prompt. */
  currentOptions?: Record<string, unknown>;
}

const DEFAULT_WIZARD_CONFIG_PATH = "~/.config/opencode/opencode.jsonc";

/**
 * Build the instruction prompt the agent reads when the user invokes
 * `/auto-guard-setup`. The agent uses its native `question` tool to
 * walk the user through the wizard, then `read` + `edit` to update
 * `opencode.jsonc`.
 *
 * The function is pure so it can be unit-tested: tests assert that the
 * output mentions every required question, the defaults, and the
 * post-collection steps.
 */
export function buildSetupWizardPrompt(opts: SetupWizardOptions = {}): string {
  const configPath = opts.configPath ?? DEFAULT_WIZARD_CONFIG_PATH;
  const currentBlock = opts.currentOptions
    ? `\n## Current options (for context)\n\n\`\`\`jsonc\n${JSON.stringify(opts.currentOptions, null, 2)}\n\`\`\`\n`
    : "";

  return `The user just ran \`/auto-guard-setup\`. Walk them through configuring the opencode-auto-guard plugin interactively.

Use the \`question\` tool to ask the questions below **one at a time**, in order. After each answer, accept "default" or silence as the documented default. When you have all the answers, write the new options back to \`${configPath}\` using \`read\` + \`edit\`.
${currentBlock}
## Questions

1. **LLM judge**: enable the LLM judge? It catches ambiguous cases the fast classifier cannot, but costs API tokens. \`yes\` / \`no\`, default \`yes\`.
2. **Judge model** (only if Q1 = yes): which model? Format \`provider/model\`, e.g. \`anthropic/claude-sonnet-4-5\`. Say "default" to use the opencode default model.
3. **Strict build mode**: should the build agent force \`ask\` for terraform / aws / kubectl / \`npm publish\` / ssh / scp / rsync? \`yes\` / \`no\`, default \`yes\`.
4. **Context usage limit**: at what fraction of the model context window should the session pause? Range 0.0–1.0. \`0.6\` means pause at 60%. Default \`0.6\`.
5. **Max denials**: after how many denials should the session pause? Default \`3\`.
6. **Max actions**: after how many risky actions (bash / edit / write / webfetch / subagent) should the session pause? Default \`250\`.
7. **Trusted domains**: extra domains to whitelist for webfetch? Comma-separated, optional. Say "none" to keep the built-in list (github.com, npm, pypi, crates.io, etc.).
8. **Pin**: lock the plugin to its current SHA-256 so any tampering disables it? \`yes\` / \`no\`, default \`no\` for first-time setup.

## After collecting answers

1. Show the user a preview of the new options block before writing.
2. Read \`${configPath}\` with the \`read\` tool.
3. Locate the \`opencode-auto-guard\` entry in the \`plugins\` array and replace its \`options\` object. Preserve every other plugin and every other top-level key.
4. If pin was enabled, compute it now:
   - \`Get-FileHash "<plugin-dir>/src/index.ts" -Algorithm SHA256\`
   - \`Get-FileHash "<plugin-dir>/src/rules.ts" -Algorithm SHA256\`
   - Combined: \`[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("<index-hash>|<rules-hash>"))) -replace "-", ""\`
   - Prefix with \`sha256:\` and store as \`options.pin\`.
5. Write the file with the \`edit\` tool. Do not modify any other section.
6. Confirm to the user with a one-line summary of what changed and remind them to restart opencode (the plugin only re-reads options on startup).

If the user already has a \`pin\` set and wants to keep it, skip the recomputation. If they want to refresh it, run the calculation above regardless of the answer to Q8.`;
}

// ============== Secret patterns ==============

export const SECRET_PATTERNS: RegExp[] = [
  /gh[pousr]_[A-Za-z0-9]{36,}/g,
  /gho_[A-Za-z0-9]{36,}/g,
  /github_pat_[A-Za-z0-9_]{82}/g,
  /xox[bpars]-[A-Za-z0-9-]{10,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /ASIA[0-9A-Z]{16}/g,
  /arn:aws:[a-z0-9:-]*:[a-z0-9]*:[^\s"']{12,}/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(?:api[_-]?key|apikey|token|secret|password|bearer|authorization)\b["']?\s*[:=]\s*["']?[A-Za-z0-9_./+\-]{16,}/gi,
  /https?:\/\/[^\s/?#]*\?[^\s#]*(?:token|signature|api[_-]?key|access[_-]?token|sig)=[^&\s#]*/gi,
  /\b(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s:]+:[^\s@]+@[^\s/]+/gi,
];

// ============== Default protected paths and trusted domains ==============

export function defaultProtectedPaths(): string[] {
  const home = os.homedir();
  return [
    path.resolve(home, ".config/opencode/plugins/auto-guard.ts"),
    path.resolve(home, ".config/opencode/plugins/auto-guard-rules.ts"),
    path.resolve(home, ".config/opencode/opencode.jsonc"),
    path.resolve(home, ".config/opencode/opencode.json"),
    path.resolve(home, ".config/opencode/auto-permissions.json"),
  ];
}

export function defaultTrustedDomains(): string[] {
  return [
    "github.com",
    "gist.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "pkg.go.dev",
    "proxy.golang.org",
    "developer.mozilla.org",
    "stackoverflow.com",
    "opencode.ai",
    "anthropic.com",
    "openai.com",
    "googleapis.com",
    "docs.rs",
  ];
}

// ============== Pure utilities ==============

export function normalize(raw: string): string {
  return raw.replace(/\\/g, "/").toLowerCase().replace(/\s+/g, " ").trim();
}

export function unwrap(raw: string): string {
  let s = normalize(raw);

  // 1) Strip leading interpreter
  s = s.replace(
    /^(pwsh|powershell|pwsh\.exe|powershell\.exe|bash|bash\.exe|sh|sh\.exe|zsh|zsh\.exe|ksh|dash|cmd|cmd\.exe)\s+/,
    "",
  );

  // 2) Iteratively strip leading flags. Categories:
  //    a) Flag that CONSUMES its next token as value: -ExecutionPolicy, -File, ...
  //    b) Boolean PowerShell flag: -NoProfile, -NonInteractive, ...
  //    c) Flag that MARKS start of value (rest is the command): -Command, -EncodedCommand
  //    d) Short bash/sh flag: -c, -l, -lc, -lsa, etc.
  let prev = "";
  while (s !== prev) {
    prev = s;
    s = s.replace(
      /^-(?:ExecutionPolicy|File|WorkingDirectory|ConfigurationName|CustomPipeName|WindowStyle)\s+\S+\s+/i,
      "",
    );
    s = s.replace(/^-(?:NoProfile|NonInteractive|NoLogo|NoExit|MTA|STA)\s+/i, "");
    s = s.replace(/^-(?:Command|EncodedCommand)\s+/i, "");
    s = s.replace(/^-[a-zA-Z]{1,4}\s+/, "");
    s = s.replace(/^(\/c|\/k)\s+/, "");
  }

  s = s.replace(/^["'](.*)["']$/, "$1");

  return s.trim();
}

export function includesAny(hay: string, needles: string[]): string | undefined {
  return needles.find((n) => hay.includes(n));
}

export function isSafeSingle(s: string): boolean {
  if (includesAny(s, HARD_DENY) || includesAny(s, HARD_ASK)) return false;
  return SAFE_PREFIXES.some((p) => s === p.trim() || s.startsWith(p));
}

export function isSafe(normalizedInner: string): boolean {
  if (!normalizedInner) return false;
  const parts = normalizedInner.split(/\s*(;|&&|\|\||\|)\s*/).filter(Boolean);
  const frags = parts.filter((p) => !/^(;|&&|\|\||\|)$/.test(p));
  if (frags.length > 1) return frags.every(isSafeSingle);
  return isSafeSingle(normalizedInner);
}

// ============== Cached safe check ==============

export interface SafeCacheOptions {
  ttl?: number;
  max?: number;
}

// module-level LRU+TTL cache shared across all isSafeCached calls.
const safeCache = new Map<string, { result: boolean; expires: number }>();

// same result as the existing isSafe(command) but with a module-level
// LRU+TTL cache. cache is module-level and shared across calls.
export function isSafeCached(command: string, options?: SafeCacheOptions): boolean {
  const ttl = options?.ttl ?? 60_000;
  const max = options?.max ?? 1000;
  const key = shortHash(command);
  const now = Date.now();
  const hit = safeCache.get(key);
  if (hit && hit.expires > now) return hit.result;
  const result = isSafe(command);
  safeCache.set(key, { result, expires: now + ttl });
  // evict oldest insertion if over max
  while (safeCache.size > max) {
    const oldest = safeCache.keys().next().value;
    if (oldest === undefined) break;
    safeCache.delete(oldest);
  }
  return result;
}

export function redactSecrets(input: string): string {
  let out = input;
  for (const p of SECRET_PATTERNS) out = out.replace(p, "[REDACTED]");
  return out;
}

export function shortHash(s: string): string {
  return `sha256:${crypto.createHash("sha256").update(s).digest("hex").slice(0, 16)}`;
}

export function fullHash(s: string): string {
  return `sha256:${crypto.createHash("sha256").update(s).digest("hex")}`;
}

// ============== Path protection (cross-platform) ==============

function normPath(p: string): string {
  return p
    .replace(/[\\/]+/g, path.sep)
    .replace(/\/$/, "")
    .toLowerCase();
}

export function isProtectedPath(p: string, protectedPaths?: string[]): boolean {
  if (!p) return false;
  try {
    const resolved = path.resolve(p.replace(/\//g, path.sep));
    const r = normPath(resolved);
    const list = protectedPaths ?? defaultProtectedPaths();
    return list.some((pp) => {
      const n = normPath(pp);
      return r === n || r.startsWith(n + path.sep);
    });
  } catch {
    return false;
  }
}

// ============== URL trust check ==============

export function isTrustedUrl(url: string, trustedDomains?: string[]): boolean {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const list = trustedDomains ?? defaultTrustedDomains();
    return list.some((d) => host === d || host.endsWith(`.${d}`));
  } catch {
    return false;
  }
}

// ============== Fast classifier (no LLM) ==============

export type Decision = "allow" | "ask" | "deny";

export interface FastVerdict {
  decision: Decision;
  category: string;
  reason: string;
  confidence: number;
  source: "fast";
}

const FAST_CONFIDENCE = 0.99;

export function fastClassifyShell(rawCommand: string, agent?: string): FastVerdict | null {
  const inner = unwrap(rawCommand);
  if (!inner) return null;

  // HARD_DENY/HARD_ASK already handled by the permission hook; here we add
  // patterns the hook would miss otherwise.

  for (const p of OBFUSCATION) {
    if (p.test(inner)) {
      return {
        decision: "deny",
        category: "fast_obfuscation",
        reason: p.source ?? "obfuscation",
        confidence: FAST_CONFIDENCE,
        source: "fast",
      };
    }
  }

  for (const p of PIPE_TO_SHELL) {
    if (p.test(inner)) {
      return {
        decision: "deny",
        category: "fast_pipe_to_shell",
        reason: p.source ?? "pipe to shell",
        confidence: FAST_CONFIDENCE,
        source: "fast",
      };
    }
  }

  for (const p of DANGEROUS_RM) {
    if (p.test(inner)) {
      return {
        decision: "deny",
        category: "fast_dangerous_rm",
        reason: p.source ?? "dangerous rm",
        confidence: FAST_CONFIDENCE,
        source: "fast",
      };
    }
  }

  for (const p of FIND_EXEC) {
    if (p.test(inner)) {
      return {
        decision: "deny",
        category: "fast_find_exec",
        reason: p.source ?? "find/xargs exec",
        confidence: FAST_CONFIDENCE,
        source: "fast",
      };
    }
  }

  for (const p of TAR_CHECKPOINT) {
    if (p.test(inner)) {
      return {
        decision: "deny",
        category: "fast_tar_exec",
        reason: p.source ?? "tar exec",
        confidence: FAST_CONFIDENCE,
        source: "fast",
      };
    }
  }

  if (agent === "auto" && isSafe(inner)) {
    return {
      decision: "allow",
      category: "fast_safe",
      reason: "allowlist hit",
      confidence: FAST_CONFIDENCE,
      source: "fast",
    };
  }

  return null;
}

// ============== Decision merging ==============

const ORDER: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

export function worstDecision(a: Decision, b: Decision): Decision {
  return ORDER[a] >= ORDER[b] ? a : b;
}

// ============== Compact context guard skill ==============

/**
 * Stable identifier the plugin uses to invoke the skill via
 * `ctx.session.skill({ sessionID, id: "compact-context-guard" })` and to
 * register it via `ctx.skill.transform`. Keep in sync with
 * `agents/compact-context-guard.md`.
 */
export const COMPACT_CONTEXT_GUARD_SKILL_ID = "compact-context-guard";

/**
 * Default location the plugin dumps per-session conversation archives
 * and the agent writes refined compact documents to. Resolves to
 *   ~/.config/opencode/opencode-auto-guard/sessions/
 * matching the existing plugin convention.
 */
export function defaultCompactSessionsDir(): string {
  return path.resolve(os.homedir(), ".config/opencode/opencode-auto-guard/sessions");
}

/**
 * Stable identifier the plugin uses for the audit category when it
 * auto-creates the temp directory on startup. Kept here (alongside the
 * other category strings) so audit consumers can match on a single
 * constant instead of grepping for the literal.
 */
export const TMP_DIR_AUDIT_CATEGORY = "temp_dir_ready";

/**
 * Default scratch directory the auto agent can use without asking for
 * permission on every read/write. Resolves to
 *   ~/.config/opencode/opencode-auto-guard/tmp/
 *
 * The directory is intentionally NOT in the protected-paths list —
 * the guard considers it a known scratch area. The plugin creates it
 * at startup so the agent does not have to. Subdirectories inside it
 * are still subject to the regular per-action checks (self-protection,
 * shell classification, network egress, etc.) — only the TMP root
 * itself is granted the implicit "temp files live here" semantics.
 */
export function defaultTempDir(): string {
  return path.resolve(os.homedir(), ".config/opencode/opencode-auto-guard/tmp");
}

export interface CompactContextSkillOptions {
  /** Absolute base dir for session artifacts. Defaults to `~/.config/opencode/opencode-auto-guard/sessions`. */
  sessionsDir?: string;
  /** Session ID the skill is running against. Embedded in the prompt for traceability. */
  sessionID?: string;
  /** Token usage at the moment the guard fired, e.g. `"85000/200000"`. */
  tokensAtPause?: string;
  /** Fraction of the model context window reached, e.g. `"85%"`. */
  contextPct?: string;
  /** Absolute path to the raw conversation dump the plugin just wrote. */
  rawDumpPath?: string;
  /** ISO timestamp of when the guard fired. */
  triggeredAt?: string;
  /** Plugin version embedded in the compact template. */
  pluginVersion?: string;
}

/**
 * Build the prompt content for the `compact-context-guard` skill.
 *
 * The skill is invoked by the plugin when the context guard denies an
 * action because the session is running out of context. Its job is to
 * turn the current conversation into a small, well-structured markdown
 * document the user can hand to a fresh session later.
 *
 * The skill prompt is split into a fixed base structure (known to the
 * agent so it can keep filling it in across versions) and a variable
 * block describing the current invocation (paths, timestamps, token
 * counts). Pure so it can be unit-tested.
 */
export function buildCompactContextSkillPrompt(opts: CompactContextSkillOptions = {}): string {
  const sessionsDir = opts.sessionsDir ?? defaultCompactSessionsDir();
  const triggeredAt = opts.triggeredAt ?? new Date().toISOString();
  const sessionID = opts.sessionID ?? "<session-id>";
  const tokensAtPause = opts.tokensAtPause ?? "<tokens>/<limit>";
  const contextPct = opts.contextPct ?? "<pct>%";
  const rawDumpPath = opts.rawDumpPath ?? "<raw-dump-path>";
  const pluginVersion = opts.pluginVersion ?? "<plugin-version>";
  const compactPath = `${sessionsDir}/${sessionID}/compact-${stampForFilename(triggeredAt)}.md`;

  return `# compact-context-guard

The session context guard has paused this session because the model's context window is too full to safely keep going. The plugin has already:

1. Denied the action that crossed the threshold.
2. Dumped the full conversation history to a JSON file so you can read it without using more context.

Your job: turn that dump into a small, structured compact document the user can load into a fresh session later.

## What was paused

- Session ID: \`${sessionID}\`
- Triggered at: ${triggeredAt}
- Context at pause: ${contextPct} (${tokensAtPause} tokens)
- Reason: \`opencode-auto-guard\` \`context_limit\` denial

## Where the artifacts go

Base directory: \`${sessionsDir}\`

- Per-session subdir: \`${sessionsDir}/${sessionID}/\`
- Raw conversation dump (already written by the plugin): \`${rawDumpPath}\`
- Refined compact (you write this): \`${compactPath}\`

## What to do

1. \`read\` the raw dump at \`${rawDumpPath}\`. It is a JSON array of session messages (user, assistant, tool calls, etc.) in chronological order.
2. Parse out the meaningful content: the user's goal, the agent's plan, the key decisions, the files touched, and what is still pending.
3. \`write\` a refined compact document to \`${compactPath}\` following the **Compact document structure** below. Fill in every section; if a section truly has no content, write \`None.\` instead of leaving it empty so the next agent does not have to guess.
4. After writing, respond to the user with a one-line summary and the absolute path. Example: \`Compact saved to <path>. Open a fresh session and /load <path> to continue.\`
5. Do not run any further shell, edit, or webfetch actions. The guard has paused the session; respect that and end your turn.

## Compact document structure

Use this template verbatim for the section headings — the next agent will recognise them.

\`\`\`markdown
# Compact Session: <short title, derived from the user's first message>

> Compaction generated by \`opencode-auto-guard\` (compact-context-guard skill) on <iso timestamp>.
> Session ID: <session-id>
> Trigger: context guard paused session at <pct>% of model context window
> Tokens at pause: <tokens>/<limit>

## Original Goal

What the user originally asked for. Written as if the user is explaining it to a fresh agent. One short paragraph.

## Where We Are Now

- ✅ Done: <what has been completed>
- 🔄 In progress: <what is partially done>
- ❌ Blocked: <what is stuck and why>
- ⏭️ Next: <the very next concrete action>

## Key Decisions Made

1. **<decision>** — <rationale, why this choice over alternatives>
2. ...

## Files Touched

- \`<path/to/file>\` — <what changed and why>
- ...

## Pending Questions / Blockers

1. <question or blocker, written so the user can answer it without re-reading the whole session>
2. ...

## Recommended Next Steps

1. <concrete step the next agent should do first>
2. ...

## Context the Next Agent Needs

Files / URLs / docs / commands to read first to continue:
- \`<path>\` — <why>
- ...

## Environment Notes

- Model used: <provider/model>
- Branch / commit: <git rev-parse HEAD> if available
- Working directory: <pwd>
- Plugin version: \`${pluginVersion}\`
\`\`\`

## Rules

- Do not invent facts. If something is unknown, say so explicitly under **Pending Questions**.
- Do not include raw secret material. The raw dump is the source of truth; the compact is a summary safe to paste into a new session.
- Keep the compact under ~3 KB. The point is to recover context cheaply, not to mirror the dump.
- If the raw dump is empty or unreadable, write a minimal compact that says so under **Where We Are Now** and list what you can infer from the system prompt under **Original Goal**.
`;
}

/**
 * Filename-safe timestamp derived from an ISO string. Used to make
 * stable, sortable paths for raw dumps and compact documents.
 */
function stampForFilename(iso: string): string {
  // Strip characters Windows / POSIX both reject in filenames.
  return iso.replace(/[:.]/g, "-").replace(/Z$/, "Z");
}

/**
 * Build the **Compact document structure** template as a standalone
 * string. Exposed so tests can assert the headings and so other agents
 * (e.g. the user manually loading a compact) can render an empty
 * template.
 */
export function buildCompactDocumentTemplate(): string {
  return `# Compact Session: <short title, derived from the user's first message>

> Compaction generated by \`opencode-auto-guard\` (compact-context-guard skill) on <iso timestamp>.
> Session ID: <session-id>
> Trigger: context guard paused session at <pct>% of model context window
> Tokens at pause: <tokens>/<limit>

## Original Goal

<One short paragraph explaining what the user wanted.>

## Where We Are Now

- ✅ Done: <what has been completed>
- 🔄 In progress: <what is partially done>
- ❌ Blocked: <what is stuck and why>
- ⏭️ Next: <the very next concrete action>

## Key Decisions Made

1. **<decision>** — <rationale>
2. ...

## Files Touched

- \`<path/to/file>\` — <what changed and why>
- ...

## Pending Questions / Blockers

1. <question or blocker>
2. ...

## Recommended Next Steps

1. <concrete step>
2. ...

## Context the Next Agent Needs

- \`<path>\` — <why>
- ...

## Environment Notes

- Model used: <provider/model>
- Branch / commit: <git rev-parse HEAD if available>
- Working directory: <pwd>
- Plugin version: <opencode-auto-guard version>
`;
}

/**
 * Compute the per-session subdirectory the plugin uses for raw dumps
 * and the agent uses for the refined compact.
 */
export function sessionCompactDir(sessionsDir: string, sessionID: string): string {
  return path.join(sessionsDir, sessionID);
}

/**
 * Compute the path the plugin writes the raw conversation dump to
 * when the context guard fires. Filename-safe across platforms.
 */
export function rawDumpPath(sessionsDir: string, sessionID: string, isoTs: string): string {
  return path.join(
    sessionCompactDir(sessionsDir, sessionID),
    `raw-${stampForFilename(isoTs)}.json`,
  );
}

/**
 * Compute the path the agent writes the refined compact document to.
 */
export function compactDocumentPath(sessionsDir: string, sessionID: string, isoTs: string): string {
  return path.join(
    sessionCompactDir(sessionsDir, sessionID),
    `compact-${stampForFilename(isoTs)}.md`,
  );
}
