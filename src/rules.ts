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

export interface SessionState {
  denials: number;
  totalActions: number;
  startTime: number;
}

export function newSession(): SessionState {
  return { denials: 0, totalActions: 0, startTime: Date.now() };
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
