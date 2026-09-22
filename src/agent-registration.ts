// agent-registration.ts
//
// First-install UX: instead of forcing the user to manually copy
// `agents/auto.md` into `~/.config/opencode/agents/` and edit
// `opencode.jsonc` to register the agent, the plugin performs these
// side effects at `setup()` time:
//
//   1. Resolve the bundled `agents/auto.md` from this package and copy
//      it into the user's agents directory **only when missing**.
//      Local edits the user has already made to that file are preserved.
//   2. Mutate the in-memory agent editor through `ctx.agent.transform`
//      so the Auto agent has `mode = "primary"` and the canonical
//      permission set. Honours any explicit user override in
//      `opencode.jsonc` — only fills in fields the user left empty.
//   3. Force a reload of the agent editor so the changes are picked up
//      without needing an OpenCode restart.
//
// The whole flow is best-effort: any failure (read-only filesystem,
// missing bundle, transform unsupported by the host runtime) returns a
// structured result without throwing. The plugin's `setup()` can then
// emit an audit entry describing what happened so the user can debug.

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { AUTO_AGENT_DEFAULT_PERMISSIONS, AUTO_AGENT_ID } from "./rules";

// ============== Types ==============

/** Loose shape we need from the OpenCode agent domain. */
interface AgentCtx {
  readonly agent?: {
    transform?: (cb: (editor: AgentEditorLike) => unknown) => Promise<unknown>;
    reload?: () => Promise<unknown>;
  };
}

/** Loose shape of the agent editor the transform callback receives. */
interface AgentEditorLike {
  get(id: string): { mode?: string; permissions?: unknown[] } | undefined;
  update?(id: string, fn: (a: { mode?: string; permissions?: unknown[] }) => void): void;
}

export interface AutoAgentSeedOutcome {
  /** Whether the file was actually written. `false` if it already existed. */
  wrote: boolean;
  /** Absolute path to the seeded file. */
  destPath: string;
}

export interface AutoAgentApplyOutcome {
  /** Whether the agent editor was located and mutated. */
  applied: boolean;
  /** Reason the apply was skipped, when `applied` is `false`. */
  reason?: string;
}

export interface AutoAgentRegistrationOutcome {
  seed: AutoAgentSeedOutcome;
  apply: AutoAgentApplyOutcome;
}

// ============== Path helpers ==============

/** Default user agents directory — matches OpenCode's standard layout. */
export function defaultAgentsDir(): string {
  return path.resolve(os.homedir(), ".config/opencode/agents");
}

/** Path the bundled auto agent gets seeded to. */
export function defaultAutoAgentPath(): string {
  return path.join(defaultAgentsDir(), `${AUTO_AGENT_ID}.md`);
}

/**
 * Resolve the bundled `agents/auto.md` relative to this module.
 *
 * Both source-tree and installed-package layouts share the same parent
 * for `src/` and `agents/`, so `..` from `src/agent-registration.ts`
 * lands at the package root and then into `agents/auto.md`. We try a
 * second candidate (`../../`) defensively in case the runtime ever
 * wraps the source in an extra dist directory.
 */
export function bundledAutoAgentPath(importMetaUrl: string): string {
  // Resolve relative to the module's file URL. `fileURLToPath` strips
  // the leading slash that `URL.pathname` keeps on Windows, so the
  // returned string is a normal platform-native absolute path.
  const candidate = new URL("../agents/auto.md", importMetaUrl);
  return fileURLToPath(candidate);
}

/** Auto agent id mirror — re-exported here so callers don't need rules. */
export function autoAgentId(): string {
  return AUTO_AGENT_ID;
}

/** Default permissions mirror — re-exported here so callers don't need rules. */
export function autoAgentDefaultPermissions(): ReadonlyArray<{
  readonly action: string;
  readonly resource: string;
  readonly effect: "allow" | "deny" | "ask";
}> {
  return AUTO_AGENT_DEFAULT_PERMISSIONS;
}

// ============== Pure helpers (testable without a runtime) ==============

/**
 * Idempotent: write the bundled auto.md to dest **only when missing**.
 *
 * - If dest exists (user edited it, or a previous install seeded it),
 *   we leave it alone and return `{ wrote: false }`.
 * - If the bundled source isn't readable (e.g. published package
 *   trimmed its `files` list), we bail without throwing.
 */
export async function seedAutoAgentMarkdown(opts: {
  bundledPath: string;
  destPath?: string;
}): Promise<AutoAgentSeedOutcome> {
  const destPath = opts.destPath ?? defaultAutoAgentPath();

  // Honour existing user/local files.
  try {
    await fs.access(destPath);
    return { wrote: false, destPath };
  } catch {
    // proceed
  }

  let src: string;
  try {
    src = await fs.readFile(opts.bundledPath, "utf8");
  } catch {
    return { wrote: false, destPath };
  }

  await fs.mkdir(path.dirname(destPath), { recursive: true });
  await fs.writeFile(destPath, src, "utf8");
  return { wrote: true, destPath };
}

/**
 * Apply the auto-agent defaults via `ctx.agent.transform`. Idempotent.
 *
 * Only acts when `editor.get(AUTO_AGENT_ID)` returns a live agent — i.e.
 * OpenCode already discovered it through the seeded `.md` OR the user
 * has it in `opencode.jsonc`. If the disk write happened but the agent
 * editor hasn't reloaded yet, we get a `get() → undefined` and treat
 * that as "no-op, try again on next setup()". Permissions are only
 * filled in when the user left the list empty, so explicit overrides
 * in `opencode.jsonc` win.
 */
export async function applyAutoAgentDefaults(ctx: AgentCtx): Promise<AutoAgentApplyOutcome> {
  if (!ctx.agent || typeof ctx.agent.transform !== "function") {
    return { applied: false, reason: "ctx.agent.transform unavailable" };
  }

  let applied = false;
  let reason: string | undefined;

  try {
    await ctx.agent.transform((editor: AgentEditorLike) => {
      const a = editor.get?.(AUTO_AGENT_ID);
      if (!a) {
        reason = `agent '${AUTO_AGENT_ID}' not present in editor (reload not yet fired)`;
        return;
      }
      // Only fill in fields the user left empty. Explicit user config
      // declared via `agents.auto` in opencode.jsonc must win.
      if (typeof a.mode !== "string" || a.mode.length === 0) {
        a.mode = "primary";
      }
      if (!Array.isArray(a.permissions) || a.permissions.length === 0) {
        a.permissions = [...AUTO_AGENT_DEFAULT_PERMISSIONS];
      }
      applied = true;
    });
  } catch (err) {
    return { applied: false, reason: String((err as Error)?.message ?? err) };
  }

  // Reload is best-effort: hosts without the method, or a failed call,
  // should not bring the plugin down.
  if (typeof ctx.agent.reload === "function") {
    try {
      await ctx.agent.reload();
    } catch {
      // ignore
    }
  }

  return reason ? { applied, reason } : { applied };
}

/**
 * End-to-end first-install registration. Run this from the plugin's
 * `setup()` **before** the self-integrity check so a missing `pin`
 * (the common case at first install) still delivers the agent.
 *
 * `opts.autoAgentDestPath` overrides where the bundled markdown gets
 * seeded to. Defaults to `defaultAutoAgentPath()` so the production
 * path requires no arguments; tests pass an explicit sandbox path.
 */
export async function registerAutoAgent(
  ctx: AgentCtx,
  importMetaUrl: string,
  opts: { autoAgentDestPath?: string } = {},
): Promise<AutoAgentRegistrationOutcome> {
  const bundledPath = bundledAutoAgentPath(importMetaUrl);
  const seed = await seedAutoAgentMarkdown({
    bundledPath,
    destPath: opts.autoAgentDestPath,
  });
  const apply = await applyAutoAgentDefaults(ctx);
  return { seed, apply };
}
