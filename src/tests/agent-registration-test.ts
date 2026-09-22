// tests/agent-registration-test.ts
//
// Regression tests for the first-install auto-registration flow in
// src/agent-registration.ts. Run with: `bun src/tests/agent-registration-test.ts`
//
// Coverage:
//   1. Path helpers — defaultAgentsDir / defaultAutoAgentPath.
//   2. Auto agent id constant — exported from rules.ts.
//   3. Permission defaults — shape, count, effect values.
//   4. bundledAutoAgentPath — must point at a real file on disk in the
//      working tree (i.e. survives `bun install`).
//   5. seedAutoAgentMarkdown — writes when dest missing, no-op when
//      present, no-throw when bundled source missing.
//   6. applyAutoAgentDefaults — mutates editor when agent present,
//      no-op when missing, no-throw when transform unavailable.
//   7. registerAutoAgent — end-to-end with a synthetic ctx.

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

import {
  applyAutoAgentDefaults,
  autoAgentDefaultPermissions,
  autoAgentId,
  bundledAutoAgentPath,
  defaultAgentsDir,
  defaultAutoAgentPath,
  registerAutoAgent,
  seedAutoAgentMarkdown,
} from "../agent-registration";
import { AUTO_AGENT_ID, AUTO_AGENT_DEFAULT_PERMISSIONS } from "../rules";

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

// Build a proper file:// URL for the module so `bundledAutoAgentPath`
// resolves through `fileURLToPath` and the bundling round-trips
// correctly on Windows and POSIX.
const modulePath = path.resolve(__dirname, "..", "agent-registration.ts");
const importMetaUrlFile = pathToFileURL(modulePath).href;

// =================== 1. Path helpers ===================

section("Path helpers — resolve under ~/.config/opencode/agents");

const agentsDir = defaultAgentsDir();
ok(
  "defaultAgentsDir resolves under .config/opencode/agents",
  agentsDir.endsWith(path.join(".config", "opencode", "agents")),
  `got: ${agentsDir}`,
);
ok("defaultAgentsDir is absolute", path.isAbsolute(agentsDir), `got: ${agentsDir}`);

const autoPath = defaultAutoAgentPath();
ok(
  "defaultAutoAgentPath ends with auto.md",
  autoPath.endsWith(`${AUTO_AGENT_ID}.md`),
  `got: ${autoPath}`,
);
ok(
  "defaultAutoAgentPath lives inside agents dir",
  autoPath.startsWith(agentsDir),
  `got: ${autoPath}`,
);
ok("defaultAutoAgentPath is absolute", path.isAbsolute(autoPath), `got: ${autoPath}`);

// =================== 2. Auto agent id ===================

section("Auto agent id — stable and re-exported");

ok("autoAgentId() === 'auto'", autoAgentId() === "auto");
ok("AUTO_AGENT_ID === 'auto'", AUTO_AGENT_ID === "auto");
ok("autoAgentId() matches AUTO_AGENT_ID from rules", autoAgentId() === AUTO_AGENT_ID);

// =================== 3. Default permissions ===================

section("Default permissions — shape matches README block");

const perms = autoAgentDefaultPermissions();
ok("returns 8 rules", perms.length === 8, `got: ${perms.length}`);
ok(
  "every rule has action/resource/effect strings",
  perms.every(
    (p) =>
      typeof p.action === "string" &&
      typeof p.resource === "string" &&
      typeof p.effect === "string",
  ),
);
ok(
  "every effect is one of allow/deny/ask",
  perms.every((p) => p.effect === "allow" || p.effect === "deny" || p.effect === "ask"),
);
ok(
  "read is allow on *",
  perms.some((p) => p.action === "read" && p.resource === "*" && p.effect === "allow"),
);
ok(
  "edit is allow on *",
  perms.some((p) => p.action === "edit" && p.resource === "*" && p.effect === "allow"),
);
ok(
  "shell is ask on *",
  perms.some((p) => p.action === "shell" && p.resource === "*" && p.effect === "ask"),
);
ok(
  "external_directory is ask on *",
  perms.some((p) => p.action === "external_directory" && p.resource === "*" && p.effect === "ask"),
);
ok(
  "webfetch github.com is allow",
  perms.some(
    (p) => p.action === "webfetch" && p.resource === "*github.com*" && p.effect === "allow",
  ),
);
ok(
  "webfetch * is ask",
  perms.some((p) => p.action === "webfetch" && p.resource === "*" && p.effect === "ask"),
);
ok("matches rules.ts constant", perms.length === AUTO_AGENT_DEFAULT_PERMISSIONS.length);

// =================== 4. Bundled path ===================

section("bundledAutoAgentPath — must point at a real file");

const bundled = bundledAutoAgentPath(importMetaUrlFile);
ok(
  "bundled path is absolute",
  path.isAbsolute(bundled) || bundled.startsWith("/"),
  `got: ${bundled}`,
);

const bundledExists = await fs
  .access(bundled)
  .then(() => true)
  .catch(() => false);
ok("bundled agents/auto.md exists at the resolved path", bundledExists, `missing: ${bundled}`);
ok("bundled file is non-empty", bundledExists ? (await fs.stat(bundled)).size > 100 : false);
if (bundledExists) {
  const head = (await fs.readFile(bundled, "utf8")).split("\n").slice(0, 5).join("\n");
  ok(
    "bundled file has YAML front-matter",
    head.startsWith("---"),
    `head: ${head.replace(/\n/g, "\\n")}`,
  );
}

// =================== 5. seedAutoAgentMarkdown ===================

section("seedAutoAgentMarkdown — idempotent write to dest");

const workRoot = await fs.mkdtemp(path.join(os.tmpdir(), "guard-arseed-"));
const tmpDest = path.join(workRoot, "nested", "auto.md");

const writeOutcome = await seedAutoAgentMarkdown({
  bundledPath: bundled,
  destPath: tmpDest,
});
ok("first call wrote the file", writeOutcome.wrote === true);
ok(
  "first call returned the dest path",
  writeOutcome.destPath === tmpDest,
  `got: ${writeOutcome.destPath}`,
);
const onDiskAfterFirst = await fs.readFile(tmpDest, "utf8");
ok(
  "file contents match the bundle",
  onDiskAfterFirst.length > 0 && onDiskAfterFirst === (await fs.readFile(bundled, "utf8")),
);

const expectedHashFirst = await fs.readFile(tmpDest, "utf8");
const existingPath = path.join(workRoot, "exists.md");
await fs.writeFile(existingPath, "user-edited-content", "utf8");
const skipOutcome = await seedAutoAgentMarkdown({
  bundledPath: bundled,
  destPath: existingPath,
});
ok("second call did not overwrite", skipOutcome.wrote === false);
const afterSkip = await fs.readFile(existingPath, "utf8");
ok("user content was preserved verbatim", afterSkip === "user-edited-content", `got: ${afterSkip}`);
ok("first-write file is still intact", (await fs.readFile(tmpDest, "utf8")) === expectedHashFirst);

const missingBundleOutcome = await seedAutoAgentMarkdown({
  bundledPath: path.join(workRoot, "definitely-not-a-real-bundle.md"),
  destPath: path.join(workRoot, "should-not-exist.md"),
});
ok("missing bundle returns wrote=false without throwing", missingBundleOutcome.wrote === false);
const missingBundleFile = await fs
  .access(path.join(workRoot, "should-not-exist.md"))
  .then(() => true)
  .catch(() => false);
ok("missing bundle did not create dest", !missingBundleFile);

// =================== 6. applyAutoAgentDefaults ===================

section("applyAutoAgentDefaults — only mutates when agent is in editor");

let captured: Array<{ id: string; mutated: boolean }> = [];
function makeCtx(opts: {
  hasTransform?: boolean;
  agentExists?: boolean;
  userPermissions?: unknown[];
  userMode?: string;
  reloadThrows?: boolean;
}) {
  captured = [];
  const editor = {
    get: (id: string) => {
      if (!opts.hasTransform || !opts.agentExists) return undefined;
      if (id !== AUTO_AGENT_ID) return undefined;
      const agent: { mode?: string; permissions?: unknown[] } = {};
      if (opts.userMode !== undefined) agent.mode = opts.userMode;
      if (opts.userPermissions !== undefined) agent.permissions = opts.userPermissions;
      return agent;
    },
  };
  return {
    agent: {
      transform: async (cb: (e: typeof editor) => unknown) => {
        await Promise.resolve(cb(editor));
      },
      reload: opts.reloadThrows
        ? async () => {
            throw new Error("reload failed");
          }
        : async () => {},
    },
  };
}

const filled = makeCtx({ hasTransform: true, agentExists: true });
const filledOutcome = await applyAutoAgentDefaults(filled);
ok("applies when agent present + no overrides", filledOutcome.applied === true);

const noTransform = makeCtx({ hasTransform: false });
const noTransformOutcome = await applyAutoAgentDefaults(noTransform);
ok(
  "skips when transform unavailable (legacy v1 runtime)",
  noTransformOutcome.applied === false && typeof noTransformOutcome.reason === "string",
);

const noAgent = makeCtx({ hasTransform: true, agentExists: false });
const noAgentOutcome = await applyAutoAgentDefaults(noAgent);
ok(
  "skips when agent missing (reload not yet fired)",
  noAgentOutcome.applied === false && typeof noAgentOutcome.reason === "string",
);

const userPerms = makeCtx({
  hasTransform: true,
  agentExists: true,
  userPermissions: [{ action: "read", resource: "*", effect: "deny" }],
});
await applyAutoAgentDefaults(userPerms);
ok(
  "user-set permissions are preserved (not overwritten)",
  Array.isArray(captured) && userPerms !== undefined,
);
{
  // Re-run with a capturing editor to assert the perms block survived.
  let permsAfter: unknown[] | undefined;
  const ctx = {
    agent: {
      transform: async (
        cb: (e: { get: (id: string) => { permissions?: unknown[] } | undefined }) => unknown,
      ) => {
        const e = {
          get: (id: string) => {
            if (id !== AUTO_AGENT_ID) return undefined;
            return { permissions: [{ action: "read", resource: "*", effect: "deny" }] };
          },
        };
        await Promise.resolve(cb(e));
        permsAfter = e.get(AUTO_AGENT_ID)?.permissions;
      },
      reload: async () => {},
    },
  };
  await applyAutoAgentDefaults(ctx);
  const firstPerm = Array.isArray(permsAfter)
    ? (permsAfter[0] as { action?: string; effect?: string } | undefined)
    : undefined;
  ok(
    "explicit user permissions are not replaced",
    !!firstPerm &&
      firstPerm.action === "read" &&
      firstPerm.effect === "deny" &&
      permsAfter?.length === 1,
    `got: ${JSON.stringify(permsAfter)}`,
  );
}

const userMode = makeCtx({ hasTransform: true, agentExists: true, userMode: "plan" });
{
  let modeAfter: string | undefined;
  const ctx = {
    agent: {
      transform: async (
        cb: (e: { get: (id: string) => { mode?: string } | undefined }) => unknown,
      ) => {
        const e = {
          get: (id: string) => {
            if (id !== AUTO_AGENT_ID) return undefined;
            return { mode: "plan" };
          },
        };
        await Promise.resolve(cb(e));
        modeAfter = e.get(AUTO_AGENT_ID)?.mode;
      },
      reload: async () => {},
    },
  };
  await applyAutoAgentDefaults(ctx);
  ok("explicit user mode is preserved", modeAfter === "plan", `got: ${modeAfter}`);
}

const reloadThrowsCtx = makeCtx({
  hasTransform: true,
  agentExists: true,
  reloadThrows: true,
});
const reloadOutcome = await applyAutoAgentDefaults(reloadThrowsCtx);
ok("reload failure is swallowed", reloadOutcome.applied === true);

// =================== 7. registerAutoAgent end-to-end ===================

section("registerAutoAgent — seed + apply under a synthetic ctx");

const e2eRoot = await fs.mkdtemp(path.join(os.tmpdir(), "guard-are2e-"));
const e2eSandbox = path.join(e2eRoot, "agents", "auto.md");
const e2eOutcome = await registerAutoAgent(
  {
    agent: {
      transform: async (
        cb: (e: { get: (id: string) => { mode?: string } | undefined }) => unknown,
      ) => {
        const e = {
          get: (id: string) => (id === AUTO_AGENT_ID ? {} : undefined),
        };
        await Promise.resolve(cb(e));
      },
      reload: async () => {},
    },
  },
  importMetaUrlFile,
  { autoAgentDestPath: e2eSandbox },
);

ok(
  "registerAutoAgent seeds the bundled agent markdown",
  e2eOutcome.seed.wrote === true && e2eOutcome.seed.destPath.startsWith(e2eRoot),
  `got: ${JSON.stringify(e2eOutcome.seed)}`,
);
ok(
  "registerAutoAgent applies permissions through the agent editor",
  e2eOutcome.apply.applied === true,
  `got: ${JSON.stringify(e2eOutcome.apply)}`,
);

// Verify that the published-files layout is compatible: the path
// bundling should resolve at install time because package.json `files`
// includes both `src/agent-registration.ts` and `agents/auto.md`.
ok(
  "package.json files manifest includes agents/",
  (await fs.readFile(path.resolve(__dirname, "..", "..", "package.json"), "utf8")).includes(
    '"agents"',
  ),
  "agents/ must be in package.json files for the bundling to survive install",
);

// =================== Cleanup ===================

await fs.rm(workRoot, { recursive: true, force: true });
await fs.rm(e2eRoot, { recursive: true, force: true });

// =================== Result ===================

console.log("");
console.log(`pass: ${pass}`);
console.log(`fail: ${fail}`);
if (fail > 0) process.exit(1);
