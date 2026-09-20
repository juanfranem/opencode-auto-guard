// tests/compact-test.ts
// Regression tests for the compact-context-guard skill and document
// template builders in rules.ts.
// Run with: bun src/tests/compact-test.ts

import * as path from "node:path";
import {
  buildCompactContextSkillPrompt,
  buildCompactDocumentTemplate,
  defaultCompactSessionsDir,
  defaultTempDir,
  TMP_DIR_AUDIT_CATEGORY,
  sessionCompactDir,
  rawDumpPath,
  compactDocumentPath,
  COMPACT_CONTEXT_GUARD_SKILL_ID,
  newSession,
  type CompactContextSkillOptions,
} from "../rules";

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

// =================== 1. Skill id and default dir ===================

section("Constants — skill id and default base dir");

ok(
  "skill id is stable and kebab-cased",
  COMPACT_CONTEXT_GUARD_SKILL_ID === "compact-context-guard",
);
const defaultDir = defaultCompactSessionsDir();
ok(
  "default sessions dir resolves under .config/opencode/opencode-auto-guard",
  defaultDir.endsWith(path.join(".config", "opencode", "opencode-auto-guard", "sessions")),
  `got: ${defaultDir}`,
);
ok("default sessions dir is absolute", path.isAbsolute(defaultDir), `got: ${defaultDir}`);

// =================== 1b. Temp dir ===================

section("Constants — temp dir for the auto agent scratch space");

const tmpDir = defaultTempDir();
ok(
  "defaultTempDir resolves under .config/opencode/opencode-auto-guard",
  tmpDir.endsWith(path.join(".config", "opencode", "opencode-auto-guard", "tmp")),
  `got: ${tmpDir}`,
);
ok("defaultTempDir is absolute", path.isAbsolute(tmpDir), `got: ${tmpDir}`);
ok("temp dir is sibling of sessions dir, not nested", !tmpDir.startsWith(defaultDir));
ok("temp dir is sibling of sessions dir, not parent", !defaultDir.startsWith(tmpDir));
ok("audit category constant is stable", TMP_DIR_AUDIT_CATEGORY === "temp_dir_ready");

// =================== 2. Path helpers ===================

section("Path helpers — pure, filename-safe, deterministic");

const sessionsDir = "/tmp/guard-sessions";
const sessionID = "ses_abc123";
const iso = "2026-09-20T13:45:01.123Z";

const expectedSessionDir = path.join(sessionsDir, sessionID);
ok(
  "sessionCompactDir joins correctly",
  sessionCompactDir(sessionsDir, sessionID) === expectedSessionDir,
);

const expectedRaw = path.join(expectedSessionDir, "raw-2026-09-20T13-45-01-123Z.json");
ok(
  "rawDumpPath uses filename-safe timestamp",
  rawDumpPath(sessionsDir, sessionID, iso) === expectedRaw,
  `got: ${rawDumpPath(sessionsDir, sessionID, iso)}`,
);

const expectedCompact = path.join(expectedSessionDir, "compact-2026-09-20T13-45-01-123Z.md");
ok(
  "compactDocumentPath uses filename-safe timestamp",
  compactDocumentPath(sessionsDir, sessionID, iso) === expectedCompact,
  `got: ${compactDocumentPath(sessionsDir, sessionID, iso)}`,
);

// Filename safety: no `:` or `.` (Windows-illegal chars).
const rawFilename = rawDumpPath(sessionsDir, sessionID, iso).split(path.sep).pop() ?? "";
ok("rawDumpPath filename has no colon", !rawFilename.includes(":"));
ok(
  "compactDocumentPath filename has no trailing dot before extension",
  !compactDocumentPath(sessionsDir, sessionID, iso).endsWith(".Z.md"),
);

// =================== 3. Skill prompt — defaults ===================

section("buildCompactContextSkillPrompt — default template");

const prompt = buildCompactContextSkillPrompt();

ok("prompt is non-empty", prompt.length > 500);
ok("uses stable skill id heading", prompt.includes("# compact-context-guard"));
ok("documents the plugin author", prompt.includes("opencode-auto-guard"));
ok("explains why it was triggered (context guard paused)", prompt.includes("context guard"));
ok("tells the agent to use the read tool", prompt.includes("`read`"));
ok("tells the agent to use the write tool", prompt.includes("`write`"));
ok("mentions raw dump artifact", prompt.includes("raw-"));
ok("embeds base structure heading", prompt.includes("## Compact document structure"));
ok("tells agent to end its turn after writing", prompt.toLowerCase().includes("end your turn"));
ok("forbids inventing facts", prompt.includes("Do not invent facts"));
ok("forbids raw secret material", prompt.includes("secret"));

const requiredHeadings = [
  "## Original Goal",
  "## Where We Are Now",
  "## Key Decisions Made",
  "## Files Touched",
  "## Pending Questions / Blockers",
  "## Recommended Next Steps",
  "## Context the Next Agent Needs",
  "## Environment Notes",
];
for (const h of requiredHeadings) {
  ok(`embedded template contains heading: ${h}`, prompt.includes(h));
}

// =================== 4. Skill prompt — custom options ===================

section("buildCompactContextSkillPrompt — uses custom options verbatim");

const customOpts: CompactContextSkillOptions = {
  sessionsDir: "/data/compacts",
  sessionID: "ses_DEAD_BEEF",
  tokensAtPause: "170000/200000",
  contextPct: "85%",
  rawDumpPath: "/data/compacts/ses_DEAD_BEEF/raw-2026-09-20T13-45-01-123Z.json",
  triggeredAt: "2026-09-20T13:45:01.123Z",
  pluginVersion: "9.9.9-test",
};
const custom = buildCompactContextSkillPrompt(customOpts);
const expectedRawDump = customOpts.rawDumpPath ?? "";

ok("uses custom sessionsDir", custom.includes("/data/compacts"));
ok("uses custom sessionID", custom.includes("ses_DEAD_BEEF"));
ok("uses custom tokensAtPause", custom.includes("170000/200000"));
ok("uses custom contextPct", custom.includes("85%"));
ok("uses custom rawDumpPath", custom.includes(expectedRawDump));
ok("uses custom triggeredAt", custom.includes("2026-09-20T13:45:01.123Z"));
ok("uses custom pluginVersion", custom.includes("9.9.9-test"));
ok(
  "computes compact path under sessionsDir/sessionID/",
  custom.includes("/data/compacts/ses_DEAD_BEEF/compact-2026-09-20T13-45-01-123Z.md"),
);

// =================== 5. Skill prompt — fallback defaults ===================

section("buildCompactContextSkillPrompt — fallback placeholders");

const minimal = buildCompactContextSkillPrompt({});
ok(
  "falls back to <session-id> when sessionID missing",
  minimal.includes("Session ID: `<session-id>`"),
);
ok(
  "falls back to <plugin-version> when version missing",
  minimal.includes("Plugin version: `<plugin-version>`"),
);
ok(
  "falls back to <tokens>/<limit> when tokens missing",
  minimal.includes("Tokens at pause: <tokens>/<limit>"),
);

// =================== 6. Standalone template ===================

section("buildCompactDocumentTemplate — standalone heading parity");

const tmpl = buildCompactDocumentTemplate();
for (const h of requiredHeadings) {
  ok(`template contains heading: ${h}`, tmpl.includes(h));
}
ok("template has the compact metadata blockquote", tmpl.includes("> Compaction generated by"));
ok("template is non-empty", tmpl.length > 200);

// =================== 7. SessionState — compact trigger flag ===================

section("SessionState — contextCompactTriggered flag");

const s = newSession();
ok("starts with contextCompactTriggered=false", s.contextCompactTriggered === false);
s.contextCompactTriggered = true;
ok("can be flipped to true", s.contextCompactTriggered === true);

// =================== Summary ===================

console.log("\n\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500");
console.log(`Tests: ${pass} pass / ${fail} fail`);
if (fail > 0) process.exit(1);
