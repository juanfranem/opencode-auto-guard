// tests/env-placeholder-test.ts
// Unit tests for `{env:VAR}` placeholder expansion in plugin options.
//
// Why this lives in its own file:
//   `expandEnvPlaceholder` is a tiny pure helper, but it's the bridge
//   between how OpenCode hands us options and how the plugin actually
//   uses them (e.g. the Jev fast-judge API key). Bugs here are silent:
//   the plugin would accept `{env:OPENCODE_ZEN_TOKEN}`, never resolve
//   it, and report `key=missing` without telling the user that the
//   placeholder was the problem. So we cover every shape and a few
//   regression cases that have bitten other tools.
//
// Run with: bun src/tests/env-placeholder-test.ts
//
// These tests intentionally mutate `process.env` to simulate the various
// states a user can be in. `withEnv()` snapshots the original state and
// restores it (or deletes what we added) when the callback returns, even
// if the callback throws.

import { expandEnvPlaceholder } from "../rules";

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

/**
 * Run a callback with a controlled `process.env` snapshot. We snapshot
 * the named keys, let the callback mutate them freely, then restore the
 * originals (or delete anything we added) so neither subsequent tests
 * nor the parent shell's process get polluted.
 */
function withEnv<T>(envSetup: Record<string, string | undefined>, fn: () => T): T {
  const KEYS = Object.keys(envSetup);
  const before: Record<string, string | undefined> = {};
  const had: Record<string, boolean> = {};
  for (const k of KEYS) {
    had[k] = k in process.env;
    before[k] = process.env[k];
    if (envSetup[k] === undefined) delete process.env[k];
    else process.env[k] = envSetup[k];
  }
  try {
    return fn();
  } finally {
    for (const k of KEYS) {
      if (had[k]) process.env[k] = before[k];
      else delete process.env[k];
    }
  }
}

// =================== 1. Plain string passthrough ===================

section("Plain string (no placeholder) returned as-is");

ok("literal-token -> same string", expandEnvPlaceholder("literal-token") === "literal-token");
ok(
  "anthropic/claude-sonnet-4-5 -> same string",
  expandEnvPlaceholder("anthropic/claude-sonnet-4-5") === "anthropic/claude-sonnet-4-5",
);
ok("empty string -> undefined", expandEnvPlaceholder("") === undefined);

// =================== 2. Non-string inputs ===================

section("Non-string inputs map to undefined");

ok("undefined -> undefined", expandEnvPlaceholder(undefined) === undefined);
// Cast around the type system to exercise runtime tolerance for callers
// that hand us something the type signature never promised to accept.
ok("null -> undefined", expandEnvPlaceholder(null as unknown as string) === undefined);
ok("number -> undefined", expandEnvPlaceholder(42 as unknown as string) === undefined);
ok("object -> undefined", expandEnvPlaceholder({ env: "VAR" } as unknown as string) === undefined);
ok("array -> undefined", expandEnvPlaceholder(["{env:VAR}"] as unknown as string) === undefined);

// =================== 3. {env:VAR} resolved ===================

section("{env:VAR} resolves to process.env.VAR");

withEnv({ OPENCODE_ZEN_TOKEN: "tok-1234" }, () => {
  ok("resolves to env value", expandEnvPlaceholder("{env:OPENCODE_ZEN_TOKEN}") === "tok-1234");
});

withEnv({ SOME_LONG_VAR_NAME_2: "value-2" }, () => {
  ok("long var name works", expandEnvPlaceholder("{env:SOME_LONG_VAR_NAME_2}") === "value-2");
});

withEnv({ lowercase_var: "lower-val" }, () => {
  ok("lowercase var works", expandEnvPlaceholder("{env:lowercase_var}") === "lower-val");
});

withEnv({ VAR_WITH_DIGITS_42: "v" }, () => {
  ok("vars may contain digits", expandEnvPlaceholder("{env:VAR_WITH_DIGITS_42}") === "v");
});

withEnv({ _UNDERSCORE: "u-val" }, () => {
  ok("leading underscore is allowed", expandEnvPlaceholder("{env:_UNDERSCORE}") === "u-val");
});

withEnv({ $DOLLAR: "d-val" }, () => {
  ok("leading dollar is allowed", expandEnvPlaceholder("{env:$DOLLAR}") === "d-val");
});

// =================== 4. {env:VAR} not set ===================

section("{env:VAR} where VAR is unset -> undefined");

withEnv({ DEFINITELY_NOT_SET_HERE: undefined }, () => {
  ok("unset var -> undefined", expandEnvPlaceholder("{env:DEFINITELY_NOT_SET_HERE}") === undefined);
});

withEnv({ EMPTY_VAR: "" }, () => {
  ok(
    "empty-string var -> undefined (avoid treating empty as a real token)",
    expandEnvPlaceholder("{env:EMPTY_VAR}") === undefined,
  );
});

// =================== 5. Malformed placeholders are left alone ===================

section("Malformed placeholders are passed through verbatim");

// Missing closing brace.
ok("{env:VAR (no close brace) is passthrough", expandEnvPlaceholder("{env:VAR") === "{env:VAR");
// Empty placeholder.
ok("{env:} is passthrough", expandEnvPlaceholder("{env:}") === "{env:}");
// Identifier must not start with a digit.
ok(
  "{env:1FOO} is passthrough (leading digit)",
  expandEnvPlaceholder("{env:1FOO}") === "{env:1FOO}",
);
// Whitespace is not allowed in the identifier portion.
ok(
  "spaces inside the placeholder are passthrough",
  expandEnvPlaceholder("{env: VAR }") === "{env: VAR }",
);
// Lowercased wrapper to make sure we didn't accidentally normalise.
ok(
  "{ENV:VAR} is passthrough (uppercase wrapper)",
  expandEnvPlaceholder("{ENV:VAR}") === "{ENV:VAR}",
);
// Garbage that happens to look like a placeholder prefix.
ok(
  "value that contains {env:…} mid-string is passthrough",
  expandEnvPlaceholder("cmd --arg {env:FOO} --other") === "cmd --arg {env:FOO} --other",
);

// =================== 6. CLI override precedence (sanity) ===================

section("Live env value, not a cached one");

withEnv({ OPENCODE_ZEN_TOKEN: "fresh-token" }, () => {
  const got = expandEnvPlaceholder("{env:OPENCODE_ZEN_TOKEN}");
  ok("matches env value at call time", got === "fresh-token");
});
withEnv({ OPENCODE_ZEN_TOKEN: "later-token" }, () => {
  const got = expandEnvPlaceholder("{env:OPENCODE_ZEN_TOKEN}");
  ok("matches the *current* env value, not a cached one", got === "later-token");
});

// =================== Summary ===================

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
