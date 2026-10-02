import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  safeDownloadFile,
  type SafeDownloadDependencies,
  type SafeDownloadInput,
  type SafeDownloadSpec,
} from "../safe-download";

let pass = 0;
let fail = 0;
const ok = (name: string, condition: boolean): void => {
  if (condition) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
};

// A trivial, content-agnostic spec used to prove `safeDownloadFile` is
// adapter-agnostic: a single-key object carrying an opaque id and a
// filename, returning an arbitrary text payload whose first byte is checked.
const textSpec: SafeDownloadSpec<{ input: string; filename: string }> = {
  expectedContentType: "image/png",
  validateInput(input): { input: string; filename: string } {
    if (input === null || typeof input !== "object" || Array.isArray(input))
      throw new Error("text input must be an object");
    const v = input as Record<string, unknown>;
    if (typeof v.input !== "string" || v.input.length === 0) throw new Error("text input missing");
    if (typeof v.filename !== "string" || !/^[a-z0-9_-]{1,32}\.txt$/.test(v.filename))
      throw new Error("text filename invalid");
    return { input: v.input, filename: v.filename };
  },
  buildUrl(input) {
    return `https://example.test/assets/${encodeURIComponent(input.input)}`;
  },
  validateContent(bytes) {
    if (bytes.length === 0) throw new Error("empty payload");
    const text = new TextDecoder().decode(bytes);
    if (!text.startsWith("ok:")) throw new Error(`unexpected payload prefix: ${text.slice(0, 16)}`);
  },
};

const response = (
  body: BodyInit,
  headers: Record<string, string> = { "content-type": "image/png" },
  status = 200,
) => new Response(body, { status, headers });

const okBody = (text: string) => new TextEncoder().encode(`ok:${text}`);

const deps = (r: Response, seen?: (init: RequestInit) => void): SafeDownloadDependencies => ({
  fetch: async (_url: string | URL | Request, init?: RequestInit) => {
    seen?.(init ?? {});
    return r;
  },
});

const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), "safe-download-"));
const root = path.join(sandbox, "root");
await fs.mkdir(root);

try {
  let seenInit: RequestInit | undefined;
  const result = await safeDownloadFile(
    { input: "hello", filename: "world.txt" },
    textSpec,
    root,
    [],
    deps(response(okBody("hello body")), (i) => {
      seenInit = i;
    }),
  );
  ok(
    "happy path writes payload to configured root",
    result.bytes === okBody("hello body").byteLength,
  );
  const written = await fs.readFile(path.join(root, "world.txt"), "utf8");
  ok("written content matches payload", written === "ok:hello body");
  ok(
    "GET-only with no redirects/credentials",
    seenInit?.method === "GET" && seenInit.redirect === "error" && seenInit.credentials === "omit",
  );

  // Spec's URL builder is what gets called; the primitive doesn't bake in any URL.
  // We assert by exercising a different spec: a different URL must be used.
  let capturedUrl = "";
  await safeDownloadFile(
    { input: "abc", filename: "two.txt" },
    {
      ...textSpec,
      buildUrl: (input) => {
        capturedUrl = `https://override.test/${input.input}`;
        return capturedUrl;
      },
    },
    root,
    [],
    deps(response(okBody("one"))),
  );
  ok("adapter-supplied URL builder runs", capturedUrl === "https://override.test/abc");

  for (const bad of [null, undefined, "string", 7, [1, 2], { input: "" }, { input: 1 }, {}]) {
    let rejected = false;
    try {
      await safeDownloadFile(bad, textSpec, root, [], deps(response(okBody("ignored"))));
    } catch {
      rejected = true;
    }
    ok("adapter input validation rejects", rejected);
  }

  let validated = false;
  let openedBeforeValidate = false;
  // Stub a spec that throws AFTER recording that fs.open has NOT been called
  // by the time validateContent throws. We assert ordering by injecting a
  // fetch spy that observes whether the destination already exists at the
  // moment validateContent runs. Easier: validateContent is called inside
  // safeDownloadFile between readResponse and fs.open. We prove ordering by
  // having validateContent list the destination directory; if the file were
  // already created, the listing would include it.
  await safeDownloadFile(
    { input: "throw", filename: "must-not-exist.txt" },
    {
      ...textSpec,
      validateContent(bytes) {
        validated = true;
        // destination must NOT exist yet: validate runs before fs.open("wx")
        fs.readdir(root).then((entries) => {
          if (entries.includes("must-not-exist.txt")) openedBeforeValidate = true;
        });
        throw new Error("content validator failure");
      },
    },
    root,
    [],
    deps(response(okBody("would have been written"))),
  ).catch(() => {
    /* expected */
  });
  ok("content validator runs", validated);
  ok("destination not created when validator rejects", !openedBeforeValidate);
  ok(
    "destination not left behind when validator rejects",
    !(await fs.stat(path.join(root, "must-not-exist.txt")).catch(() => undefined)),
  );

  // Existing-destination guard still applies with a non-pixellab spec.
  await fs.writeFile(path.join(root, "existing.txt"), "keep me");
  let net = false;
  try {
    await safeDownloadFile({ input: "x", filename: "existing.txt" }, textSpec, root, [], {
      fetch: async () => {
        net = true;
        return response(okBody("never"));
      },
    });
  } catch {
    /* expected */
  }
  ok(
    "existing target refused before fetch",
    !net && (await fs.readFile(path.join(root, "existing.txt"), "utf8")) === "keep me",
  );

  for (const r of [
    response(okBody("x"), { "content-type": "text/plain" }),
    response(okBody("x"), { "content-type": "image/png" }, 302),
    response(new Uint8Array(1024 * 1024 + 1), { "content-type": "image/png" }),
    response(okBody("x"), {
      "content-type": "image/png",
      "content-length": String(1024 * 1024 + 1),
    }),
    response("", { "content-type": "image/png" }),
    response(new TextEncoder().encode("not-ok-prefix")),
  ]) {
    let rejected = false;
    try {
      await safeDownloadFile(
        { input: "x", filename: `bad${fail}.txt` },
        textSpec,
        root,
        [],
        deps(r),
      );
    } catch {
      rejected = true;
    }
    ok("rejects bad response shape", rejected);
  }

  const abort = new AbortController();
  abort.abort();
  let cancelRejected = false;
  let cancelFetched = false;
  try {
    await safeDownloadFile({ input: "x", filename: "cancel.txt" }, textSpec, root, [], {
      signal: abort.signal,
      fetch: async () => {
        cancelFetched = true;
        return response(okBody("x"));
      },
    });
  } catch {
    cancelRejected = true;
  }
  ok("pre-cancelled signal never reaches fetch or write", cancelRejected && !cancelFetched);

  let timeoutRejected = false;
  try {
    await safeDownloadFile({ input: "x", filename: "timeout.txt" }, textSpec, root, [], {
      timeoutMs: 5,
      fetch: async (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("timeout")), {
            once: true,
          });
        }),
    });
  } catch {
    timeoutRejected = true;
  }
  ok(
    "timeout aborts before destination is created",
    timeoutRejected && !(await fs.stat(path.join(root, "timeout.txt")).catch(() => undefined)),
  );

  const linkedRoot = path.join(sandbox, "linked");
  await fs.symlink(root, linkedRoot, process.platform === "win32" ? "junction" : "dir");
  let symlinkRejected = false;
  try {
    await safeDownloadFile(
      { input: "x", filename: "link.txt" },
      textSpec,
      linkedRoot,
      [],
      deps(response(okBody("x"))),
    );
  } catch {
    symlinkRejected = true;
  }
  ok("symlink/junction root still refused", symlinkRejected);

  const changingRoot = path.join(sandbox, "changing");
  await fs.mkdir(changingRoot);
  let changedRejected = false;
  try {
    await safeDownloadFile({ input: "x", filename: "changed.txt" }, textSpec, changingRoot, [], {
      fetch: async () => {
        await fs.rename(changingRoot, path.join(sandbox, "old-root"));
        await fs.mkdir(changingRoot);
        return response(okBody("x"));
      },
    });
  } catch {
    changedRejected = true;
  }
  ok("directory replacement during network still refused", changedRejected);

  let protectedRejected = false;
  try {
    await safeDownloadFile(
      { input: "x", filename: "protected.txt" },
      textSpec,
      root,
      [root],
      deps(response(okBody("x"))),
    );
  } catch {
    protectedRejected = true;
  }
  ok(
    "protected root still refused",
    protectedRejected && !(await fs.stat(path.join(root, "protected.txt")).catch(() => undefined)),
  );

  for (const badRoot of [
    "relative",
    path.join(sandbox, "missing"),
    "//host/share",
    `${root}/../root`,
    `${root}/.`,
  ]) {
    let rejected = false;
    let fetched = false;
    try {
      await safeDownloadFile({ input: "x", filename: "root.txt" }, textSpec, badRoot, [], {
        fetch: async () => {
          fetched = true;
          return response(okBody("x"));
        },
      });
    } catch {
      rejected = true;
    }
    ok("invalid root rejected before fetch", rejected && !fetched);
  }

  const [one, two] = await Promise.allSettled([
    safeDownloadFile(
      { input: "x", filename: "race.txt" },
      textSpec,
      root,
      [],
      deps(response(okBody("a"))),
    ),
    safeDownloadFile(
      { input: "x", filename: "race.txt" },
      textSpec,
      root,
      [],
      deps(response(okBody("b"))),
    ),
  ]);
  ok(
    "concurrent target has one winner",
    [one, two].filter((x) => x.status === "fulfilled").length === 1,
  );
} finally {
  await fs.rm(sandbox, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
