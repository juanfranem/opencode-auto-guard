import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  buildPixellabDownloadUrl,
  downloadPixellabPng,
  validatePixellabDownloadInput,
  validatePixellabPng,
} from "../pixellab-download";

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
const id = "123e4567-e89b-12d3-a456-426614174000";
const MAX = 1024 * 1024;
const png = Uint8Array.from(
  Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  ),
);
const response = (
  body: BodyInit = png,
  headers: Record<string, string> = { "content-type": "image/png" },
  status = 200,
) => new Response(body, { status, headers });
const deps = (r: Response, seen?: (init: RequestInit) => void) => ({
  fetch: async (_url: string | URL | Request, init?: RequestInit) => {
    seen?.(init ?? {});
    return r;
  },
});

// Mutate a chunk and recompute its checksum so tests exercise structure/inflate,
// not merely the CRC check.
function mutateChunk(type: string, change: (body: Buffer) => void): Uint8Array {
  const copy = Buffer.from(png);
  for (let offset = 8; offset < copy.length; ) {
    const size = copy.readUInt32BE(offset);
    if (copy.toString("ascii", offset + 4, offset + 8) === type) {
      change(copy.subarray(offset + 8, offset + 8 + size));
      let crc = 0xffffffff;
      for (const b of copy.subarray(offset + 4, offset + 8 + size)) {
        crc ^= b;
        for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
      }
      copy.writeUInt32BE((crc ^ 0xffffffff) >>> 0, offset + 8 + size);
      return copy;
    }
    offset += size + 12;
  }
  throw new Error("fixture chunk missing");
}

const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), "pixellab-download-"));
const root = path.join(sandbox, "root");
await fs.mkdir(root);

try {
  ok(
    "accepts exact input",
    validatePixellabDownloadInput({ objectId: id, filename: "asset_1.png" }).filename ===
      "asset_1.png",
  );
  for (const bad of [
    null,
    { objectId: id, filename: "../x.png" },
    { objectId: `${id}?x`, filename: "a.png" },
    { objectId: id, filename: "A.png" },
    { objectId: id, filename: "a.png", extra: 1 },
    { objectId: `https://api.pixellab.ai.evil.test/${id}`, filename: "a.png" },
    { objectId: id, filename: "a.png:secret" },
    { objectId: id, filename: "con.png" },
    { objectId: id, filename: "a.png; whoami" },
    { objectId: id, filename: "C:/outside.png" },
  ]) {
    let rejected = false;
    try {
      validatePixellabDownloadInput(bad);
    } catch {
      rejected = true;
    }
    ok("rejects malformed input", rejected);
  }
  ok(
    "builds fixed URL",
    buildPixellabDownloadUrl(id) === `https://api.pixellab.ai/mcp/map-objects/${id}/download`,
  );

  for (const invalid of [
    mutateChunk("IHDR", (body) => body.writeUInt32BE(401, 0)),
    mutateChunk("IHDR", (body) => body.writeUInt32BE(0, 4)),
    mutateChunk("IHDR", (body) => {
      body[8] = 3;
    }),
    mutateChunk("IHDR", (body) => {
      body[9] = 7;
    }),
    mutateChunk("IHDR", (body) => {
      body[12] = 1;
    }),
    mutateChunk("IDAT", (body) => {
      body.fill(0);
    }),
  ]) {
    let rejected = false;
    try {
      validatePixellabPng(invalid);
    } catch {
      rejected = true;
    }
    ok("CRC-valid malformed PNG refused", rejected);
  }

  let seen: RequestInit | undefined;
  const result = await downloadPixellabPng(
    { objectId: id, filename: "good.png" },
    root,
    [],
    deps(response(), (i) => {
      seen = i;
    }),
  );
  ok(
    "downloads valid PNG",
    result.bytes === png.length && (await fs.readFile(result.path)).equals(png),
  );
  ok(
    "uses safe GET options",
    seen?.method === "GET" && seen.redirect === "error" && seen.credentials === "omit",
  );

  await fs.writeFile(path.join(root, "existing.png"), "keep");
  let network = false;
  try {
    await downloadPixellabPng({ objectId: id, filename: "existing.png" }, root, [], {
      fetch: async () => {
        network = true;
        return response();
      },
    });
  } catch {
    /* expected */
  }
  ok(
    "rejects existing target before network",
    !network && (await fs.readFile(path.join(root, "existing.png"))).toString() === "keep",
  );

  for (const r of [
    response(png, { "content-type": "text/html" }),
    response(png, { "content-type": "image/png" }, 302),
    response(new Uint8Array(MAX + 1), { "content-type": "image/png" }),
    response(png, { "content-type": "image/png", "content-length": String(MAX + 1) }),
    response("<html>not PNG</html>", { "content-type": "image/png" }),
    response(png.subarray(0, png.length - 4)),
    response(new Uint8Array(png).fill(0, 29, 33)),
  ]) {
    let rejected = false;
    try {
      await downloadPixellabPng({ objectId: id, filename: `bad${pass}.png` }, root, [], deps(r));
    } catch {
      rejected = true;
    }
    ok("rejects bad response", rejected);
  }
  let redirectError = false;
  try {
    await downloadPixellabPng({ objectId: id, filename: "redirect.png" }, root, [], {
      fetch: async (_u, init) => {
        if (init?.redirect !== "error") throw new Error("redirect option missing");
        throw new TypeError("redirect");
      },
    });
  } catch {
    redirectError = true;
  }
  ok("redirect is refused", redirectError);

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
      await downloadPixellabPng({ objectId: id, filename: "root.png" }, badRoot, [], {
        fetch: async () => {
          fetched = true;
          return response();
        },
      });
    } catch {
      rejected = true;
    }
    ok("invalid root rejected before network", rejected && !fetched);
  }

  const linkedRoot = path.join(sandbox, "linked");
  await fs.symlink(root, linkedRoot, process.platform === "win32" ? "junction" : "dir");
  let symlinkRejected = false;
  try {
    await downloadPixellabPng(
      { objectId: id, filename: "link.png" },
      linkedRoot,
      [],
      deps(response()),
    );
  } catch {
    symlinkRejected = true;
  }
  ok(
    "symlink/junction root refused",
    symlinkRejected && !(await fs.stat(path.join(root, "link.png")).catch(() => undefined)),
  );
  const inner = path.join(root, "inner");
  await fs.mkdir(inner);
  let ancestorRejected = false;
  try {
    await downloadPixellabPng(
      { objectId: id, filename: "ancestor.png" },
      path.join(linkedRoot, "inner"),
      [],
      deps(response()),
    );
  } catch {
    ancestorRejected = true;
  }
  ok("symlink/junction ancestor refused", ancestorRejected);

  const abort = new AbortController();
  abort.abort();
  let cancelRejected = false;
  let cancelFetched = false;
  try {
    await downloadPixellabPng({ objectId: id, filename: "cancel.png" }, root, [], {
      signal: abort.signal,
      fetch: async () => {
        cancelFetched = true;
        return response();
      },
    });
  } catch {
    cancelRejected = true;
  }
  ok("pre-cancelled call does not fetch or write", cancelRejected && !cancelFetched);

  let timeoutRejected = false;
  try {
    await downloadPixellabPng({ objectId: id, filename: "timeout.png" }, root, [], {
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
    "network timeout aborts before creating destination",
    timeoutRejected && !(await fs.stat(path.join(root, "timeout.png")).catch(() => undefined)),
  );

  const changingRoot = path.join(sandbox, "changing");
  await fs.mkdir(changingRoot);
  let changedRejected = false;
  try {
    await downloadPixellabPng({ objectId: id, filename: "changed.png" }, changingRoot, [], {
      fetch: async () => {
        await fs.rename(changingRoot, path.join(sandbox, "old-root"));
        await fs.mkdir(changingRoot);
        return response();
      },
    });
  } catch {
    changedRejected = true;
  }
  ok(
    "directory replacement during network refused",
    changedRejected &&
      !(await fs.stat(path.join(changingRoot, "changed.png")).catch(() => undefined)),
  );

  let protectedRejected = false;
  try {
    await downloadPixellabPng(
      { objectId: id, filename: "protected.png" },
      root,
      [root],
      deps(response()),
    );
  } catch {
    protectedRejected = true;
  }
  ok(
    "protected root is refused",
    protectedRejected && !(await fs.stat(path.join(root, "protected.png")).catch(() => undefined)),
  );

  const [one, two] = await Promise.allSettled([
    downloadPixellabPng({ objectId: id, filename: "race.png" }, root, [], deps(response())),
    downloadPixellabPng({ objectId: id, filename: "race.png" }, root, [], deps(response())),
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
