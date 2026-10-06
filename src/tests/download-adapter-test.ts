// download-adapter-test.ts
//
// Adversarial tests for `compileDownloadAdapter`. These cover the
// boundary between a user-supplied JSON config and the safe-download
// spec the runtime consumes. Anything that escapes this seam is a
// bug; the spec the compiler yields MUST be safe to execute even
// when fed hostile inputs.

import { compileDownloadAdapter, type DownloadAdapterConfig } from "../download-adapter";

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

const basePixellab: DownloadAdapterConfig = {
  enabled: true,
  root: "/tmp/adapter",
  host: "api.pixellab.ai",
  pathTemplate: "/mcp/{collection}/{objectId}/download",
  expectedContentType: "image/png",
  contentValidator: "png",
  fields: {
    objectId: "uuid",
    collection: { enum: ["map-objects", "images"] },
  },
};

// Backward-compat: v0.2.x shipped with a `{ shape: ... }` wrapper that
// the user (and the README) documented. The v0.2.2+ compiler unwraps it.
const wrappedPixellab = {
  enabled: true,
  root: "/tmp/adapter",
  host: "api.pixellab.ai",
  pathTemplate: "/mcp/{collection}/{objectId}/download",
  expectedContentType: "image/png",
  contentValidator: "png",
  fields: {
    objectId: { shape: "uuid" },
    collection: { shape: { enum: ["map-objects", "images"] } },
  },
} as unknown as DownloadAdapterConfig;

try {
  // ---- host-only configuration ----
  {
    const minimal = { enabled: true, root: "/tmp/adapter", host: "api.pixellab.ai" };
    const compiled = compileDownloadAdapter(minimal);
    ok("minimal config selects host mode", compiled.config.mode === "host");
    ok(
      "host mode has no default content restrictions",
      compiled.spec.expectedContentType === undefined,
    );
    compiled.spec.validateContent(new Uint8Array([0, 255, 1]));
    for (const url of [
      "https://api.pixellab.ai/",
      "https://api.pixellab.ai/mcp/images/job/download?index=0",
      "https://api.pixellab.ai/any/path/file.zip?token=a%2Fb&index=2&index=3",
      "https://api.pixellab.ai:443/other?redirect=https%3A%2F%2Fexample.test",
    ]) {
      const valid = compiled.spec.validateInput({ filename: "asset.zip", url });
      ok(`host mode accepts ${url}`, compiled.spec.buildUrl(valid) === new URL(url).toString());
    }
    for (const url of [
      "http://api.pixellab.ai/file",
      "https://evil.test/file",
      "https://sub.api.pixellab.ai/file",
      "https://api.pixellab.ai.evil.test/file",
      "https://api.pixellab.ai:8443/file",
      "https://user:pass@api.pixellab.ai/file",
      "https://@api.pixellab.ai/file",
      "https://api.pixellab.ai@evil.test/file",
      "https://api.pixellab.ai/file#fragment",
      "https://api.pixellab.ai/file#",
      "https://api.pixellab.ai\\@evil.test/file",
      " https://api.pixellab.ai/file",
      "https://api.pixellab.ai/fi\nle",
      "//api.pixellab.ai/file",
      "/file",
      "not a url",
    ]) {
      for (const method of ["validateInput", "buildUrl"] as const) {
        let rejected = false;
        try {
          compiled.spec[method]({ filename: "asset.zip", url });
        } catch {
          rejected = true;
        }
        ok(`${method} rejects unsafe host URL ${JSON.stringify(url)}`, rejected);
      }
    }
    const url = "https://api.pixellab.ai/file";
    for (const filename of [
      "asset.png",
      "pack.zip",
      "data.json",
      "readme",
      "0.bin",
      "a-b_c.v2.tar.gz",
    ]) {
      ok(
        `host mode accepts basename ${filename}`,
        compiled.spec.validateInput({ filename, url }).filename === filename,
      );
    }
    for (const bad of [
      null,
      [],
      {},
      { filename: "a.zip" },
      { url },
      { filename: "a.zip", url, extra: 1 },
      ...[
        "../a.zip",
        "a/b.zip",
        "a\\b.zip",
        "CON.zip",
        "con.zip",
        "nul",
        "com1.tar.gz",
        "a.",
        ".env",
        "a b.zip",
        "a:stream",
        "a".repeat(129),
      ].map((filename) => ({ filename, url })),
    ]) {
      let rejected = false;
      try {
        compiled.spec.validateInput(bad);
      } catch {
        rejected = true;
      }
      ok(`host mode rejects malformed input ${JSON.stringify(bad)}`, rejected);
    }
    for (const extra of [
      { fields: {} },
      { pathTemplate: null },
      { pathTemplate: "" },
      { pathTemplate: "/file" },
      { expectedContentType: null },
      { contentValidator: "bad" },
      { contentValidator: null },
    ]) {
      let rejected = false;
      try {
        compileDownloadAdapter({ ...minimal, ...extra } as never);
      } catch {
        rejected = true;
      }
      ok(`partial/malformed config rejected ${JSON.stringify(extra)}`, rejected);
    }
    const constrained = compileDownloadAdapter({
      ...minimal,
      expectedContentType: "image/png",
      contentValidator: "png",
    });
    ok(
      "host mode honors explicit content type",
      constrained.spec.expectedContentType === "image/png",
    );
    let rejected = false;
    try {
      constrained.spec.validateInput({ filename: "a.zip", url });
    } catch {
      rejected = true;
    }
    ok("host mode explicit content type restricts filename extension", rejected);
  }
  // ---- happy path ----
  {
    const compiled = compileDownloadAdapter(basePixellab);
    const url = compiled.spec.buildUrl({
      filename: "a.png",
      objectId: "123e4567-e89b-12d3-a456-426614174000",
      collection: "map-objects",
    } as never);
    ok(
      "compiles canonical pixellab URL",
      url ===
        "https://api.pixellab.ai/mcp/map-objects/123e4567-e89b-12d3-a456-426614174000/download",
    );
  }
  {
    const compiled = compileDownloadAdapter(basePixellab);
    const url = compiled.spec.buildUrl({
      filename: "a.png",
      objectId: "123e4567-e89b-12d3-a456-426614174000",
      collection: "images",
    } as never);
    ok(
      "collection=images produces /images/ URL",
      url === "https://api.pixellab.ai/mcp/images/123e4567-e89b-12d3-a456-426614174000/download",
    );
  }

  // ---- input validation ----
  {
    const compiled = compileDownloadAdapter(basePixellab);
    ok(
      "accepts valid input",
      (() => {
        try {
          compiled.spec.validateInput({
            filename: "asset_1.png",
            objectId: "123e4567-e89b-12d3-a456-426614174000",
            collection: "map-objects",
          });
          return true;
        } catch {
          return false;
        }
      })(),
    );
    for (const bad of [
      null,
      undefined,
      "string",
      7,
      [],
      { objectId: "123e4567-e89b-12d3-a456-426614174000" }, // missing filename + collection
      {
        filename: "../escape.png",
        objectId: "123e4567-e89b-12d3-a456-426614174000",
        collection: "map-objects",
      },
      {
        filename: "a.png",
        objectId: "https://evil.test/123e4567-e89b-12d3-a456-426614174000",
        collection: "map-objects",
      },
      {
        filename: "A.png",
        objectId: "123e4567-e89b-12d3-a456-426614174000",
        collection: "map-objects",
      },
      {
        filename: "a.png",
        objectId: "123e4567-e89b-12d3-a456-426614174000",
        collection: "images",
        extra: 1,
      },
    ]) {
      let rejected = false;
      try {
        compiled.spec.validateInput(bad);
      } catch {
        rejected = true;
      }
      ok("validateInput rejects malformed input", rejected);
    }
  }

  // ---- wrapped shape form (backward compat from v0.2.x README) ----
  {
    const compiled = compileDownloadAdapter(wrappedPixellab);
    const url = compiled.spec.buildUrl({
      filename: "a.png",
      objectId: "123e4567-e89b-12d3-a456-426614174000",
      collection: "map-objects",
    } as never);
    ok(
      "wrapped {shape: ...} form compiles to the same URL",
      url ===
        "https://api.pixellab.ai/mcp/map-objects/123e4567-e89b-12d3-a456-426614174000/download",
    );
  }
  {
    let rejected = false;
    try {
      compileDownloadAdapter({
        ...wrappedPixellab,
        fields: {
          objectId: { shape: "uuid", extra: "ignored" } as never,
        },
      });
    } catch {
      rejected = true;
    }
    ok("wrapped form rejects extra fields besides shape", rejected);
  }
  for (const badHost of [
    "",
    "API.PIXELLAB.AI", // uppercase
    "api pixellab ai",
    "api.pixellab.ai:8080",
    "user@api.pixellab.ai",
    "https://api.pixellab.ai",
    "/api.pixellab.ai",
    1,
    {},
  ]) {
    let rejected = false;
    try {
      compileDownloadAdapter({ ...basePixellab, host: badHost as never });
    } catch {
      rejected = true;
    }
    ok(`host "${String(badHost)}" rejected at compile`, rejected);
  }
  for (const bad of [
    "mcp/{collection}/{objectId}/download", // missing leading /
    "/mcp/{collection}/{objectId}/download?evil=1",
    "/mcp/{collection}/{objectId}/download#frag",
    "/mcp//{objectId}/download",
    "/mcp/{unknown}/{objectId}/download",
    "/mcp/{collection}/download", // missing {objectId}
    "/mcp/../etc/passwd",
    1,
  ]) {
    let rejected = false;
    try {
      compileDownloadAdapter({ ...basePixellab, pathTemplate: bad as never });
    } catch {
      rejected = true;
    }
    ok(`pathTemplate ${String(bad)} rejected at compile`, rejected);
  }

  // ---- field shape ----
  for (const bad of [
    "uuid1",
    "",
    { enum: [] },
    { enum: ["x", 1] },
    { enum: ["valid-but-empty-ish", ""] },
    1,
    [],
  ]) {
    let rejected = false;
    try {
      compileDownloadAdapter({
        ...basePixellab,
        fields: { objectId: bad as never },
      });
    } catch {
      rejected = true;
    }
    ok(`field shape ${JSON.stringify(bad)} rejected`, rejected);
  }

  // ---- content type / extension coupling ----
  {
    let rejected = false;
    try {
      compileDownloadAdapter({
        ...basePixellab,
        expectedContentType: "image/png; charset=binary",
      });
    } catch {
      rejected = true;
    }
    ok("expectedContentType with parameters is normalized, not rejected", !rejected);
  }
  {
    let rejected = false;
    try {
      compileDownloadAdapter({
        ...basePixellab,
        expectedContentType: "application/zip",
      });
    } catch {
      rejected = true;
    }
    ok("unknown content type rejected at compile", rejected);
  }

  // ---- URL render rejects crafted field inputs that the shape regex
  //      would otherwise pass. This is a belt-and-braces guard: even if a
  //      future shape regex were looser than intended, render must
  //      refuse to produce an URL fragment.
  {
    const compiled = compileDownloadAdapter(basePixellab);
    let rejected = false;
    try {
      compiled.spec.buildUrl({
        filename: "a.png",
        objectId: "../etc/passwd", // would never survive validateInput
        collection: "map-objects",
      } as never);
    } catch {
      rejected = true;
    }
    ok("URL render rejects slashes inside a field value", rejected);
  }
  {
    const compiled = compileDownloadAdapter(basePixellab);
    let rejected = false;
    try {
      compiled.spec.buildUrl({
        filename: "a.png",
        objectId: "123e4567-e89b-12d3-a456-426614174000",
        collection: "images?q=1",
      } as never);
    } catch {
      rejected = true;
    }
    ok("URL render rejects ? inside a field value", rejected);
  }

  // ---- file extension uniqueness per content type ----
  {
    const compiled = compileDownloadAdapter(basePixellab);
    let rejected = false;
    try {
      compiled.spec.validateInput({
        filename: "a.jpg",
        objectId: "123e4567-e89b-12d3-a456-426614174000",
        collection: "map-objects",
      });
    } catch {
      rejected = true;
    }
    ok("PNG adapter rejects .jpg filename", rejected);
  }

  // ---- wrapped shape form (backward compat from v0.2.x README) ----
  {
    const compiled = compileDownloadAdapter(wrappedPixellab);
    const url = compiled.spec.buildUrl({
      filename: "a.png",
      objectId: "123e4567-e89b-12d3-a456-426614174000",
      collection: "map-objects",
    } as never);
    ok(
      "wrapped {shape: ...} form compiles to the same URL",
      url ===
        "https://api.pixellab.ai/mcp/map-objects/123e4567-e89b-12d3-a456-426614174000/download",
    );
  }
  {
    let rejected = false;
    try {
      compileDownloadAdapter({
        ...wrappedPixellab,
        fields: {
          objectId: { shape: "uuid", extra: "ignored" } as never,
        },
      });
    } catch {
      rejected = true;
    }
    ok("wrapped form rejects extra fields besides shape", rejected);
  }
} catch (error) {
  console.error("unexpected error:", error);
  process.exit(2);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
