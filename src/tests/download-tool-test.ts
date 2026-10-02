// download-tool-test.ts
//
// Adversarial tests for the generic download-tool registration. These
// verify the SDK-facing boundary: tool name, permission id, the
// ask-effect policy, and the executor wiring into the safe-download
// primitive.

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { compileDownloadAdapter, type DownloadAdapterConfig } from "../download-adapter";
import {
  downloadAdapterEffect,
  downloadAdapterPermission,
  isDownloadAdapterId,
  registerDownloadTool,
} from "../download-tool";

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

const baseConfig: DownloadAdapterConfig = {
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

const goodPng = Uint8Array.from(
  Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  ),
);

interface RegisteredTool {
  name: string;
  description: string;
  options: { namespace?: string; codemode?: boolean; permission?: string };
  execute: (input: unknown, context: any) => Promise<unknown>;
}

interface Editor {
  namespace: (def: { name: string; description: string }) => void;
  add: (tool: RegisteredTool) => void;
}

class CapturingCtx {
  tools: RegisteredTool[] = [];
  tool = {
    transform: async (fn: (editor: Editor) => void): Promise<void> => {
      fn({
        namespace: () => undefined,
        add: (tool: RegisteredTool) => {
          this.tools.push(tool);
        },
      });
    },
  };
}

try {
  // ---- id + permission helpers ----
  ok(
    "isDownloadAdapterId accepts lower-case ids",
    isDownloadAdapterId("pixellab") && isDownloadAdapterId("gh1") && isDownloadAdapterId("a_b_c"),
  );
  for (const bad of ["", "Pixellab", "1pixellab", "way_too_long_id_here_yes", "no spaces"]) {
    ok(`isDownloadAdapterId rejects ${JSON.stringify(bad)}`, !isDownloadAdapterId(bad));
  }
  ok(
    "downloadAdapterPermission maps id to <id>_download",
    downloadAdapterPermission("pixellab") === "pixellab_download",
  );
  ok("downloadAdapterEffect forces ask for allow", downloadAdapterEffect("allow") === "ask");
  ok("downloadAdapterEffect preserves deny", downloadAdapterEffect("deny") === "deny");
  ok("downloadAdapterEffect keeps ask", downloadAdapterEffect("ask") === "ask");

  // ---- registration happy path ----
  {
    const compiled = compileDownloadAdapter(baseConfig);
    const ctx = new CapturingCtx();
    let auditedStatus: "completed" | "failed" | undefined;
    await registerDownloadTool(ctx as never, "pixellab", compiled, [], async (_context, status) => {
      auditedStatus = status;
    });
    ok("registers exactly one tool", ctx.tools.length === 1);
    const tool = ctx.tools[0];
    ok("tool name is download_<id>", tool.name === "download_pixellab");
    ok("namespace is auto_guard", tool.options.namespace === "auto_guard");
    ok("codemode is enabled", tool.options.codemode === true);
    ok("permission id matches <id>_download", tool.options.permission === "pixellab_download");
    ok("tool description mentions pixellab", /pixellab/i.test(tool.description));

    // Executor happy path: stub the SDK context with a fetch injection
    // through `compileDownloadAdapter`'s spec is not possible at this
    // point — the spec's request is fired with globalThis.fetch. We
    // exercise the executor by pointing the adapter at a non-existent
    // root; the executor must reject without calling fetch.
    const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), "download-tool-test-"));
    try {
      await fs.mkdir(path.join(sandbox, "root"));
      const compiled2 = compileDownloadAdapter({ ...baseConfig, root: path.join(sandbox, "root") });
      const ctx2 = new CapturingCtx();
      let fetched = false;
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async () => {
        fetched = true;
        return new Response(goodPng, { headers: { "content-type": "image/png" } });
      }) as unknown as typeof fetch;
      try {
        await registerDownloadTool(ctx2 as never, "pixellab", compiled2, [], async (_c, status) => {
          auditedStatus = status;
        });
        const tool2 = ctx2.tools[0];
        const result = await tool2.execute(
          {
            filename: "asset.png",
            objectId: "123e4567-e89b-12d3-a456-426614174000",
            collection: "map-objects",
          },
          { sessionID: "s", agent: "auto" },
        );
        ok(
          "executor writes payload and audit-marks success",
          fetched &&
            auditedStatus === "completed" &&
            (await fs.readFile(path.join(sandbox, "root", "asset.png"))).equals(goodPng) &&
            (result as { content: string }).content.includes("Saved"),
        );
      } finally {
        globalThis.fetch = originalFetch;
        await fs.rm(sandbox, { recursive: true, force: true });
      }
    } catch (error) {
      console.error("executor happy path failed:", error);
      ok("executor happy path happy path", false);
    }
  }

  // ---- executor rejects invalid input before fetch ----
  {
    const sandbox = await fs.mkdtemp(path.join(os.tmpdir(), "download-tool-invalid-"));
    try {
      await fs.mkdir(path.join(sandbox, "root"));
      const compiled = compileDownloadAdapter({ ...baseConfig, root: path.join(sandbox, "root") });
      const ctx = new CapturingCtx();
      let fetched = false;
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async () => {
        fetched = true;
        return new Response(goodPng, { headers: { "content-type": "image/png" } });
      }) as unknown as typeof fetch;
      try {
        await registerDownloadTool(ctx as never, "pixellab", compiled, [], async () => undefined);
        const tool = ctx.tools[0];
        let rejected = false;
        try {
          await tool.execute(
            {
              filename: "../escape.png",
              objectId: "123e4567-e89b-12d3-a456-426614174000",
              collection: "map-objects",
            },
            { sessionID: "s", agent: "auto" },
          );
        } catch {
          rejected = true;
        }
        ok("executor rejects path-traversal filename", !fetched && rejected);
      } finally {
        globalThis.fetch = originalFetch;
        await fs.rm(sandbox, { recursive: true, force: true });
      }
    } catch (error) {
      console.error("invalid input test failed:", error);
      ok("invalid input test happy path", false);
    }
  }

  // ---- registry helper rejects illegal ids before touching ctx.tool ----
  {
    let threw = false;
    try {
      await registerDownloadTool(
        new CapturingCtx() as never,
        "PIXELLAB",
        compileDownloadAdapter(baseConfig),
        [],
        async () => undefined,
      );
    } catch {
      threw = true;
    }
    ok("registerDownloadTool rejects illegal id", threw);
  }
} catch (error) {
  console.error("unexpected error:", error);
  process.exit(2);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
