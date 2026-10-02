import type { Plugin } from "@opencode/plugin";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  PIXELLAB_DOWNLOAD_PERMISSION,
  pixellabDownloadEffect,
  registerPixellabDownloadTool,
} from "../pixellab-tool";
import { HARD_DENY } from "../rules";

let pass = 0;
let fail = 0;
function ok(name: string, condition: boolean): void {
  if (condition) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    console.log(`  ✗ ${name}`);
  }
}

type Editor = Parameters<Parameters<Plugin.Context["tool"]["transform"]>[0]>[0];
type Definition = Parameters<Editor["add"]>[0];
const tools: Definition[] = [];
const namespaces: string[] = [];
let transforms = 0;
const ctx = {
  tool: {
    transform: async (callback: (editor: Editor) => void) => {
      transforms++;
      callback({
        namespace: (namespace) => {
          namespaces.push(namespace.name);
        },
        add: (tool) => {
          tools.push(tool);
        },
        list: () => [],
        get: () => undefined,
        update: () => {},
        remove: () => {},
      });
      return { dispose: async () => {} };
    },
  },
} as Pick<Plugin.Context, "tool">;

await registerPixellabDownloadTool(ctx, undefined, [], async () => {});
await registerPixellabDownloadTool(ctx, "", [], async () => {});
ok("disabled by default; no transform registered", transforms === 0);

const audit: string[] = [];
await registerPixellabDownloadTool(ctx, "relative-root", [], async (_context, status) => {
  audit.push(status);
});
ok("enabled only with explicit root", Number(transforms) === 1 && tools.length === 1);
ok("dedicated namespace", namespaces[0] === "auto_guard");
const tool = tools[0];
ok("stable tool name", tool?.name === "download_pixellab_png");
ok("dedicated permission action", tool?.options?.permission === PIXELLAB_DOWNLOAD_PERMISSION);
ok("permission action remains unchanged", PIXELLAB_DOWNLOAD_PERMISSION === "pixellab_download");
const schema = tool?.input as
  | {
      properties?: Record<string, { type?: string; enum?: string[] }>;
      required?: string[];
      additionalProperties?: boolean;
    }
  | undefined;
ok(
  "resourceType schema allows only map-object and image",
  schema?.properties?.resourceType?.type === "string" &&
    JSON.stringify(schema.properties.resourceType.enum) === JSON.stringify(["map-object", "image"]),
);
ok(
  "resourceType stays optional and unknown fields forbidden",
  JSON.stringify(schema?.required) === JSON.stringify(["objectId", "filename"]) &&
    schema?.additionalProperties === false,
);
ok("exposed to Code Mode", tool?.options?.codemode === true);
ok("global allow still requires confirmation", pixellabDownloadEffect("allow") === "ask");
ok("ask remains ask", pixellabDownloadEffect("ask") === "ask");
ok("explicit deny remains deny", pixellabDownloadEffect("deny") === "deny");
ok("Invoke-WebRequest remains hard denied", HARD_DENY.includes("invoke-webrequest"));

if (tool) {
  let rejected = false;
  try {
    await tool.execute(
      { objectId: "a4f416f2-0749-4b9a-90e3-b05c9b238819", filename: "economy.png" },
      { sessionID: "test", agent: "auto" } as never,
    );
  } catch {
    rejected = true;
  }
  ok("executor does not normalize invalid relative root into permission", rejected);
  ok("failed execution is audited", audit.join(",") === "failed");
}

const root = await fs.mkdtemp(path.join(os.tmpdir(), "pixellab-tool-"));
const originalFetch = globalThis.fetch;
const fetchedUrls: string[] = [];
try {
  globalThis.fetch = Object.assign(
    async (url: string | URL | Request) => {
      fetchedUrls.push(String(url));
      return new Response(
        Buffer.from(
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
          "base64",
        ),
        { headers: { "content-type": "image/png" } },
      );
    },
    { preconnect: originalFetch.preconnect },
  );
  await registerPixellabDownloadTool(ctx, root, [], async (_context, status) => {
    audit.push(status);
  });
  const registered = tools[1];
  if (!registered) throw new Error("tool was not registered");
  const result = await registered.execute(
    { objectId: "a4f416f2-0749-4b9a-90e3-b05c9b238819", filename: "economy.png" },
    { sessionID: "test", agent: "auto" } as never,
  );
  ok(
    "registered executor writes into configured root",
    (await fs.stat(path.join(root, "economy.png"))).isFile(),
  );
  ok("successful execution is audited", audit.join(",") === "failed,completed");
  ok(
    "legacy execution retains map-object endpoint",
    fetchedUrls[0] ===
      "https://api.pixellab.ai/mcp/map-objects/a4f416f2-0749-4b9a-90e3-b05c9b238819/download",
  );
  ok(
    "result reports local filename",
    typeof result.content === "string" && result.content.includes("economy.png"),
  );
  const imageResult = await registered.execute(
    {
      objectId: "a4f416f2-0749-4b9a-90e3-b05c9b238819",
      filename: "edited.png",
      resourceType: "image",
    },
    { sessionID: "test", agent: "auto" } as never,
  );
  ok(
    "registered image executor uses fixed images endpoint",
    fetchedUrls[1] ===
      "https://api.pixellab.ai/mcp/images/a4f416f2-0749-4b9a-90e3-b05c9b238819/download",
  );
  ok(
    "registered image executor writes configured root",
    (await fs.stat(path.join(root, "edited.png"))).isFile(),
  );
  ok("image execution success is audited", audit.join(",") === "failed,completed,completed");
  ok(
    "image result reports local filename",
    typeof imageResult.content === "string" && imageResult.content.includes("edited.png"),
  );
} finally {
  globalThis.fetch = originalFetch;
  await fs.rm(root, { recursive: true, force: true });
}

const source = await fs.readFile(new URL("../index.ts", import.meta.url), "utf8");
ok(
  "option explicitly resolved without default directory",
  source.includes("pixellabDownloadRoot: readEnvString(o.pixellabDownloadRoot)"),
);
ok(
  "permission is counted for session limits",
  source.includes('"subagent",\n  PIXELLAB_DOWNLOAD_PERMISSION,'),
);
ok(
  "download permission audit omits access-key resources",
  source.includes('mkAudit(event, event.effect, "pixellab_download_permission", "", false, [])'),
);
ok(
  "dedicated policy occurs before shell/LLM handling",
  source.indexOf("if (action === PIXELLAB_DOWNLOAD_PERMISSION)") <
    source.indexOf('if (action === "shell")'),
);

console.log(`\nPixelLab tool: ${pass} passed, ${fail} failed.`);
if (fail > 0) process.exit(1);
