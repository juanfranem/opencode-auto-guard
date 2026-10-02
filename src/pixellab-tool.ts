import type { Plugin } from "@opencode/plugin";
import { downloadPixellabPng } from "./pixellab-download";

export const PIXELLAB_DOWNLOAD_PERMISSION = "pixellab_download";

/** This permission never participates in shell allowlist or LLM judge elevation. */
export function pixellabDownloadEffect(effect: "allow" | "ask" | "deny"): "ask" | "deny" {
  return effect === "deny" ? "deny" : "ask";
}

export async function registerPixellabDownloadTool(
  ctx: Pick<Plugin.Context, "tool">,
  root: string | undefined,
  protectedPaths: readonly string[],
  audit: (
    context: { sessionID: string; agent: string },
    status: "completed" | "failed",
  ) => Promise<void>,
): Promise<void> {
  if (!root) return;
  await ctx.tool.transform((editor) => {
    editor.namespace({
      name: "auto_guard",
      description: "Constrained, confirmation-required guard operations.",
    });
    editor.add({
      name: "download_pixellab_png",
      description:
        "Download one approved PixelLab map-object PNG into the configured directory. " +
        "Requires confirmation. Accepts an object UUID and a PNG basename only; " +
        "never follows redirects or overwrites existing files. Does not generate assets.",
      input: {
        type: "object",
        properties: {
          objectId: {
            type: "string",
            pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            description: "PixelLab map-object UUID.",
          },
          filename: {
            type: "string",
            pattern: "^[a-z][a-z0-9_-]{0,63}\\.png$",
            description: "Lowercase PNG basename, e.g. economy.png.",
          },
        },
        required: ["objectId", "filename"],
        additionalProperties: false,
      },
      options: {
        namespace: "auto_guard",
        codemode: true,
        permission: PIXELLAB_DOWNLOAD_PERMISSION,
      },
      execute: async (input, context) => {
        try {
          // Newer SDKs expose cancellation; the installed SDK may not yet do so.
          const signal =
            "signal" in context && context.signal instanceof AbortSignal
              ? context.signal
              : undefined;
          const result = await downloadPixellabPng(input, root, protectedPaths, { signal });
          await audit(context, "completed");
          return { content: `Saved PNG: ${result.path} (${result.bytes} bytes).` };
        } catch (error) {
          await audit(context, "failed");
          throw error;
        }
      },
    });
  });
}
