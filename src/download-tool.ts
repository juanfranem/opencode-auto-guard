// download-tool.ts
//
// Generic OpenCode tool registration for a compiled download adapter.
// For each enabled adapter, registers exactly one tool named
// `auto_guard_download_<id>` under the existing `auto_guard` namespace,
// tied to the permission `<id>_download` so the plugin's permission hook
// can apply its own `ask`-forcing + audit wiring.

import type { Plugin } from "@opencode/plugin";
import { safeDownloadFile } from "./safe-download";
import type { CompiledDownloadAdapter } from "./download-adapter";

/** Lowercase identifier, 2-9 chars, `[a-z][a-z0-9_]{1,8}`. */
export type DownloadAdapterId = string;

export function isDownloadAdapterId(value: string): boolean {
  return /^[a-z][a-z0-9_]{1,8}$/.test(value);
}

export function downloadAdapterPermission(id: DownloadAdapterId): string {
  return `${id}_download`;
}

/**
 * Permission effect for any download action. Confirms the user's intent
 * even in Auto mode; an existing `deny` is preserved. Identical to the
 * previous pixellab policy — the adapter-level permissions do NOT
 * participate in shell allowlist elevation.
 */
export function downloadAdapterEffect(effect: "allow" | "ask" | "deny"): "ask" | "deny" {
  return effect === "deny" ? "deny" : "ask";
}

export async function registerDownloadTool(
  ctx: Pick<Plugin.Context, "tool">,
  id: DownloadAdapterId,
  compiled: CompiledDownloadAdapter,
  protectedPaths: readonly string[],
  audit: (
    context: { sessionID: string; agent: string },
    status: "completed" | "failed",
  ) => Promise<void>,
): Promise<void> {
  if (!isDownloadAdapterId(id)) throw new Error(`Invalid download adapter id "${id}"`);
  const toolName = `download_${id}`;
  const permission = downloadAdapterPermission(id);
  await ctx.tool.transform((editor) => {
    // NOTE: editor.namespace is intentionally NOT called inside this
    // transform — the namespace is declared once at boot by `index.ts`
    // before iterating adapters, so multiple `registerDownloadTool`
    // calls never re-declare it. Re-declaring can flip the namespace
    // description mid-flight and confuse the LLM.
    // Build a description that mirrors the prior pixellab wording but
    // uses the adapter id so the LLM sees what it's about to do.
    const fieldLines = Object.keys(compiled.config.fields)
      .map((n) => `\`${n}\``)
      .join(", ");
    const fieldClause = fieldLines ? `${fieldLines} and ` : "";
    const description = `Download one approved ${id} asset into the configured directory. Requires confirmation. Accepts ${fieldClause}\`filename\`; every other input field is rejected. Never follows redirects or overwrites existing files. Does not generate assets.`;
    editor.add({
      name: toolName,
      description,
      // The input shape is intentionally loose here; the adapter's
      // `validateInput` re-validates strictly. We still declare the
      // `filename` property so editor tooling and the SDK schema are
      // useful; extra fields are allowed at the SDK level because the
      // adapter drops them.
      input: {
        type: "object",
        properties: {
          filename: {
            type: "string",
            description:
              "Lowercase destination basename with the configured extension (.png/.jpg/.jpeg/.webp/.txt).",
          },
        },
        required: ["filename"],
        additionalProperties: true,
      },
      options: {
        namespace: "auto_guard",
        codemode: true,
        permission,
      },
      execute: async (input, context) => {
        try {
          const signal =
            "signal" in context && context.signal instanceof AbortSignal
              ? context.signal
              : undefined;
          const result = await safeDownloadFile(
            input,
            compiled.spec,
            compiled.config.root,
            protectedPaths,
            { signal, timeoutMs: compiled.config.timeoutMs },
          );
          await audit(context, "completed");
          return {
            content: `Saved ${compiled.config.contentValidator} asset: ${result.path} (${result.bytes} bytes).`,
          };
        } catch (error) {
          await audit(context, "failed");
          throw error;
        }
      },
    });
  });
}
