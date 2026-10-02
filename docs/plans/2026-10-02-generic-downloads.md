# Generic Download Adapters — Implementation Plan

> **For Codex:** Execute these scoped tasks in this repository; no deployment, configuration edits, commits or downloads without separate authorization.

**Goal:** Replace the hardcoded PixelLab PNG downloader with a generic, declarative, toggleable `downloads` map. One primitive, many adapters. Each adapter's tool, permission, and audit category is named after the user-supplied id; the user can enable/disable each independently.

**Architecture (post-refactor):**

```
opencode.jsonc
  └─ downloads: {
       pixellab:    { enabled: true,  root, host, pathTemplate, ... },
       gh_releases: { enabled: false, root, host, pathTemplate, ... },
       ...
     }
            │
            ▼
src/index.ts  (parses, validates, registers one tool per enabled adapter)
            │
            ▼
src/download-tool.ts        (generic OpenCode tool registration)
            │
            ▼
src/download-adapter.ts     (generic spec: input → URL → content)
            │
            ▼
src/safe-download.ts        (defense contract: root, identity, fetch, exclusive write)
            │
            ▼
src/content-validators.ts   (palette: png | jpeg | webp | text/plain | none)
```

The `safe-download.ts` primitive is reused as-is. `content-validators.ts` replaces the in-adapter PNG decoder; new validators ship in the same palette. The pixellab adapter becomes a documented config entry, not code.

**Tech Stack:** TypeScript, OpenCode V2 plugin SDK, Node filesystem/fetch/zlib, Bun test scripts. Biome for lint + format. No new dependencies.

**Breaking change:** The single option `pixellabDownloadRoot` is removed. Anyone who had it must migrate to the equivalent `downloads.pixellab` entry. This is intentional — keeping two parallel surfaces for the same feature is more risk than benefit.

---

### Config shape (user-facing)

```jsonc
{
  "downloads": {
    "pixellab": {
      "enabled": true,
      "root": "C:/Users/.../kingdom-simulator/src/assets/icons/stats",
      "host": "api.pixellab.ai",
      "pathTemplate": "/mcp/{collection}/{objectId}/download",
      "expectedContentType": "image/png",
      "contentValidator": "png",
      "maxBytes": 1048576,
      "timeoutMs": 30000,
      "fields": {
        "objectId":    { "shape": "uuid" },
        "collection":  { "shape": { "enum": ["map-objects", "images"] } }
      }
    },
    "gh_releases": {
      "enabled": false,
      "root": "C:/Users/.../downloads",
      "host": "github.com",
      "pathTemplate": "/{owner}/{repo}/releases/download/{tag}/{asset}",
      "expectedContentType": "application/octet-stream",
      "contentValidator": "none",
      "fields": {
        "owner": { "shape": "slug" },
        "repo":  { "shape": "slug" },
        "tag":   { "shape": "slug" },
        "asset": { "shape": "slug" }
      }
    }
  }
}
```

Contract:
- `enabled` (default false): only `true` registers a tool.
- `root` must be absolute, non-network, no dot segments. Checked at startup; plugin refuses to register the adapter if invalid.
- `host` must be a single literal hostname (no scheme, no port, no path, no userinfo). The primitive pins to `https://${host}${pathTemplate-rendered}` and re-verifies the response URL after any redirect is rejected.
- `pathTemplate` is a literal `/path` with `{key}` placeholders. Placeholders MUST correspond to a field name in `fields`. Unknown placeholders are rejected at startup.
- `expectedContentType` is matched exactly (lowercased, parameter stripped). `contentValidator` runs after the type check.
- `maxBytes` (default 1 MiB, hard ceiling 1 MiB) bounds the streamed body.
- `timeoutMs` (default 30s, max 60s) is the abort budget.
- `fields` keys are MUST match the placeholder keys in `pathTemplate` plus the always-present `"filename"` field (which uses a built-in filename regex tied to the content type's known extension: `.png` / `.jpg|.jpeg` / `.webp` / `.txt`).
- Field shapes are a closed palette: `"uuid" | "num" | "slug" | "hex32" | "hex64" | { "enum": [...] }`. The LLM cannot supply a URL fragment, query, or path separator; every value is re-validated against the shape regex at call time.

`{objectId}` only ever expands to a string that already passed the per-field shape regex. The primitive performs the regex check in addition to the URL builder so a future adapter cannot accidentally leak a slash.

**Generated per-adapter:** tool name `auto_guard_download_<id>`, permission `<id>_download`, audit category `<id>_download_result`. The `<id>` is the lowercase `[a-z][a-z0-9_]{0,31}` of the config key.

---

### Task 1: Content validator palette

- Create `src/content-validators.ts`.
- Export `ContentValidatorName = "png" | "jpeg" | "webp" | "text/plain" | "none"` and `validateContentByName(name, bytes) → void`.
- Implement `png` (move the strict decoder from `pixellab-download.ts` verbatim — same CRC, IHDR, IDAT, scanline validation; only the function location moves).
- Implement `jpeg` with SOI/EOI marker check + dimension bounds from the SOF segment (≤ 400×400 like the PNG one; bounded to keep with the small-pixel-defense theme).
- Implement `webp` with RIFF/WEBP header + VP8/VP8L/VP8X chunk walk + dimension bounds.
- Implement `text/plain` with a UTF-8 BOM/replacement-char sanity check + size cap already handled upstream.
- Implement `none` as identity; defers to `expectedContentType` + size cap.
- Add `src/tests/content-validators-test.ts`: each validator rejects its respective malformed payload; each accepts a known-good minimal fixture. Use synthetic bytes; no fixtures from the opencode-auto-guard repo (this plugin is the binary).

### Task 2: Generic adapter + tool

- Create `src/download-adapter.ts`:
  - Export `DownloadAdapterConfig` (the shape from above).
  - Export `compileDownloadAdapter(id, config) → SafeDownloadSpec<ValidatedInput>`:
    - Parse `pathTemplate` at startup; reject unknown placeholders or empty placeholders.
    - For each field, pre-compile the shape regex.
    - `validateInput` enforces: object input; `filename` is required and matches the per-content-type filename regex; every other declared field is required; no extras.
    - `buildUrl` expands placeholders ONLY with already-validated strings; rejects any remaining `{...}` and the resulting URL is parsed to confirm `host` matches and path starts with `/` and contains no `..` or `//`.
- Create `src/download-tool.ts`:
  - Export `registerDownloadTool(ctx, id, config, protectedPaths, audit) → void`.
  - Register a tool named `auto_guard_download_<id>` in the `auto_guard` namespace with `codemode: true` and permission `<id>_download`.
  - Hook the executor through `safeDownloadFile`.
- Add `src/tests/download-adapter-test.ts` (spec compilation, input rejection, URL rendering) and `src/tests/download-tool-test.ts` (tool registration, permission id, no registration when `enabled: false`).

### Task 3: Wire `index.ts` to the map

- Replace `pixellabDownloadRoot` with `downloads` (a `Record<string, DownloadAdapterConfig>`).
- In `resolveOptions`: validate `downloads` shape; reject unknown keys (`enabled`, `root`, `host`, `pathTemplate`, `expectedContentType`, `contentValidator`, `maxBytes`, `timeoutMs`, `fields`); reject unknown `contentValidator`; reject id < 2 chars or non-`[a-z][a-z0-9_]{0,8}`; reject unknown field shapes.
- Keep a deprecated alias read path only at the **diagnostic** level (a startup log line saying the option was removed); do not honor the old key. The user explicitly chose breaking.
- In the registration loop, for each entry with `enabled === true`, call `registerDownloadTool`. Each adapter gets its own entry in `COUNTED_ACTIONS`, its own branch in the permission hook (always `ask`, preserve `deny`), its own audit category.
- Update the audit-category factory and the COUNTED_ACTIONS set to be derived from the enabled adapters.

### Task 5: Delete hardcoded pixellab

- Delete `src/pixellab-download.ts`, `src/pixellab-tool.ts`, `src/tests/pixellab-download-test.ts`, `src/tests/pixellab-tool-test.ts`.
- Update `package.json` `files` and `test` script.

### Task 7: Documentation

- `README.md`: replace the "Safe PixelLab PNG downloads (opt-in)" section with a generic "Safe downloads (opt-in, per-adapter)" section showing the pixellab config + a second non-PNG example.
- `docs/SECURITY.md`: rewrite the "Dedicated PixelLab downloader" section to describe the generic mechanism; reference the `safe-download.ts` contract unchanged.
- `CHANGELOG.md`: add a v0.2.0 entry explaining the breaking `pixellabDownloadRoot → downloads.pixellab` migration.

### Task 8: Quality gate + release

- `bun run check` must be green before tag.
- Bump to `0.2.0`.
- Run the user's preferred tag workflow (amend-on-fix / -bump / push-tag).