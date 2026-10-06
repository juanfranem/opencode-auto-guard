// download-adapter.ts
//
// Generic, declarative download adapter. Given a `DownloadAdapterConfig`
// (validated at startup by `index.ts`), compiles a `SafeDownloadSpec` that
// the `safeDownloadFile` primitive can execute. The pixellab-specific
// adapter that lived in `pixellab-download.ts` is now just one config
// entry; this file is the single shape every user-declared adapter
// becomes at runtime.
//
// Security model recap (the config cannot weaken them):
//   * The host is a single literal hostname (no scheme, port, path,
//     userinfo). Every URL is pinned to its HTTPS origin.
//   * Without a path template, input is a full HTTPS URL pinned to the
//     configured host, plus a safe basename. Any route/query is allowed.
//   * In template mode, the path is a literal `/path` with `{key}` placeholders.
//     Each placeholder key MUST correspond to a field declared in the
//     config; unknown placeholders are rejected at compile time, missing
//     placeholders are rejected at compile time. Empty placeholders or
//     placeholder keys that contain anything other than `[A-Za-z0-9_]+`
//     are rejected at compile time.
//   * Each declared field's value is regex-validated against its shape
//     before being substituted. A shape regex can never match a `/`, a
//     `?`, a `#`, a `\0`, or whitespace — see `SHAPE_PATTERNS` below.
//   * The resulting URL is parsed with `new URL(...)` and re-verified to
//     match the configured host (defense against a future bug that lets
//     an exotic ID through a shape check).
//   * The destination filename is matched against the per-content-type
//     extension regex built into this file. The user cannot supply a
//     custom filename regex.
//
// Field shapes ("uuid" | "num" | "slug" | "hex32" | "hex64" | enum):
//   * uuid:        8-4-4-4-12 hex (lowercase only — matches the existing
//                  pixellab convention; uppercase is rejected so the LLM
//                  cannot smuggle different cases through).
//   * num:         1-10 decimal digits.
//   * slug:        [a-z0-9-]{1,64}, must start and end with an alphanumeric.
//   * hex32:       exactly 32 lowercase hex chars (sha256 is 64 — use hex64
//                  for hashes).
//   * hex64:       exactly 64 lowercase hex chars.
//   * enum:        exactly one value from a closed list declared in the
//                  config (e.g. ["map-objects", "images"]).

import type { SafeDownloadInput, SafeDownloadSpec } from "./safe-download";
import {
  type ContentValidatorName,
  isContentValidatorName,
  validateContentByName,
} from "./content-validators";

// ===== Public types =====

export type FieldShapeName = "uuid" | "num" | "slug" | "hex32" | "hex64";

export type FieldShapeSpec = FieldShapeName | { readonly enum: readonly string[] };

export interface DownloadAdapterConfig {
  /** When true, the adapter is registered. Default false. */
  enabled?: boolean;
  /** Absolute, non-network directory that will receive downloaded files. */
  root: string;
  /**
   * Single literal hostname (no scheme, no port, no path, no userinfo).
   * Validated at compile time.
   */
  host: string;
  /**
   * Literal path template. Placeholders are `{key}` where `key` matches
   * `[A-Za-z_][A-Za-z0-9_]*` and corresponds to a field name in `fields`.
   * Empty placeholders (`{}`) and placeholder names not in `fields` are
   * rejected.
   */
  pathTemplate?: string;
  /** Exact response type; required in template mode, optional in host mode. */
  expectedContentType?: string;
  /** Named validator; required in template mode, defaults to none in host mode. */
  contentValidator?: ContentValidatorName;
  /** Max body size in bytes. Default 1 MiB. Hard ceiling 1 MiB. */
  maxBytes?: number;
  /** Per-request network timeout in ms. Default 30s. Hard ceiling 60s. */
  timeoutMs?: number;
  /**
   * Input fields other than the always-present `filename`. Each becomes a
   * required input property AND a placeholder key in `pathTemplate`.
   */
  fields?: Record<string, FieldShapeSpec>;
}

// ===== Compiled adapter =====

export interface CompiledDownloadAdapter<TInput extends SafeDownloadInput = SafeDownloadInput> {
  /** Spec the primitive consumes. */
  spec: SafeDownloadSpec<TInput>;
  /** Mirror of the config, after defaults applied. Useful for tool registration. */
  config: Pick<DownloadAdapterConfig, "root" | "host"> & {
    mode: "host" | "template";
    pathTemplate?: string;
    expectedContentType?: string;
    contentValidator: ContentValidatorName;
    maxBytes: number;
    timeoutMs: number;
    fields: Record<string, FieldShapeSpec>;
  };
}

const HARD_MAX_BYTES = 1024 * 1024;
const HARD_MAX_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

const SHAPE_PATTERNS: Record<FieldShapeName, RegExp> = {
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  num: /^[0-9]{1,10}$/,
  slug: /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/,
  hex32: /^[0-9a-f]{32}$/,
  hex64: /^[0-9a-f]{64}$/,
};

const EXTENSIONS_FOR_CONTENT_TYPE: Record<string, readonly RegExp[]> = {
  "image/png": [/^[a-z][a-z0-9_-]{0,63}\.png$/],
  "image/jpeg": [/^[a-z][a-z0-9_-]{0,63}\.jpe?g$/],
  "image/webp": [/^[a-z][a-z0-9_-]{0,63}\.webp$/],
  "text/plain": [/^[a-z][a-z0-9_-]{0,63}\.txt$/],
};

const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

const VALID_HOST =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const VALID_HOST_LABEL = /^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

// ===== Public API =====

/**
 * Compile a `DownloadAdapterConfig` into a `SafeDownloadSpec` ready for the
 * primitive. Throws on any malformed config; the plugin refuses to register
 * the adapter in that case (and surfaces the failure in the audit log).
 */
export function compileDownloadAdapter(config: DownloadAdapterConfig): CompiledDownloadAdapter {
  const host = requireValidHost(config.host);
  const hostMode = config.pathTemplate === undefined;
  if (!hostMode && config.contentValidator === undefined)
    throw new Error("contentValidator must be specified in template mode");
  const contentType =
    config.expectedContentType === undefined
      ? undefined
      : normalizeContentType(config.expectedContentType);
  const contentValidator = config.contentValidator === undefined ? "none" : config.contentValidator;
  if (!isContentValidatorName(contentValidator)) throw new Error("Unknown contentValidator");
  const maxBytes = clamp(config.maxBytes, DEFAULT_MAX_BYTES, 1, HARD_MAX_BYTES);
  const timeoutMs = clamp(config.timeoutMs, DEFAULT_TIMEOUT_MS, 100, HARD_MAX_TIMEOUT_MS);

  if (hostMode) {
    if (config.fields !== undefined) throw new Error("Host-mode adapters must not declare fields");
  } else if (
    typeof config.fields !== "object" ||
    config.fields === null ||
    Array.isArray(config.fields)
  )
    throw new Error("Adapter fields must be a plain object");

  const fields = config.fields ?? {};
  const compiledFields: Record<string, FieldShapeSpec> = {};
  for (const [name, shape] of Object.entries(fields)) {
    if (!/^[a-z_][a-zA-Z0-9_]{0,31}$/.test(name))
      throw new Error(`Invalid field name "${name}": must match [a-z_][a-zA-Z0-9_]{0,31}`);
    compiledFields[name] = compileShape(shape);
  }

  const pathTemplate = hostMode
    ? undefined
    : resolvePathTemplate(config.pathTemplate, Object.keys(compiledFields));
  const filenamePatterns = contentType ? EXTENSIONS_FOR_CONTENT_TYPE[contentType] : undefined;
  if ((!hostMode || contentType !== undefined) && !filenamePatterns)
    throw new Error(
      `expectedContentType "${contentType}" has no built-in filename extension; cannot compile adapter`,
    );

  const spec: SafeDownloadSpec<SafeDownloadInput> = {
    expectedContentType: contentType,
    validateInput(input: unknown): SafeDownloadInput {
      if (input === null || typeof input !== "object" || Array.isArray(input))
        throw new Error("Download input must be an object");
      const v = input as Record<string, unknown>;
      const keys = Object.keys(v).sort();
      const expected = hostMode
        ? ["filename", "url"]
        : ["filename", ...Object.keys(compiledFields)];
      expected.sort();
      if (keys.length !== expected.length || !keys.every((k, i) => k === expected[i])) {
        throw new Error("Download input has unknown or missing fields");
      }
      const filename = v.filename;
      if (typeof filename !== "string") throw new Error("Download input filename must be a string");
      if (
        (hostMode
          ? !isGenericFilename(filename)
          : !filenamePatterns?.some((re) => re.test(filename))) ||
        WINDOWS_DEVICE.test(filename)
      )
        throw new Error("Download input filename invalid");
      if (hostMode) {
        if (filenamePatterns && !filenamePatterns.some((re) => re.test(filename)))
          throw new Error("Download input filename invalid");
        if (
          !Object.prototype.hasOwnProperty.call(v, "filename") ||
          !Object.prototype.hasOwnProperty.call(v, "url")
        )
          throw new Error("Download input has unknown or missing fields");
        if (typeof v.url !== "string") throw new Error("Download input url must be a string");
        return { filename, url: validateHostUrl(v.url, host) } as SafeDownloadInput;
      }
      const out: Record<string, string> = { filename };
      for (const [name, shape] of Object.entries(compiledFields)) {
        const value = v[name];
        if (typeof value !== "string") throw new Error(`Download input ${name} is required`);
        if (!shapeMatches(shape, value)) throw new Error(`Invalid download ${name}`);
        out[name] = value;
      }
      return out as SafeDownloadInput;
    },
    buildUrl(input: SafeDownloadInput): string {
      if (hostMode) return validateHostUrl(input.url, host);
      const path = renderPathTemplate(pathTemplate, input as Record<string, string>);
      const url = new URL(`https://${host}${path}`);
      if (url.host !== host) throw new Error("Download URL host differs from declared");
      return url.toString();
    },
    validateContent(bytes: Uint8Array): void {
      validateContentByName(contentValidator, bytes);
    },
  };

  return {
    spec,
    config: {
      root: config.root,
      host,
      mode: hostMode ? "host" : "template",
      pathTemplate,
      expectedContentType: contentType,
      contentValidator,
      maxBytes,
      timeoutMs,
      fields: compiledFields,
    },
  };
}

// ===== compile-shape + matching =====

function compileShape(shape: unknown): FieldShapeSpec {
  // Accept both flat and wrapped shapes so existing user configs keep
  // working. The canonical form documented in the README is the flat
  // shape: `"objectId": "uuid"` or `"collection": { "enum": [...] }`.
  // The wrapped form `"objectId": { "shape": "uuid" }` is tolerated for
  // backward compatibility with v0.2.x migrations and is unwrapped here.
  if (typeof shape === "string") {
    if (!(shape in SHAPE_PATTERNS)) throw new Error(`Unknown field shape "${shape}"`);
    return shape as FieldShapeName;
  }
  if (shape === null || typeof shape !== "object" || Array.isArray(shape)) {
    throw new Error(
      `Invalid field shape ${JSON.stringify(shape)}: expected a shape name (uuid|num|slug|hex32|hex64) or { enum: [...] }`,
    );
  }
  let rawShape: unknown = shape;
  if ("shape" in (shape as Record<string, unknown>)) {
    const wrapper = shape as Record<string, unknown>;
    if (Object.keys(wrapper).length !== 1) {
      throw new Error(
        `Wrapped field shape must have exactly one "shape" key, got ${JSON.stringify(wrapper)}`,
      );
    }
    rawShape = wrapper.shape;
  }
  if (typeof rawShape === "string") {
    if (!(rawShape in SHAPE_PATTERNS)) throw new Error(`Unknown field shape "${rawShape}"`);
    return rawShape as FieldShapeName;
  }
  if (
    rawShape === null ||
    typeof rawShape !== "object" ||
    Array.isArray(rawShape) ||
    !Array.isArray((rawShape as { enum?: unknown[] }).enum) ||
    (rawShape as { enum: unknown[] }).enum.length === 0 ||
    !(rawShape as { enum: unknown[] }).enum.every(
      (v) => typeof v === "string" && v.length > 0 && /^[a-z0-9-]+$/.test(v),
    )
  )
    throw new Error("enum shape must be a non-empty list of [a-z0-9-]+ values");
  // Snapshot so callers cannot mutate after compilation.
  return { enum: Object.freeze([...(rawShape as { enum: string[] }).enum]) };
}

function shapeMatches(shape: FieldShapeSpec, value: string): boolean {
  if (typeof shape === "string") return SHAPE_PATTERNS[shape].test(value);
  return shape.enum.some((v) => v === value);
}

// ===== template rendering =====

const PLACEHOLDER_RE = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

function resolvePathTemplate(raw: string, fieldNames: readonly string[]): string {
  if (typeof raw !== "string") throw new Error("pathTemplate must be a string");
  if (!raw.startsWith("/")) throw new Error("pathTemplate must start with /");
  if (raw.includes("?")) throw new Error("pathTemplate must not contain query string");
  if (raw.includes("#")) throw new Error("pathTemplate must not contain fragment");
  if (raw.includes("//")) throw new Error("pathTemplate must not contain empty path segment");
  if (raw.includes("..")) throw new Error("pathTemplate must not contain .. segments");
  const known = new Set(fieldNames);
  const seen = new Set<string>();
  let result = "";
  let lastIndex = 0;
  // Reset stateful regex (PLACEHOLDER_RE is module-level).
  PLACEHOLDER_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = PLACEHOLDER_RE.exec(raw)) !== null) {
    const [whole, key] = m;
    if (!known.has(key)) throw new Error(`pathTemplate has unknown placeholder {${key}}`);
    seen.add(key);
    result += `${raw.slice(lastIndex, m.index)}{${key}}`;
    lastIndex = m.index + whole.length;
  }
  result += raw.slice(lastIndex);
  for (const name of fieldNames) {
    if (!seen.has(name)) throw new Error(`pathTemplate missing placeholder for field "${name}"`);
  }
  return result;
}

function renderPathTemplate(template: string, values: Record<string, string>): string {
  // Values are already shape-validated by validateInput; we still escape any
  // remaining `{` or `}` defensively so a future bug in shape regexes can't
  // produce a half-rendered URL.
  return template.replace(PLACEHOLDER_RE, (_m, key: string) => {
    const v = values[key];
    if (typeof v !== "string") throw new Error(`Missing field "${key}" during URL render`);
    if (v.includes("/") || v.includes("?") || v.includes("#") || v.includes("\\") || v.length === 0)
      throw new Error(`Field "${key}" value contains forbidden characters`);
    return v;
  });
}

// ===== helpers =====

function requireValidHost(host: unknown): string {
  if (typeof host !== "string" || host.length === 0)
    throw new Error("Download host must be a non-empty string");
  const lower = host.toLowerCase();
  if (lower !== host) throw new Error("Download host must be lowercase");
  for (const label of lower.split(".")) {
    if (!VALID_HOST_LABEL.test(label))
      throw new Error(`Download host label "${label}" is not valid`);
  }
  if (!VALID_HOST.test(lower)) throw new Error(`Download host "${host}" is not valid`);
  if (lower.includes(":") || lower.includes("/") || lower.includes("@"))
    throw new Error("Download host must be hostname only (no scheme/port/path/userinfo)");
  return lower;
}

function normalizeContentType(value: unknown): string {
  if (typeof value !== "string") throw new Error("expectedContentType must be a string");
  const trimmed = value.split(";", 1)[0].trim().toLowerCase();
  if (trimmed.length === 0) throw new Error("expectedContentType must not be empty");
  return trimmed;
}

function isGenericFilename(filename: string): boolean {
  return (
    filename !== "." &&
    filename !== ".." &&
    !filename.endsWith(".") &&
    filename.length <= 128 &&
    /^[a-z0-9][a-z0-9_.-]*$/.test(filename) &&
    !filename.includes("/") &&
    !filename.includes("\\")
  );
}

function validateHostUrl(raw: unknown, host: string): string {
  if (typeof raw !== "string" || !/^https:\/\//i.test(raw))
    throw new Error("Download URL must be an absolute HTTPS URL");
  if (
    /\s/.test(raw) ||
    raw.includes("\\") ||
    raw.includes("#") ||
    [...raw].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
  )
    throw new Error("Download URL contains forbidden characters");
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("Download URL is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname !== host ||
    (parsed.port !== "" && parsed.port !== "443")
  )
    throw new Error("Download URL host differs from declared");
  if (parsed.username !== "" || parsed.password !== "")
    throw new Error("Download URL must not contain credentials");
  if (
    raw
      .slice(raw.indexOf("://") + 3)
      .split(/[/?]/, 1)[0]
      .includes("@")
  )
    throw new Error("Download URL must not contain credentials");
  return parsed.toString();
}

function clamp(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  if (value < min) return min;
  if (value > max) return max;
  return value;
}
