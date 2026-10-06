// safe-download.ts
//
// Generic primitive for downloading a single, bounded, validated file from a
// fixed-origin HTTPS endpoint into a pre-approved absolute directory.
//
// This module is intentionally source-agnostic. Adapters layer on top by
// supplying three pure functions plus an optional `expectedContentType`:
//   - validateInput(input)        -> { filename, ... }
//   - buildUrl(input)             -> string  (caller-owned origin/host)
//   - validateContent(bytes)      -> void    (throws on rejection)
//   - expectedContentType         -> string | undefined (e.g. "image/png")
//
// The adapters in `download-adapter.ts` compose this primitive from a
// declarative config; the spec is compiled once at registration time.
//
// Defenses applied here (every caller inherits them):
//   - configuredRoot must be absolute, non-network, no dot segments.
//   - every ancestor of configuredRoot is lstat-checked for reparse points
//     and verified to resolve to its lexical path.
//   - configuredRoot identity is captured before the network call and
//     re-checked after the download and again after the exclusive open.
//   - destination must not pre-exist (ENOENT check before the network call).
//   - destination is created with `fs.open(..., "wx")`; cleanup removes only
//     the inode obtained by our exclusive open.
//   - fetch: GET only, `redirect: "error"`, `credentials: "omit"`, signal
//     aborts on caller cancellation OR the configurable timeout.
//   - response: HTTP 200, exact-match content-type when configured, streamed size
//     cap of MAX_BYTES (1 MiB by default).
//   - payload is passed to the caller-supplied validator before any write.
//   - generic file-tool hooks are NOT invoked for this download — the
//     executor itself performs stricter checks than the generic hook.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isProtectedPath } from "./rules";

export const SAFE_DOWNLOAD_MAX_BYTES = 1024 * 1024;
export const SAFE_DOWNLOAD_TIMEOUT_MS = 30_000;

/**
 * Returned shape from a caller-supplied `validateInput`. The only required
 * field is `filename`; everything else is opaque to this primitive and is
 * forwarded to `buildUrl`. Keeping the contract minimal here means each
 * adapter keeps its own input schema.
 */
export interface SafeDownloadInput {
  filename: string;
  [key: string]: unknown;
}

/**
 * Adapter-supplied behavior. The primitive composes these pieces with its
 * own filesystem/network defenses; nothing else leaks across the seam.
 */
export interface SafeDownloadSpec<TInput extends SafeDownloadInput = SafeDownloadInput> {
  /** Strict input validation. Throws on any malformed input. */
  validateInput(input: unknown): TInput;
  /** Construct the fixed-origin URL. Receives the validated input. */
  buildUrl(input: TInput): string;
  /** Validate the downloaded bytes. Throws on rejection. */
  validateContent(bytes: Uint8Array): void;
  /**
   * Exact content-type (lowercased, parameter-stripped) the response must
   * carry when configured. Omit for host mode with unrestricted response types.
   */
  expectedContentType?: string;
}

export interface SafeDownloadDependencies {
  /** Test injection only; production callers leave this unset. */
  fetch?: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  signal?: AbortSignal;
  /** Per-request network timeout in ms. Defaults to SAFE_DOWNLOAD_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Per-download byte budget, at most SAFE_DOWNLOAD_MAX_BYTES (1 MiB). */
  maxBytes?: number;
}

export interface SafeDownloadResult {
  path: string;
  bytes: number;
}

export async function safeDownloadFile<TInput extends SafeDownloadInput>(
  input: unknown,
  spec: SafeDownloadSpec<TInput>,
  configuredRoot: string,
  protectedPaths: readonly string[],
  dependencies: SafeDownloadDependencies = {},
): Promise<SafeDownloadResult> {
  const valid = spec.validateInput(input);
  const maxBytes = dependencies.maxBytes ?? SAFE_DOWNLOAD_MAX_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > SAFE_DOWNLOAD_MAX_BYTES)
    throw new Error("Download maxBytes must be an integer between 1 and 1048576");
  if (!path.isAbsolute(configuredRoot)) throw new Error("Download root must be absolute");
  if (configuredRoot.startsWith("\\\\") || configuredRoot.startsWith("//"))
    throw new Error("Network/device download roots are not allowed");
  if (configuredRoot.split(/[\\/]+/).some((part) => part === "." || part === ".."))
    throw new Error("Download root cannot contain dot segments");
  const root = path.resolve(configuredRoot);
  const rootStats = await lstatNoLinks(root);
  const destination = path.join(root, valid.filename);
  if (
    isProtectedPath(root, [...protectedPaths]) ||
    isProtectedPath(destination, [...protectedPaths])
  )
    throw new Error("Download path is protected");
  try {
    await fs.lstat(destination);
    throw new Error("Download destination already exists");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    dependencies.timeoutMs ?? SAFE_DOWNLOAD_TIMEOUT_MS,
  );
  const signal = dependencies.signal
    ? AbortSignal.any([controller.signal, dependencies.signal])
    : controller.signal;
  let bytes: Uint8Array;
  try {
    signal.throwIfAborted();
    const response = await (dependencies.fetch ?? globalThis.fetch)(spec.buildUrl(valid), {
      method: "GET",
      redirect: "error",
      credentials: "omit",
      signal,
    });
    bytes = await readBoundedResponse(response, spec.expectedContentType, maxBytes);
    signal.throwIfAborted();
    spec.validateContent(bytes);
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
  dependencies.signal?.throwIfAborted();
  if (!(await samePathStats(root, rootStats)))
    throw new Error("Download root changed during download");
  // Identity checks close ordinary rename/symlink races; hostile OS-level renames
  // between individual syscalls cannot be made fully atomic on every platform.
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  let owned: { dev: number; ino: number } | undefined;
  try {
    dependencies.signal?.throwIfAborted();
    handle = await fs.open(destination, "wx");
    const opened = await handle.stat();
    owned = { dev: opened.dev, ino: opened.ino };
    if (!(await samePathStats(root, rootStats)))
      throw new Error("Download root changed before write");
    dependencies.signal?.throwIfAborted();
    await handle.writeFile(bytes);
    await handle.close();
    handle = undefined;
    return { path: destination, bytes: bytes.length };
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    try {
      const st = await fs.lstat(destination);
      // Only remove the inode obtained by our exclusive open; never remove a prior file.
      if (owned && st.isFile() && st.dev === owned.dev && st.ino === owned.ino)
        await fs.unlink(destination);
    } catch {
      /* never replace or remove a pre-existing destination */
    }
    throw error;
  }
}

// ----- filesystem helpers (kept private; pure, no Node-specific imports) -----

async function lstatNoLinks(p: string): Promise<Awaited<ReturnType<typeof fs.lstat>>[]> {
  if (!path.isAbsolute(p)) throw new Error("Download root must be absolute");
  const parsed = path.parse(p);
  const parts = p
    .slice(parsed.root.length)
    .split(/[\\/]+/)
    .filter(Boolean);
  let current = parsed.root;
  const stats: Awaited<ReturnType<typeof fs.lstat>>[] = [];
  const rootStat = await fs.lstat(current);
  if (rootStat.isSymbolicLink())
    throw new Error("Download root contains a symlink or reparse point");
  stats.push(rootStat);
  for (const part of parts) {
    current = path.join(current, part);
    const st = await fs.lstat(current);
    if (st.isSymbolicLink()) throw new Error("Download root contains a symlink or reparse point");
    // Identity check (dev/ino between lstat and stat) catches the real attack
    // surface on both platforms:
    //   - POSIX symlinks: lstat differs from stat.
    //   - Windows directory junctions: lstat returns the junction's inode,
    //     stat returns the target's inode — they differ.
    //   - bind mounts / cross-device swaps: dev differs.
    // We deliberately skip a "lexical vs resolved path string" comparison on
    // Windows because GitHub Actions runners (and other Windows hosts) resolve
    // benign temp paths through 8.3 short names (`RUNNER~1` vs the full
    // user name). Bun 1.4.x's `fs.realpath` returns the long form, the
    // lexical path keeps the short form, and the comparison false-positives
    // on a perfectly legitimate tempdir. On POSIX the lexical/resolved check is
    // kept below because it surfaces aliasing the dev/ino check cannot see
    // (e.g. bind-mounted subtree under a different visible path).
    if (process.platform !== "win32") {
      const resolved = path.resolve(await fs.realpath(current));
      const lexical = path.resolve(current);
      if (resolved !== lexical) throw new Error("Download root resolves to a different path");
    }
    const followed = await fs.stat(current);
    if (st.dev !== followed.dev || st.ino !== followed.ino)
      throw new Error("Download root resolves to a different identity");
    stats.push(st);
  }
  if (!stats[stats.length - 1].isDirectory()) throw new Error("Download root is not a directory");
  return stats;
}

async function samePathStats(
  root: string,
  before: Awaited<ReturnType<typeof lstatNoLinks>>,
): Promise<boolean> {
  try {
    const after = await lstatNoLinks(root);
    return (
      after.length === before.length &&
      after.every((s, i) => s.dev === before[i].dev && s.ino === before[i].ino)
    );
  } catch {
    return false;
  }
}

async function readBoundedResponse(
  response: Response,
  expectedContentType: string | undefined,
  maxBytes: number,
): Promise<Uint8Array> {
  const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (response.status !== 200) throw new Error(`Download returned HTTP ${response.status}`);
  if (expectedContentType !== undefined && contentType !== expectedContentType.toLowerCase())
    throw new Error(`Download returned unsupported content-type: ${contentType ?? "<missing>"}`);
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes))
    throw new Error("Download is too large");
  if (!response.body) throw new Error("Download has no body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
    total += chunk.byteLength;
    if (total > maxBytes) throw new Error("Download is too large");
    chunks.push(chunk);
  }
  const result = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    result.set(chunk, at);
    at += chunk.length;
  }
  return result;
}
