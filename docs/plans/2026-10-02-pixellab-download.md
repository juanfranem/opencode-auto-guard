# Safe PixelLab Downloader Implementation Plan

> **For Codex:** Execute these scoped tasks in this repository; no deployment, configuration edits, commits or downloads without separate authorization.

**Goal:** Download approved PixelLab PNGs through a constrained tool without relaxing the shell guard.

**Architecture:** An opt-in absolute directory enables a dedicated tool. The agent supplies only an object UUID and PNG basename. A fixed-origin GET, bounded PNG validation and exclusive file creation replace shell execution. The existing permission hook always requests confirmation and preserves denials and session limits.

**Tech Stack:** TypeScript, OpenCode V2 plugin SDK, Node filesystem/fetch/zlib, Bun test scripts.

---

### Task 1: Download primitive and adversarial tests

- Create `src/pixellab-download.ts` and `src/tests/pixellab-download-test.ts`.
- Reject extra input keys, invalid UUIDs, paths and filenames; construct the URL internally.
- Require an existing absolute directory, reject symlink ancestors and protected paths.
- GET only, no redirects/credentials; timeout and streamed size cap.
- Validate PNG data before exclusive creation; existing files must remain unchanged.
- Test with injected HTTP responses, never live network requests.
- Run `bun src/tests/pixellab-download-test.ts`.

### Task 2: Tool registration and permission policy

- Create `src/pixellab-tool.ts` and `src/tests/pixellab-tool-test.ts`.
- Register only when `pixellabDownloadRoot` is explicitly configured.
- Set the tool's permission action to `pixellab_download`; force ask, preserving deny.
- Keep `Invoke-WebRequest` in `HARD_DENY`.
- Wire registration, session action counting and audit entries in `src/index.ts`.
- Add runtime modules to package `files` and tests to package scripts.
- Run registration tests and `bun run typecheck`.

### Task 3: Review and documentation

- Document configuration and limitations in `README.md` and `docs/SECURITY.md`.
- Run `bun run check`; request security review of downloader and permission wiring.
- Do not claim immunity to a hostile local process that can rename directory ancestors;
  root must be owned by the user and not writable by untrusted processes.
- Explain activation against the local working tree (Git dependency caches do not use uncommitted changes).
