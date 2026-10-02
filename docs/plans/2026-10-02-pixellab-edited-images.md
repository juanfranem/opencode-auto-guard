# Edited PixelLab Images Implementation Plan

**Goal:** Download approved expression edits without bypassing the guard.

**Architecture:** Extend the existing PixelLab adapter with a closed resource-type enum.
The generic safe-download primitive, confirmation policy and shell blocks remain unchanged.

1. Add optional `resourceType: map-object | image`; preserve old two-field inputs.
2. Construct exactly one of two fixed-origin HTTPS paths, with strict UUID validation.
3. Reject invalid/extra fields before network access; keep all PNG, redirect, size,
   root, symlink, exclusive-write and protected-path checks.
4. Expose the enum in the tool schema, document image job UUIDs versus gallery IDs.
5. Add adapter/tool regression tests and run `bun run check`.
6. Restart/reload the local plugin through the user's existing activation workflow.
   Download only the two approved expressions, then register them in the game;
   do not invent gameplay expression rules or generate new images.
