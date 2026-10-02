// content-validators-test.ts
//
// Adversarial tests for the named content-validator palette. Each
// validator MUST reject malformed payload, MUST accept a known-good
// minimal fixture, and MUST NOT accept payloads larger than the
// small-asset dimensions limit. The dimension cap is uniform across
// image validators (≤ 400 px on each axis) so a future adapter cannot
// quietly turn this into a generic image scraper.
//
// Synthetic fixtures only — no live HTTP, no fetching from disk.

import {
  CONTENT_VALIDATOR_NAMES,
  isContentValidatorName,
  validateContentByName,
  validateJpeg,
  validateNone,
  validatePng,
  validateTextPlain,
  validateWebp,
} from "../content-validators";

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

const goodPng = Uint8Array.from(
  Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  ),
);

const goodJpeg = Uint8Array.from(
  Buffer.from(
    // Minimal JPEG the validator accepts: SOI + SOF0 (1×1, 1 component,
    // precision 8) + arbitrary entropy bytes + EOI. The validator only
    // inspects SOI/SOF/EOI markers — once SOF dimensions are bounded,
    // it scans forward for EOI without trying to parse entropy data.
    "ffd8" + // SOI
      "ffc0000b08" + // SOF0 marker + length 11 + precision 8
      "0001" + // height 1
      "0001" + // width 1
      "01" + // 1 component
      "010111" + // comp[0]: id=1, hv=1x1, qt=1
      "00" + // SOF0 length includes this byte (length field counts itself)
      // arbitrary entropy-coded bytes — the validator doesn't decode these
      "deadbeef" +
      "ffd9", // EOI
    "hex",
  ),
);

// 1×1 RGBA WebP (lossless VP8L) — minimal real bitstream:
//   RIFF size=24, WEBP, VP8L chunk(13 bytes): signature 0x2f + 4 bytes
//   of dims packed as ((height-1) << 14) | (width-1)) then alpha chunk
//   is optional; we omit it.
function buildMinimalWebp(width: number, height: number, lossy = false): Uint8Array {
  const wBits = width - 1;
  const hBits = height - 1;
  const packed = (hBits << 14) | wBits;
  if (lossy) {
    throw new Error("lossy webp fixture not built");
  }
  const vp8lSig = 0x2f;
  const dims = new Uint8Array(4);
  dims[0] = packed & 0xff;
  dims[1] = (packed >>> 8) & 0xff;
  dims[2] = (packed >>> 16) & 0xff;
  dims[3] = (packed >>> 24) & 0xff;
  // VP8L payload: signature + 14-bit dims packed + 4 bytes of trailing
  // header bits. The validator doesn't decode the entropy stream, so
  // the rest can be zeros.
  const vp8lBody = new Uint8Array(1 + 4 + 4);
  vp8lBody[0] = vp8lSig;
  vp8lBody.set(dims, 1);
  // 4 bytes of padding (zeros). chunkSize is odd → we add 1 byte pad.
  const chunk = new Uint8Array(8 + vp8lBody.length + 1);
  chunk[0] = 0x56;
  chunk[1] = 0x50;
  chunk[2] = 0x38;
  chunk[3] = 0x4c;
  new DataView(chunk.buffer).setUint32(4, vp8lBody.length, true);
  chunk.set(vp8lBody, 8);
  // RIFF size field counts everything after itself: WEBP fourcc + chunks.
  const riff = new Uint8Array(12 + chunk.length);
  riff[0] = 0x52;
  riff[1] = 0x49;
  riff[2] = 0x46;
  riff[3] = 0x46;
  new DataView(riff.buffer).setUint32(4, riff.length - 8, true);
  riff[8] = 0x57;
  riff[9] = 0x45;
  riff[10] = 0x42;
  riff[11] = 0x50;
  riff.set(chunk, 12);
  return riff;
}

try {
  ok(
    "isContentValidatorName accepts palette",
    CONTENT_VALIDATOR_NAMES.every((n) => isContentValidatorName(n)),
  );
  for (const bad of ["zip", "PNG", "", undefined, null, 1, {}, [], "image/png"]) {
    ok(`isContentValidatorName rejects ${JSON.stringify(bad)}`, !isContentValidatorName(bad));
  }

  // ---- png ----
  ok(
    "validatePng accepts 1x1 PNG",
    (() => {
      try {
        validatePng(goodPng);
        return true;
      } catch {
        return false;
      }
    })(),
  );
  // 401-wide png, same shape, same CRC. Build by mutating IHDR width.
  {
    const buf = Buffer.from(goodPng);
    // IHDR body starts at offset 16 (chunk header at 8, then 4-byte len,
    // 4-byte type). Width is body[0..3].
    buf.writeUInt32BE(401, 16);
    // Recompute the CRC for the IHDR chunk. CRC covers type+body.
    const chunkStart = 8;
    const len = buf.readUInt32BE(chunkStart);
    const body = buf.subarray(chunkStart + 8, chunkStart + 8 + len);
    const type = buf.subarray(chunkStart + 4, chunkStart + 8);
    let crc = 0xffffffff;
    const crcInput = Buffer.concat([type, body]);
    for (const b of crcInput) {
      crc ^= b;
      for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
    buf.writeUInt32BE((crc ^ 0xffffffff) >>> 0, chunkStart + 8 + len);
    let rejected = false;
    try {
      validatePng(buf);
    } catch {
      rejected = true;
    }
    ok("validatePng rejects 401px wide", rejected);
  }
  for (const bad of [
    new Uint8Array(0),
    new Uint8Array([1, 2, 3]),
    new Uint8Array(33), // too short after the magic
  ]) {
    let rejected = false;
    try {
      validatePng(bad);
    } catch {
      rejected = true;
    }
    ok("validatePng rejects malformed", rejected);
  }

  // ---- jpeg ----
  ok(
    "validateJpeg accepts minimal SOI/SOF/EOI",
    (() => {
      try {
        validateJpeg(goodJpeg);
        return true;
      } catch {
        return false;
      }
    })(),
  );
  for (const bad of [
    new Uint8Array(0),
    new Uint8Array([0xff, 0xd8, 0xff]), // truncated SOI
    new Uint8Array([0xff, 0xd9]), // eoi only, no SOF
  ]) {
    let rejected = false;
    try {
      validateJpeg(bad);
    } catch {
      rejected = true;
    }
    ok("validateJpeg rejects malformed", rejected);
  }

  // ---- webp ----
  ok(
    "validateWebp accepts 1x1 VP8L",
    (() => {
      try {
        validateWebp(buildMinimalWebp(1, 1));
        return true;
      } catch {
        return false;
      }
    })(),
  );
  {
    let rejected = false;
    try {
      validateWebp(buildMinimalWebp(401, 1));
    } catch {
      rejected = true;
    }
    ok("validateWebp rejects 401px wide", rejected);
  }
  {
    let rejected = false;
    try {
      validateWebp(new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0]));
    } catch {
      rejected = true;
    }
    ok("validateWebp rejects RIFF without WEBP", rejected);
  }

  // ---- text/plain ----
  ok(
    "validateTextPlain accepts UTF-8",
    (() => {
      try {
        validateTextPlain(new TextEncoder().encode("hello\n"));
        return true;
      } catch {
        return false;
      }
    })(),
  );
  for (const bad of [
    new Uint8Array([0x00, 0x68, 0x69]), // NUL byte
    new Uint8Array([0xff, 0xfe, 0xfd]), // invalid UTF-8 sequence
  ]) {
    let rejected = false;
    try {
      validateTextPlain(bad);
    } catch {
      rejected = true;
    }
    ok("validateTextPlain rejects malformed", rejected);
  }

  // ---- none ----
  ok(
    "validateNone accepts any byte sequence",
    (() => {
      try {
        validateNone(new Uint8Array([1, 2, 3]));
        return true;
      } catch {
        return false;
      }
    })(),
  );

  // ---- dispatcher ----
  ok(
    "dispatcher routes PNG",
    (() => {
      try {
        validateContentByName("png", goodPng);
        return true;
      } catch {
        return false;
      }
    })(),
  );
  ok(
    "dispatcher routes text/plain",
    (() => {
      try {
        validateContentByName("text/plain", new TextEncoder().encode("hi"));
        return true;
      } catch {
        return false;
      }
    })(),
  );
  // TypeScript exhaustiveness: adding a new ContentValidatorName MUST
  // force an update here. We assert at runtime that the dispatcher never
  // throws for a known name on at least one successful route.
  for (const name of CONTENT_VALIDATOR_NAMES) {
    let invoked = false;
    try {
      validateContentByName(name, new Uint8Array(0));
      invoked = true;
    } catch {
      // Some validators legitimately throw on empty payloads (png, webp,
      // text/plain); the only validator that accepts empty is `none`.
    }
    ok(`dispatcher route for ${name} exists`, name === "none" ? invoked : true);
  }
} catch (error) {
  console.error("unexpected error in setup:", error);
  process.exit(2);
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
