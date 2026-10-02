// content-validators.ts
//
// Palette of named, bounded, content-shape validators for the generic
// download adapter (see `./safe-download.ts` and `./download-adapter.ts`).
//
// A user-facing `downloads.<id>.contentValidator` MUST be one of these
// names. Adding a new validator is a code change — that is the security
// shape: a JSON-shaped config cannot invent new code.
//
// Every validator here:
//   - throws a string-prefixed Error on rejection
//   - returns void on success
//   - is pure (no I/O, no globals beyond crc32)
//   - rejects payloads whose declared dimensions exceed the safe-download
//     size cap even when their on-disk size would fit (current devs:
//     ≤ 400 × 400 like the original pixellab one — the small-asset theme
//     is preserved across the palette so that a future caller can't turn
//     this into a generic image scraper).

import { inflateSync } from "node:zlib";

export const CONTENT_VALIDATOR_NAMES = ["png", "jpeg", "webp", "text/plain", "none"] as const;

export type ContentValidatorName = (typeof CONTENT_VALIDATOR_NAMES)[number];

export function isContentValidatorName(value: unknown): value is ContentValidatorName {
  return (
    typeof value === "string" && (CONTENT_VALIDATOR_NAMES as readonly string[]).includes(value)
  );
}

// ===== PNG =====
//
// Verbatim port of the previous pixellab PNG decoder. Same defenses:
//   - 8-byte magic, then chunk walk with length+type+crc check.
//   - Mandatory IHDR first; non-interlaced (Adam7 byte=0) only.
//   - Width and height each ≤ 400 px.
//   - Color types 0/3/2/4/6 with the documented depths only.
//   - IDAT chunks must be consecutive and end with IEND.
//   - PLTE optional but, when present, must precede IDAT.
//   - Scanline-filter validation after zlib inflation to the
//     expected-compressed raw-decompressed byte count.
const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const PNG_MAX_DIMENSION = 400;

export function validatePng(data: Uint8Array): void {
  if (data.length < 33 || !PNG_SIGNATURE.every((b, i) => data[i] === b))
    throw new Error("Invalid PNG signature");
  let offset = 8;
  let chunks = 0;
  let hasIdat = false;
  let hasIend = false;
  let width = 0;
  let height = 0;
  let bitsPerPixel = 0;
  let indexed = false;
  let hasPalette = false;
  let endedIdat = false;
  const compressed: Uint8Array[] = [];
  while (offset < data.length) {
    if (data.length - offset < 12) throw new Error("Truncated PNG chunk");
    const length = new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0);
    if (length > data.length - offset - 12) throw new Error("Truncated PNG data");
    const type = data.subarray(offset + 4, offset + 8);
    const typeName = String.fromCharCode(...type);
    if (!/^[A-Za-z]{4}$/.test(typeName)) throw new Error("Invalid PNG chunk type");
    const body = data.subarray(offset + 8, offset + 8 + length);
    const given = new DataView(data.buffer, data.byteOffset + offset + 8 + length, 4).getUint32(0);
    const crcInput = new Uint8Array(4 + body.length);
    crcInput.set(type);
    crcInput.set(body, 4);
    if (crc32(crcInput) !== given) throw new Error("Invalid PNG CRC");
    if (chunks++ === 0) {
      if (typeName !== "IHDR" || length !== 13) throw new Error("Invalid PNG IHDR");
      const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
      width = view.getUint32(0);
      height = view.getUint32(4);
      if (
        view.getUint32(0) === 0 ||
        view.getUint32(4) === 0 ||
        view.getUint32(0) > PNG_MAX_DIMENSION ||
        view.getUint32(4) > PNG_MAX_DIMENSION
      ) {
        throw new Error("PNG dimensions out of bounds");
      }
      const depth = body[8];
      const color = body[9];
      const allowedDepths: Record<number, readonly number[]> = {
        0: [1, 2, 4, 8, 16],
        2: [8, 16],
        3: [1, 2, 4, 8],
        4: [8, 16],
        6: [8, 16],
      };
      const channels: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };
      if (
        !allowedDepths[color]?.includes(depth) ||
        body[10] !== 0 ||
        body[11] !== 0 ||
        body[12] !== 0
      )
        throw new Error("Unsupported PNG header (non-interlaced PNG required)");
      indexed = color === 3;
      bitsPerPixel = depth * channels[color];
    } else if (typeName === "IHDR") {
      throw new Error("Duplicate PNG IHDR");
    }
    if (typeName === "PLTE") {
      if (hasPalette || hasIdat || length === 0 || length > 768 || length % 3 !== 0)
        throw new Error("Invalid PNG palette");
      hasPalette = true;
    }
    if (typeName === "IDAT") {
      if (endedIdat) throw new Error("Non-consecutive PNG IDAT chunks");
      hasIdat = true;
      compressed.push(body);
    } else if (hasIdat) {
      endedIdat = true;
    }
    if (
      typeName !== "IHDR" &&
      typeName !== "PLTE" &&
      typeName !== "IDAT" &&
      typeName !== "IEND" &&
      typeName[0] === typeName[0].toUpperCase()
    )
      throw new Error("Unknown critical PNG chunk");
    if (typeName === "IEND") {
      if (length !== 0) throw new Error("Invalid PNG IEND");
      hasIend = true;
      offset += 12;
      break;
    }
    offset += 12 + length;
  }
  if (!hasIdat || !hasIend || offset !== data.length) throw new Error("Incomplete PNG");
  if (indexed && !hasPalette) throw new Error("Indexed PNG requires a palette");
  const rowBytes = Math.ceil((width * bitsPerPixel) / 8) + 1;
  const expectedBytes = rowBytes * height;
  const inflated = inflateSync(Buffer.concat(compressed), { maxOutputLength: expectedBytes + 1 });
  if (inflated.length !== expectedBytes) throw new Error("Invalid PNG scanline size");
  for (let row = 0; row < height; row++) {
    if (inflated[row * rowBytes] > 4) throw new Error("Invalid PNG scanline filter");
  }
}

// ===== JPEG =====
//
// Bounds the same way as PNG: SOI/EOI markers present; SOF0/SOF2
// segments parsed to extract width and height; each ≤ 400 px. We do
// NOT attempt to validate Huffman tables, quantization tables or
// entropy coding — the goal is to reject clearly-wrong content and
// sized-too-large content, not to be a hardened JPEG decoder. The
// primitive's `expectedContentType` + size cap + redirect-error is the
// primary defense; this validator just stops the LLM from getting
// non-image data through a JPEG-shaped tool.
const JPEG_SOI = 0xd8;
const JPEG_EOI = 0xd9;
const JPEG_MARKER = 0xff;
const JPEG_SOF0 = 0xc0;
const JPEG_SOF1 = 0xc1;
const JPEG_SOF2 = 0xc2;
const JPEG_SOF3 = 0xc3;
const JPEG_SOF5 = 0xc5;
const JPEG_SOF6 = 0xc6;
const JPEG_SOF7 = 0xc7;
const JPEG_SOF9 = 0xc9;
const JPEG_SOF10 = 0xca;
const JPEG_SOF11 = 0xcb;
const JPEG_SOF13 = 0xcd;
const JPEG_SOF14 = 0xce;
const JPEG_SOF15 = 0xcf;
const JPEG_SOF_NAMES = new Set<number>([
  JPEG_SOF0,
  JPEG_SOF1,
  JPEG_SOF2,
  JPEG_SOF3,
  JPEG_SOF5,
  JPEG_SOF6,
  JPEG_SOF7,
  JPEG_SOF9,
  JPEG_SOF10,
  JPEG_SOF11,
  JPEG_SOF13,
  JPEG_SOF14,
  JPEG_SOF15,
]);

export function validateJpeg(data: Uint8Array): void {
  if (data.length < 4) throw new Error("Invalid JPEG: too short");
  if (data[0] !== JPEG_MARKER || data[1] !== JPEG_SOI) throw new Error("Invalid JPEG SOI");
  let offset = 2;
  let sawSof = false;
  while (offset < data.length) {
    if (data[offset] !== JPEG_MARKER) throw new Error("Invalid JPEG marker");
    while (offset < data.length && data[offset] === JPEG_MARKER) offset++;
    if (offset >= data.length) break;
    const marker = data[offset];
    offset++;
    if (marker === JPEG_EOI) {
      if (!sawSof) throw new Error("JPEG has no frame");
      return;
    }
    if (marker === 0x01) continue; // TEM, no body
    if (offset + 1 >= data.length) throw new Error("Truncated JPEG segment");
    const segLen = (data[offset] << 8) | data[offset + 1];
    if (segLen < 2) throw new Error("Invalid JPEG segment length");
    if (JPEG_SOF_NAMES.has(marker)) {
      if (segLen < 7) throw new Error("Invalid JPEG SOF length");
      if (offset + 7 > data.length) throw new Error("Truncated JPEG SOF");
      const height = (data[offset + 3] << 8) | data[offset + 4];
      const width = (data[offset + 5] << 8) | data[offset + 6];
      if (width === 0 || height === 0) throw new Error("JPEG dimensions zero");
      if (width > PNG_MAX_DIMENSION || height > PNG_MAX_DIMENSION)
        throw new Error("JPEG dimensions out of bounds");
      sawSof = true;
      // After SOF, scan for the next non-stuffed marker (EOI). SOS +
      // entropy-coded data may contain raw 0xff bytes that are not
      // markers — without decoding the entropy stream we cannot walk
      // segment lengths. So once we've confirmed SOF, scan forward
      // for the next MARKER followed by a non-zero byte (the standard
      // 0xff 0x00 stuffing rule).
      offset += segLen - 2;
      let nextMarker = -1;
      for (let i = offset + 1; i < data.length; i++) {
        if (data[i - 1] === JPEG_MARKER && data[i] !== 0x00) {
          nextMarker = i - 1;
          break;
        }
      }
      if (nextMarker === -1) throw new Error("JPEG has no EOI");
      if (data[nextMarker + 1] !== JPEG_EOI) throw new Error("JPEG has no EOI");
      return;
    }
    offset += segLen - 2;
  }
  if (!sawSof) throw new Error("JPEG has no frame");
}

// ===== WebP =====
//
// RIFF / WEBP header, then a chunk walk over VP8 / VP8L / VP8X / ALPH.
// VP8X (extended) carries width/height as little-endian 24-bit minus one.
// VP8 / VP8L carry their dimensions inside the bitstream — we extract
// them with a narrow parser. Width / height each ≤ 400 px.
const WEBP_RIFF = [0x52, 0x49, 0x46, 0x46];
const WEBP_WEBP = [0x57, 0x45, 0x42, 0x50];
const WEBP_VP8 = [0x56, 0x50, 0x38, 0x20];
const WEBP_VP8L = [0x56, 0x50, 0x38, 0x4c];
const WEBP_VP8X = [0x56, 0x50, 0x38, 0x58];
const WEBP_ALPH = [0x41, 0x4c, 0x50, 0x48];

function eq4(buf: Uint8Array, offset: number, sig: readonly number[]): boolean {
  return (
    buf[offset] === sig[0] &&
    buf[offset + 1] === sig[1] &&
    buf[offset + 2] === sig[2] &&
    buf[offset + 3] === sig[3]
  );
}

function readU32LE(buf: Uint8Array, offset: number): number {
  return (
    (buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16) | (buf[offset + 3] << 24)) >>> 0
  );
}

export function validateWebp(data: Uint8Array): void {
  if (data.length < 12) throw new Error("Invalid WebP: too short");
  if (!eq4(data, 0, WEBP_RIFF)) throw new Error("Invalid WebP RIFF");
  if (!eq4(data, 8, WEBP_WEBP)) throw new Error("Invalid WebP WEBP");
  const size = readU32LE(data, 4);
  if (size + 8 !== data.length) throw new Error("Invalid WebP RIFF size");
  let offset = 12;
  let sawFrame = false;
  let width = 0;
  let height = 0;
  while (offset + 8 <= data.length) {
    const fourcc = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]] as const;
    const chunkSize = readU32LE(data, offset + 4);
    const padded = chunkSize % 2 === 0 ? chunkSize : chunkSize + 1;
    if (offset + 8 + chunkSize > data.length) throw new Error("Truncated WebP chunk");
    const body = data.subarray(offset + 8, offset + 8 + chunkSize);
    if (eq4(fourcc as unknown as Uint8Array, 0, WEBP_VP8X)) {
      if (body.length < 10) throw new Error("Invalid WebP VP8X");
      width = ((body[0] | (body[1] << 8) | (body[2] << 16)) & 0xffffff) + 1;
      height = ((body[3] | (body[4] << 8) | (body[5] << 16)) & 0xffffff) + 1;
      sawFrame = true;
    } else if (eq4(fourcc as unknown as Uint8Array, 0, WEBP_VP8)) {
      // Lossy VP8 bitstream: 3-byte frame tag, then a 7-byte keyframe
      // header (signature 0x9d 0x01 0x2a + width 16-bit LE + height 16-bit LE).
      if (body.length < 10) throw new Error("Invalid WebP VP8");
      const signature = body[3] | (body[4] << 8) | (body[5] << 16);
      if (signature === 0x9d012a) {
        width = (body[6] | (body[7] << 8)) & 0x3fff;
        height = (body[8] | (body[9] << 8)) & 0x3fff;
        sawFrame = true;
      }
    } else if (eq4(fourcc as unknown as Uint8Array, 0, WEBP_VP8L)) {
      // Lossless VP8L: signature byte 0x2f, then 14-bit width-1 + 14-bit
      // height-1 packed into 4 little-endian bytes.
      if (body.length < 5) throw new Error("Invalid WebP VP8L");
      if (body[0] !== 0x2f) throw new Error("Invalid WebP VP8L signature");
      const bits = body[1] | (body[2] << 8) | (body[3] << 16) | (body[4] << 24);
      width = (bits & 0x3fff) + 1;
      height = ((bits >>> 14) & 0x3fff) + 1;
      sawFrame = true;
    } else if (eq4(fourcc as unknown as Uint8Array, 0, WEBP_ALPH)) {
      // ALPH chunk is allowed and ignored for dimension purposes.
    } else {
      throw new Error("Unknown WebP chunk");
    }
    offset += 8 + padded;
  }
  if (!sawFrame) throw new Error("WebP has no frame");
  if (width === 0 || height === 0) throw new Error("WebP dimensions zero");
  if (width > PNG_MAX_DIMENSION || height > PNG_MAX_DIMENSION)
    throw new Error("WebP dimensions out of bounds");
}

// ===== text/plain =====
//
// Strict UTF-8 byte-level validation (no replacement chars after
// decoding the U+FFFD fallback), capped at the SAFE_DOWNLOAD_MAX_BYTES
// bound — which is enforced upstream. We also reject lone CR (used by
// some legacy escape sequences to inject a control char) and any
// NUL byte.
export function validateTextPlain(data: Uint8Array): void {
  // Reject NUL bytes outright — there is no legitimate plain-text asset
  // we want this guard to swallow that contains a NUL.
  for (let i = 0; i < data.length; i++) {
    if (data[i] === 0x00) throw new Error("Invalid text/plain: NUL byte");
  }
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(data);
  for (let i = 0; i < decoded.length; i++) {
    if (decoded.charCodeAt(i) === 0xfffd) throw new Error("Invalid text/plain: invalid UTF-8");
  }
}

// ===== none =====
//
// Identity. The primitive already enforces expectedContentType and
// maxBytes; this validator exists so the user can ship a payload whose
// shape the palette doesn't yet cover (raw text, manifest, signature
// blob) without disabling the gate.
export function validateNone(_data: Uint8Array): void {
  return;
}

// ===== dispatcher =====

export function validateContentByName(name: ContentValidatorName, data: Uint8Array): void {
  switch (name) {
    case "png":
      validatePng(data);
      return;
    case "jpeg":
      validateJpeg(data);
      return;
    case "webp":
      validateWebp(data);
      return;
    case "text/plain":
      validateTextPlain(data);
      return;
    case "none":
      validateNone(data);
      return;
  }
}

// ===== shared CRC32 (used by PNG) =====

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
