// pixellab-download.ts
//
// PixelLab-specific adapter on top of the generic safe-download primitive
// in `./safe-download`. This file owns:
//   - the strict UUID + PNG basename input schema
//   - the fixed PixelLab HTTPS URL
//   - the bounded PNG validation
// Everything else — root/symlink/identity checks, bounded fetch, exclusive
// no-overwrite creation — lives in `safeDownloadFile` and is reused by any
// future adapter (map tiles, asset packs, etc.).

import { inflateSync } from "node:zlib";
import {
  safeDownloadFile,
  type SafeDownloadDependencies,
  type SafeDownloadInput,
  type SafeDownloadResult,
  type SafeDownloadSpec,
} from "./safe-download";

export interface PixellabDownloadInput extends SafeDownloadInput {
  objectId: string;
  resourceType?: "map-object" | "image";
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FILENAME = /^[a-z][a-z0-9_-]{0,63}\.png$/;
const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])\.png$/i;

export function validatePixellabDownloadInput(input: unknown): PixellabDownloadInput {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Pixellab download input must be an object");
  }
  const value = input as Record<string, unknown>;
  const keys = Object.keys(value).sort();
  if (
    (keys.length !== 2 && keys.length !== 3) ||
    keys[0] !== "filename" ||
    keys[1] !== "objectId" ||
    (keys.length === 3 && keys[2] !== "resourceType")
  ) {
    throw new Error("Pixellab download input has unknown fields");
  }
  if (typeof value.objectId !== "string" || !UUID.test(value.objectId)) {
    throw new Error("Invalid Pixellab objectId");
  }
  if (
    typeof value.filename !== "string" ||
    !FILENAME.test(value.filename) ||
    WINDOWS_DEVICE.test(value.filename)
  ) {
    throw new Error("Invalid Pixellab filename");
  }
  if (keys.length === 3 && value.resourceType !== "map-object" && value.resourceType !== "image") {
    throw new Error("Invalid Pixellab resourceType");
  }
  return keys.length === 3
    ? {
        objectId: value.objectId,
        filename: value.filename,
        resourceType: value.resourceType as "map-object" | "image",
      }
    : { objectId: value.objectId, filename: value.filename };
}

export function buildPixellabDownloadUrl(
  objectId: string,
  resourceType: "map-object" | "image" = "map-object",
): string {
  if (typeof objectId !== "string" || !UUID.test(objectId))
    throw new Error("Invalid Pixellab objectId");
  if (resourceType !== "map-object" && resourceType !== "image")
    throw new Error("Invalid Pixellab resourceType");
  const collection = resourceType === "image" ? "images" : "map-objects";
  return `https://api.pixellab.ai/mcp/${collection}/${objectId}/download`;
}

// ===== PNG validation =====
const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);

export function validatePixellabPng(data: Uint8Array): void {
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
        view.getUint32(0) > 400 ||
        view.getUint32(4) > 400
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

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ===== Adapter composition =====

const pixellabSpec: SafeDownloadSpec<PixellabDownloadInput> = {
  validateInput: validatePixellabDownloadInput,
  buildUrl: (input) => buildPixellabDownloadUrl(input.objectId, input.resourceType),
  validateContent: validatePixellabPng,
};

export async function downloadPixellabPng(
  input: unknown,
  configuredRoot: string,
  protectedPaths: readonly string[],
  dependencies: SafeDownloadDependencies = {},
): Promise<SafeDownloadResult> {
  return safeDownloadFile(input, pixellabSpec, configuredRoot, protectedPaths, dependencies);
}
