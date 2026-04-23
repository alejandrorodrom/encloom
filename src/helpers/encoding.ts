import {
  HEX_ENC,
  LENGTH_0,
  LENGTH_16,
  type UTF8_ENC,
} from "../constants";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Encodes a UTF-8 string into bytes.
 * @param str Input string.
 * @returns UTF-8 encoded bytes.
 */
export function utf8ToBuffer(str: string): Uint8Array {
  return textEncoder.encode(str);
}

/**
 * Decodes UTF-8 bytes into a string.
 * @param buf UTF-8 encoded bytes.
 * @returns Decoded string.
 */
export function bufferToUtf8(buf: Uint8Array): string {
  return textDecoder.decode(buf);
}

/**
 * Concatenates multiple byte arrays.
 * @param buffers Byte arrays to concatenate.
 * @returns Concatenated byte array.
 */
export function concatBuffers(...buffers: Uint8Array[]): Uint8Array {
  const total = buffers.reduce((n, b) => n + b.length, LENGTH_0);
  const out = new Uint8Array(total);
  let offset = LENGTH_0;
  for (const b of buffers) {
    out.set(b, offset);
    offset += b.length;
  }
  return out;
}

/**
 * Converts bytes to a lowercase hex string.
 * @param buf Input bytes.
 * @param enc Output encoding selector. Only `hex` is accepted.
 * @returns Hex string.
 */
export function bufferToHex(
  buf: Uint8Array,
  enc: typeof HEX_ENC | typeof UTF8_ENC = HEX_ENC
): string {
  if (enc !== HEX_ENC) {
    throw new Error("bufferToHex: only hex encoding is supported");
  }
  let hex = "";
  for (const byte of buf) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Converts a hex string to bytes.
 * @param hex Input hex string, with optional `0x` prefix.
 * @returns Decoded bytes.
 */
export function hexToBuffer(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error("hexToBuffer: invalid length");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte) || byte < 0 || byte > 255) {
      throw new Error("hexToBuffer: invalid hex character");
    }
    out[i] = byte;
  }
  return out;
}

/**
 * Removes a leading `0x` prefix from a hex string.
 * @param hex Input hex string.
 * @returns Hex string without prefix.
 */
export function sanitizeHex(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}

/**
 * Removes leading zeros from a hex string.
 * @param hex Input hex string.
 * @returns Hex string without leading zeros.
 */
export function removeHexLeadingZeros(hex: string): string {
  const h = sanitizeHex(hex);
  const stripped = h.replace(/^0+/, "");
  return stripped.length ? stripped : "0";
}

/**
 * Parses a hex string into a number.
 * @param hex Input hex string.
 * @returns Parsed number.
 */
export function hexToNumber(hex: string): number {
  return Number.parseInt(sanitizeHex(hex), 16);
}

/**
 * RFC 4648 Base64 from bytes. Chunks `btoa` input to avoid huge spread argument lists.
 *
 * @param buf Input bytes.
 * @returns Base64 string (no line breaks).
 */
export function bufferToBase64(buf: Uint8Array): string {
  const chunk = 0x8000;
  let binary = "";
  for (let i = 0; i < buf.length; i += chunk) {
    binary += String.fromCharCode(...buf.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * RFC 4648 Base64 to bytes (whitespace stripped). Uses `atob`.
 *
 * @param str Base64 string.
 * @returns New `Uint8Array`.
 * @throws {DOMException} Invalid Base64 where `atob` throws.
 */
export function base64ToBuffer(str: string): Uint8Array {
  const normalized = str.replace(/\s+/g, "");
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i) & 0xff;
  }
  return out;
}

/**
 * RFC 4648 Base64url without `=` padding (`-`/`_`). Common for JWK `k`.
 *
 * @param buf Input bytes.
 * @returns Base64url string.
 */
export function bufferToBase64Url(buf: Uint8Array): string {
  return bufferToBase64(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Base64url to bytes (optional padding; then {@link base64ToBuffer}).
 *
 * @param str Base64url string.
 * @returns New `Uint8Array`.
 * @throws {Error} Length mod 4 === 1 (invalid).
 */
export function base64UrlToBuffer(str: string): Uint8Array {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad === 1) {
    throw new Error("base64UrlToBuffer: invalid length");
  }
  return base64ToBuffer(s);
}

/**
 * 16-byte AES-128 raw key from `utf8ToBuffer(key.padEnd(16, " "))`. Must yield exactly 16 UTF-8 bytes
 * (same constraint as Web Crypto `importKey("raw", …)` for AES-128).
 *
 * @param key Passphrase.
 * @returns 16 key bytes.
 * @throws {Error} UTF-8 length ≠ 16 after padding.
 */
export function aes128StringKeyMaterial(key: string): Uint8Array {
  const padded = key.padEnd(LENGTH_16, " ");
  const bytes = textEncoder.encode(padded);
  if (bytes.length !== LENGTH_16) {
    throw new Error(
      "aes128StringKeyMaterial: padded key must UTF-8 encode to exactly 16 bytes",
    );
  }
  return bytes;
}

