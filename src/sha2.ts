import { ripemd160 as ripemd160Noble } from "@noble/hashes/legacy.js";
import { sha256 as sha256Noble } from "@noble/hashes/sha2.js";
import { bufferToHex, utf8ToBuffer } from "./helpers/encoding";
import { sha512 as sha512Async, sha512Sync } from "./internal/sha512";

/**
 * Computes SHA-256 digest.
 * @param msg Input bytes.
 * @returns SHA-256 digest bytes.
 */
export async function sha256(msg: Uint8Array): Promise<Uint8Array> {
  return sha256Noble(msg);
}

/**
 * Computes SHA-256 digest.
 * @param msg Input bytes.
 * @returns SHA-256 digest bytes.
 */
export function sha256Sync(msg: Uint8Array): Uint8Array {
  return sha256Noble(msg);
}

/**
 * SHA-256 over UTF-8(`str`), returned as 64-character lowercase hex (no `0x` prefix).
 *
 * @param str Input string.
 * @returns Hex digest string.
 */
export async function sha256Utf8Hex(str: string): Promise<string> {
  return bufferToHex(await sha256(utf8ToBuffer(str)));
}

/** Synchronous {@link sha256Utf8Hex}. */
export function sha256Utf8HexSync(str: string): string {
  return bufferToHex(sha256Sync(utf8ToBuffer(str)));
}

/**
 * Computes SHA-512 digest.
 * @param msg Input bytes.
 * @returns SHA-512 digest bytes.
 */
export async function sha512(msg: Uint8Array): Promise<Uint8Array> {
  return sha512Async(msg);
}

export { sha512Sync };

/**
 * Computes RIPEMD-160 digest.
 * @param msg Input bytes.
 * @returns RIPEMD-160 digest bytes.
 */
export async function ripemd160(msg: Uint8Array): Promise<Uint8Array> {
  return ripemd160Noble(msg);
}

/**
 * Computes RIPEMD-160 digest.
 * @param msg Input bytes.
 * @returns RIPEMD-160 digest bytes.
 */
export function ripemd160Sync(msg: Uint8Array): Uint8Array {
  return ripemd160Noble(msg);
}
