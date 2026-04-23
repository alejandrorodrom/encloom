import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bufferToBase64, utf8ToBuffer } from "./helpers/encoding";
import { equalConstTime } from "./helpers/validators";

/**
 * Computes HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA256 bytes.
 */
export async function hmacSha256Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  return hmacSha256SignSync(key, msg);
}

/**
 * Verifies HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export async function hmacSha256Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  return hmacSha256VerifySync(key, msg, sig);
}

/**
 * Computes HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA512 bytes.
 */
export async function hmacSha512Sign(
  key: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  return hmacSha512SignSync(key, msg);
}

/**
 * Verifies HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export async function hmacSha512Verify(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): Promise<boolean> {
  return hmacSha512VerifySync(key, msg, sig);
}

/**
 * Computes HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA256 bytes.
 */
export function hmacSha256SignSync(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha256, key, msg);
}

/**
 * Verifies HMAC-SHA256 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export function hmacSha256VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  const expected = hmacSha256SignSync(key, msg);
  return equalConstTime(expected, sig);
}

/**
 * Computes HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @returns HMAC-SHA512 bytes.
 */
export function hmacSha512SignSync(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha512, key, msg);
}

/**
 * Verifies HMAC-SHA512 signature.
 * @param key HMAC key bytes.
 * @param msg Message bytes.
 * @param sig Signature bytes to verify.
 * @returns True when signature is valid.
 */
export function hmacSha512VerifySync(
  key: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  const expected = hmacSha512SignSync(key, msg);
  return equalConstTime(expected, sig);
}

/**
 * HMAC-SHA256: UTF-8(`keyUtf8`) is the raw key (Web Crypto `importKey("raw", …, HMAC-SHA-256)` style).
 * Tag is RFC 4648 Base64.
 *
 * @param keyUtf8 Secret string.
 * @param msg Message bytes.
 * @returns Base64 MAC.
 */
export async function hmacSha256SignUtf8KeyBase64(
  keyUtf8: string,
  msg: Uint8Array,
): Promise<string> {
  return hmacSha256SignUtf8KeyBase64Sync(keyUtf8, msg);
}

/** Synchronous {@link hmacSha256SignUtf8KeyBase64}. */
export function hmacSha256SignUtf8KeyBase64Sync(
  keyUtf8: string,
  msg: Uint8Array,
): string {
  const keyBytes = utf8ToBuffer(keyUtf8);
  return bufferToBase64(hmacSha256SignSync(keyBytes, msg));
}

/**
 * HMAC-SHA256 over UTF-8(`JSON.stringify(data)`) with UTF-8 string key; see {@link hmacSha256SignUtf8KeyBase64}.
 *
 * @param keyUtf8 Secret string.
 * @param data `JSON.stringify` input.
 * @returns Base64 MAC.
 */
export async function hmacSha256SignJsonUtf8KeyBase64(
  keyUtf8: string,
  data: unknown,
): Promise<string> {
  return hmacSha256SignJsonUtf8KeyBase64Sync(keyUtf8, data);
}

/** Synchronous {@link hmacSha256SignJsonUtf8KeyBase64}. */
export function hmacSha256SignJsonUtf8KeyBase64Sync(
  keyUtf8: string,
  data: unknown,
): string {
  return hmacSha256SignUtf8KeyBase64Sync(keyUtf8, utf8ToBuffer(JSON.stringify(data)));
}
