import { pbkdf2 as noblePbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256 as nobleSha256, sha512 as nobleSha512 } from "@noble/hashes/sha2.js";
import {
  KEY_LENGTH,
  LENGTH_16,
  MAX_KEY_LENGTH,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_DEFAULT_ITERATIONS_SHA512,
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
  SHA256_BROWSER_ALGO,
  SHA512_BROWSER_ALGO,
} from "./constants";
import type {
  Pbkdf2Digest,
  Pbkdf2Options,
  Pbkdf2Result,
} from "./helpers/types";
import { assert } from "./helpers/validators";
import { randomBytes } from "./random";

export type { Pbkdf2Digest, Pbkdf2Options, Pbkdf2Result } from "./helpers/types";

function getSubtleCrypto(): SubtleCrypto {
  const cryptoApi = (globalThis as { crypto?: Crypto }).crypto;
  const subtle = cryptoApi?.subtle;
  if (subtle === undefined) {
    throw new Error("PBKDF2: Web Crypto API is not available");
  }
  return subtle;
}

function minIterationsForDigest(digest: Pbkdf2Digest): number {
  return digest === PBKDF2_DIGEST_SHA512
    ? PBKDF2_DEFAULT_ITERATIONS_SHA512
    : PBKDF2_DEFAULT_ITERATIONS;
}

interface ResolvedPbkdf2 {
  passwordBytes: Uint8Array;
  saltBytes: Uint8Array;
  iterations: number;
  digest: Pbkdf2Digest;
  keyLength: number;
}

function resolvePbkdf2Params(
  password: Uint8Array,
  options?: Pbkdf2Options
): ResolvedPbkdf2 {
  const salt = options?.salt ?? randomBytes(LENGTH_16);
  const passwordBytes = Uint8Array.from(password);
  const saltBytes = Uint8Array.from(salt);
  assert(salt.length > 0, "PBKDF2: salt must not be empty");

  const digest: Pbkdf2Digest = options?.digest ?? PBKDF2_DIGEST_SHA256;
  const minIterations = minIterationsForDigest(digest);
  const iterations = options?.iterations ?? minIterations;
  assert(
    Number.isInteger(iterations) && iterations >= minIterations,
    `PBKDF2: iterations must be an integer >= ${minIterations} for ${digest}`
  );

  const keyLength = options?.keyLength ?? KEY_LENGTH;
  assert(
    Number.isInteger(keyLength) &&
      keyLength >= 1 &&
      keyLength <= MAX_KEY_LENGTH,
    `PBKDF2: keyLength must be an integer from 1 to ${MAX_KEY_LENGTH}`
  );

  return { passwordBytes, saltBytes, iterations, digest, keyLength };
}

function toResult(
  key: Uint8Array,
  params: ResolvedPbkdf2
): Pbkdf2Result {
  return {
    key,
    salt: params.saltBytes,
    iterations: params.iterations,
    digest: params.digest,
  };
}

/**
 * Derives a key from a password using PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512.
 *
 * Defaults: random 16-byte salt, HMAC-SHA-256, `PBKDF2_DEFAULT_ITERATIONS`,
 * 32-octet key. SHA-512 without `iterations` uses `PBKDF2_DEFAULT_ITERATIONS_SHA512`.
 * Explicit `iterations` must meet the OWASP minimum for the chosen digest.
 *
 * @param password Password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, digest, and key length.
 * @returns Derived key and the salt, iterations, and digest that were used.
 */
export function pbkdf2Sync(
  password: Uint8Array,
  options?: Pbkdf2Options
): Pbkdf2Result {
  const params = resolvePbkdf2Params(password, options);
  const hash =
    params.digest === PBKDF2_DIGEST_SHA512 ? nobleSha512 : nobleSha256;
  const key = noblePbkdf2(hash, params.passwordBytes, params.saltBytes, {
    c: params.iterations,
    dkLen: params.keyLength,
  });
  return toResult(key, params);
}

/**
 * Async {@link pbkdf2Sync} via the Web Crypto API (`crypto.subtle`).
 *
 * @param password Password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, digest, and key length.
 * @returns Derived key and the salt, iterations, and digest that were used.
 */
export async function pbkdf2(
  password: Uint8Array,
  options?: Pbkdf2Options
): Promise<Pbkdf2Result> {
  const params = resolvePbkdf2Params(password, options);
  const hash =
    params.digest === PBKDF2_DIGEST_SHA512
      ? SHA512_BROWSER_ALGO
      : SHA256_BROWSER_ALGO;
  const subtle = getSubtleCrypto();

  const keyMaterial = await subtle.importKey(
    "raw",
    params.passwordBytes as BufferSource,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: params.saltBytes as BufferSource,
      iterations: params.iterations,
      hash,
    },
    keyMaterial,
    params.keyLength * 8
  );

  return toResult(new Uint8Array(derivedBits), params);
}
