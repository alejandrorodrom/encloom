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
  const passwordBytes = Uint8Array.from(password);
  assert(passwordBytes.length > 0, "PBKDF2: password must not be empty");

  const salt = options?.salt ?? randomBytes(LENGTH_16);
  const saltBytes = Uint8Array.from(salt);
  assert(
    saltBytes.length >= LENGTH_16,
    `PBKDF2: salt must be at least ${LENGTH_16} bytes`
  );

  // Widen for a runtime check: JS callers can pass labels outside Pbkdf2Digest.
  const digestCandidate = (options?.digest ?? PBKDF2_DIGEST_SHA256) as string;
  assert(
    digestCandidate === PBKDF2_DIGEST_SHA256 ||
      digestCandidate === PBKDF2_DIGEST_SHA512,
    "PBKDF2: digest must be sha256 or sha512"
  );
  const digest = digestCandidate as Pbkdf2Digest;
  const minIterations = minIterationsForDigest(digest);
  const iterations = options?.iterations ?? minIterations;
  assert(
    Number.isInteger(iterations) && iterations >= 1,
    "PBKDF2: iterations must be an integer >= 1"
  );
  if (options?.allowLegacyIterations !== true) {
    assert(
      iterations >= minIterations,
      `PBKDF2: iterations must be an integer >= ${String(minIterations)} for ${digest} (OWASP minimum); pass allowLegacyIterations: true to re-derive with lower counts`
    );
  }

  const keyLength = options?.keyLength ?? KEY_LENGTH;
  assert(
    Number.isInteger(keyLength) &&
      keyLength >= LENGTH_16 &&
      keyLength <= MAX_KEY_LENGTH,
    `PBKDF2: keyLength must be an integer from ${LENGTH_16} to ${MAX_KEY_LENGTH}`
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
 * Explicit `iterations` below the OWASP floor for the chosen digest are rejected
 * unless `allowLegacyIterations: true` (e.g. re-deriving 210000 with SHA-256).
 * Prefer the defaults for new material. `keyLength` must be 16–`MAX_KEY_LENGTH`
 * (default 32). Rejects empty passwords, salts shorter than 16 octets, and
 * digests other than `sha256` / `sha512`.
 *
 * **Blocking:** runs the full iteration count on the calling thread (pure JS via
 * `@noble/hashes`). At OWASP defaults this can take ~1s and freezes the Node
 * event loop for that whole interval—do **not** use in request handlers or login
 * routes. Prefer {@link pbkdf2} there (and in browsers / UI). Keep this for CLI
 * scripts, tests, or dedicated workers.
 *
 * @param password Non-empty password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, digest, key length, and legacy flag.
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
 * Prefer this over {@link pbkdf2Sync} on the main thread and in Node servers:
 * Web Crypto does not freeze the UI or block the event loop for the full
 * iteration count (unlike sync, which can stall a login route for ~1s).
 *
 * @param password Non-empty password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, digest, key length, and legacy flag.
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
