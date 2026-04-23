import {
  KEY_LENGTH,
  LENGTH_16,
  PBKDF2_DEFAULT_ITERATIONS,
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

/**
 * Derives a 32-byte key from a password using PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512.
 *
 * If `options` is omitted, a random 16-byte salt is generated, iterations default to
 * `PBKDF2_DEFAULT_ITERATIONS`, and the PRF is HMAC-SHA-256.
 *
 * @param password Password material as raw bytes (encoding is up to the caller).
 * @param options Optional salt, iteration count, and digest algorithm.
 * @returns Derived key and the salt, iterations, and digest that were used.
 */
export async function pbkdf2(
  password: Uint8Array,
  options?: Pbkdf2Options
): Promise<Pbkdf2Result> {
  const salt = options?.salt ?? randomBytes(LENGTH_16);
  const passwordBytes = Uint8Array.from(password);
  const saltBytes = Uint8Array.from(salt);
  assert(salt.length > 0, "PBKDF2: salt must not be empty");
  const iterations = options?.iterations ?? PBKDF2_DEFAULT_ITERATIONS;
  assert(
    Number.isInteger(iterations) && iterations >= 1,
    "PBKDF2: iterations must be a positive integer"
  );
  const digest: Pbkdf2Digest = options?.digest ?? PBKDF2_DIGEST_SHA256;
  const digestWebCrypto =
    digest === PBKDF2_DIGEST_SHA512 ? PBKDF2_DIGEST_SHA512 : PBKDF2_DIGEST_SHA256;
  const hash =
    digestWebCrypto === PBKDF2_DIGEST_SHA512 ? SHA512_BROWSER_ALGO : SHA256_BROWSER_ALGO;
  const subtle = getSubtleCrypto();

  const keyMaterial = await subtle.importKey(
    "raw",
    passwordBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash,
    },
    keyMaterial,
    KEY_LENGTH * 8
  );

  return {
    key: new Uint8Array(derivedBits),
    salt: saltBytes,
    iterations,
    digest,
  };
}
