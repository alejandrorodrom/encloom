import type {
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
} from "../constants";

export interface Encrypted {
  ciphertext: Uint8Array;
  ephemPublicKey: Uint8Array;
  iv: Uint8Array;
  mac: Uint8Array;
}

/**
 * Optional overrides for `encrypt` / `encryptSync`.
 * Fixing `iv` or `ephemPrivateKey` is for test vectors only (deterministic ciphertext).
 */
export interface PreEncryptOpts extends Encrypted {
  ephemPrivateKey: Uint8Array;
}

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface Signature {
  r: Uint8Array;
  s: Uint8Array;
  v: Uint8Array;
}

export interface SignResult {
  signature: Uint8Array;
  recovery: number;
}

export type Pbkdf2Digest =
  | typeof PBKDF2_DIGEST_SHA256
  | typeof PBKDF2_DIGEST_SHA512;

export interface Pbkdf2Options {
  /** Salt; random 16 octets when omitted. Must be at least 16 octets if set. */
  salt?: Uint8Array;
  /**
   * Iteration count. When omitted, uses the OWASP default for `digest`.
   * Explicit values may be lower to re-derive legacy stored parameters.
   */
  iterations?: number;
  digest?: Pbkdf2Digest;
  /** Derived-key length in octets (16–`MAX_KEY_LENGTH`; default 32). */
  keyLength?: number;
}

export interface Pbkdf2Result {
  key: Uint8Array;
  salt: Uint8Array;
  iterations: number;
  digest: Pbkdf2Digest;
}

export interface AesGcmJsonWire {
  iv: string;
  key: string;
  stream: string;
}
