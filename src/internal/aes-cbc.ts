import { cbc } from "@noble/ciphers/aes.js";
import {
  ERROR_AES_IV_LENGTH,
  ERROR_AES_KEY_LENGTH,
  ERROR_AES_PKCS7_PADDING,
  IV_LENGTH,
  KEY_LENGTH,
} from "../constants";

const NOBLE_CBC_OPTS = { disablePadding: true } as const;

function assertAesLengths(iv: Uint8Array, key: Uint8Array): void {
  if (iv.length !== IV_LENGTH) {
    throw new Error(ERROR_AES_IV_LENGTH);
  }
  if (key.length !== KEY_LENGTH) {
    throw new Error(ERROR_AES_KEY_LENGTH);
  }
}

/**
 * Encrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Plaintext bytes.
 * @returns Ciphertext bytes with PKCS#7 padding applied.
 */
export async function aesCbcEncrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  return aesCbcEncryptSync(iv, key, data);
}

/**
 * Decrypts data using AES-256-CBC.
 * Does not authenticate ciphertexts; prefer AES-GCM or verify a MAC first.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Ciphertext bytes.
 * @returns Decrypted plaintext bytes without PKCS#7 padding.
 */
export async function aesCbcDecrypt(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  return aesCbcDecryptSync(iv, key, data);
}

/**
 * Encrypts data using AES-256-CBC.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Plaintext bytes.
 * @returns Ciphertext bytes with PKCS#7 padding applied.
 */
export function aesCbcEncryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  assertAesLengths(iv, key);
  const padded = pkcs7Pad(data, IV_LENGTH);
  return cbc(key, iv, NOBLE_CBC_OPTS).encrypt(padded);
}

/**
 * Decrypts data using AES-256-CBC.
 * Does not authenticate ciphertexts; prefer AES-GCM or verify a MAC first.
 * Invalid length and invalid PKCS#7 both throw `ERROR_AES_PKCS7_PADDING`.
 * @param iv Initialization vector (16 bytes).
 * @param key Encryption key (32 bytes).
 * @param data Ciphertext bytes.
 * @returns Decrypted plaintext bytes without PKCS#7 padding.
 */
export function aesCbcDecryptSync(
  iv: Uint8Array,
  key: Uint8Array,
  data: Uint8Array
): Uint8Array {
  assertAesLengths(iv, key);
  // Reject non-block lengths with the same public error as bad PKCS#7
  // (avoids leaking @noble/ciphers' "multiple of 16" message).
  if (data.length === 0 || data.length % IV_LENGTH !== 0) {
    throw new Error(ERROR_AES_PKCS7_PADDING);
  }
  const decrypted = cbc(key, iv, NOBLE_CBC_OPTS).decrypt(data);
  return pkcs7Unpad(decrypted, IV_LENGTH);
}

/**
 * Applies PKCS#7 padding to a byte array.
 * @param data Input bytes.
 * @param blockSize Cipher block size in bytes.
 * @returns Padded byte array.
 */
function pkcs7Pad(data: Uint8Array, blockSize: number): Uint8Array {
  const pad = blockSize - (data.length % blockSize);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

/**
 * Removes PKCS#7 padding from a byte array.
 * @param data Input bytes with PKCS#7 padding.
 * @returns Unpadded byte array.
 * @throws Error if padding is invalid.
 */
function pkcs7Unpad(data: Uint8Array, blockSize: number): Uint8Array {
  const pad = data.at(-1);
  if (pad === undefined) {
    throw new Error(ERROR_AES_PKCS7_PADDING);
  }
  let bad = 0;
  bad |= pad < 1 ? 1 : 0;
  bad |= pad > blockSize ? 1 : 0;
  bad |= pad > data.length ? 1 : 0;
  for (let i = 0; i < blockSize; i++) {
    const idx = data.length - 1 - i;
    const inPad = i < pad ? 1 : 0;
    const byte = data[idx] ?? 0;
    const mismatch = byte !== pad ? 1 : 0;
    bad |= inPad & mismatch;
  }
  if (bad !== 0) {
    throw new Error(ERROR_AES_PKCS7_PADDING);
  }
  return data.slice(0, data.length - pad);
}
