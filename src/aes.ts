import {
  aesCbcDecrypt as aesCbcDecryptImpl,
  aesCbcDecryptSync as aesCbcDecryptSyncImpl,
  aesCbcEncrypt as aesCbcEncryptImpl,
  aesCbcEncryptSync as aesCbcEncryptSyncImpl,
} from "./internal/aes-cbc";

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
  return aesCbcEncryptImpl(iv, key, data);
}

/**
 * Decrypts data using AES-256-CBC.
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
  return aesCbcDecryptImpl(iv, key, data);
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
  return aesCbcEncryptSyncImpl(iv, key, data);
}

/**
 * Decrypts data using AES-256-CBC.
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
  return aesCbcDecryptSyncImpl(iv, key, data);
}
