import { pbkdf2Sync as nodePbkdf2Sync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  KEY_LENGTH,
  MAX_KEY_LENGTH,
  PBKDF2_DEFAULT_ITERATIONS,
  PBKDF2_DEFAULT_ITERATIONS_SHA512,
  PBKDF2_DIGEST_SHA256,
  PBKDF2_DIGEST_SHA512,
} from "../../src/constants.js";
import { pbkdf2, pbkdf2Sync } from "../../src/pbkdf2.js";

describe("pbkdf2 parity with Node.js crypto", () => {
  it("matches crypto.pbkdf2Sync (SHA-256)", async () => {
    const password = new Uint8Array(Buffer.from("p4ss", "utf8"));
    const salt = new Uint8Array(16);
    salt.fill(7);
    const iterations = PBKDF2_DEFAULT_ITERATIONS;
    const expected = nodePbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      iterations,
      KEY_LENGTH,
      "sha256",
    );
    const out = await pbkdf2(password, {
      salt,
      iterations,
      digest: PBKDF2_DIGEST_SHA256,
    });
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
    expect(out.iterations).toBe(iterations);
    expect(out.digest).toBe(PBKDF2_DIGEST_SHA256);
  });

  it("matches crypto.pbkdf2Sync (SHA-512)", async () => {
    const password = new Uint8Array([1, 2, 3]);
    const salt = new Uint8Array(16);
    salt.fill(9);
    const iterations = PBKDF2_DEFAULT_ITERATIONS_SHA512;
    const expected = nodePbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      iterations,
      KEY_LENGTH,
      "sha512",
    );
    const out = await pbkdf2(password, {
      salt,
      iterations,
      digest: PBKDF2_DIGEST_SHA512,
    });
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
  });

  it("SHA-512 without iterations uses PBKDF2_DEFAULT_ITERATIONS_SHA512", async () => {
    const password = new Uint8Array([9, 8, 7]);
    const salt = new Uint8Array(16);
    salt.fill(4);
    const expected = nodePbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      PBKDF2_DEFAULT_ITERATIONS_SHA512,
      KEY_LENGTH,
      "sha512",
    );
    const out = await pbkdf2(password, {
      salt,
      digest: PBKDF2_DIGEST_SHA512,
    });
    expect(out.iterations).toBe(PBKDF2_DEFAULT_ITERATIONS_SHA512);
    expect(out.digest).toBe(PBKDF2_DIGEST_SHA512);
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
  });

  it("async pbkdf2 matches Node for multi-block keyLength", async () => {
    const password = new Uint8Array([4, 5, 6]);
    const salt = new Uint8Array(16);
    salt.fill(2);
    const keyLength = 48;
    const expected = nodePbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      PBKDF2_DEFAULT_ITERATIONS,
      keyLength,
      "sha256",
    );
    const out = await pbkdf2(password, { salt, keyLength });
    expect(out.key.length).toBe(keyLength);
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
  });

  // Sync path is pure-JS (@noble/hashes); keep keyLength within one SHA-256 block
  // and raise the timeout so CI runners can finish OWASP-level iteration counts.
  it(
    "pbkdf2Sync matches Node and async for custom keyLength",
    async () => {
      const password = new Uint8Array([4, 5, 6]);
      const salt = new Uint8Array(16);
      salt.fill(2);
      const keyLength = 16;
      const expected = nodePbkdf2Sync(
        Buffer.from(password),
        Buffer.from(salt),
        PBKDF2_DEFAULT_ITERATIONS,
        keyLength,
        "sha256",
      );
      const syncOut = pbkdf2Sync(password, { salt, keyLength });
      const asyncOut = await pbkdf2(password, { salt, keyLength });
      expect(syncOut.key.length).toBe(keyLength);
      expect(Buffer.from(syncOut.key).equals(expected)).toBe(true);
      expect(Buffer.from(asyncOut.key).equals(expected)).toBe(true);
    },
    60_000,
  );

  it("allows explicit legacy iterations below the OWASP default", async () => {
    const password = new Uint8Array([1, 2, 3]);
    const salt = new Uint8Array(16);
    salt.fill(5);
    const legacyIterations = 210_000;
    const expected = nodePbkdf2Sync(
      Buffer.from(password),
      Buffer.from(salt),
      legacyIterations,
      KEY_LENGTH,
      "sha256",
    );
    const out = await pbkdf2(password, {
      salt,
      iterations: legacyIterations,
    });
    expect(out.iterations).toBe(legacyIterations);
    expect(Buffer.from(out.key).equals(expected)).toBe(true);
  });

  it("rejects non-positive iterations", () => {
    const password = new Uint8Array([1]);
    const salt = new Uint8Array(16);
    expect(() => pbkdf2Sync(password, { salt, iterations: 0 })).toThrow(
      "PBKDF2: iterations must be an integer >= 1",
    );
  });

  it("rejects invalid keyLength", () => {
    const password = new Uint8Array([1]);
    const salt = new Uint8Array(16);
    expect(() => pbkdf2Sync(password, { salt, keyLength: 15 })).toThrow(
      `PBKDF2: keyLength must be an integer from 16 to ${String(MAX_KEY_LENGTH)}`,
    );
    expect(() =>
      pbkdf2Sync(password, { salt, keyLength: MAX_KEY_LENGTH + 1 }),
    ).toThrow(
      `PBKDF2: keyLength must be an integer from 16 to ${String(MAX_KEY_LENGTH)}`,
    );
  });

  it("rejects empty password, short salt, and unsupported digest", () => {
    const salt = new Uint8Array(16);
    expect(() => pbkdf2Sync(new Uint8Array(0), { salt })).toThrow(
      "PBKDF2: password must not be empty",
    );
    expect(() =>
      pbkdf2Sync(new Uint8Array([1]), { salt: new Uint8Array(1) }),
    ).toThrow("PBKDF2: salt must be at least 16 bytes");
    expect(() =>
      pbkdf2Sync(new Uint8Array([1]), {
        salt,
        // Runtime / JS callers may pass an unsupported label.
        digest: "sha1" as unknown as typeof PBKDF2_DIGEST_SHA256,
      }),
    ).toThrow("PBKDF2: digest must be sha256 or sha512");
  });

  describe("pbkdf2 snapshot batch 18", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("password-only path uses default iterations, SHA-256, and random salt from getRandomValues", async () => {
      const fixedSalt = Buffer.alloc(16, 0x3a);
      const mockGetRandomValues = (arr: ArrayBufferView) => {
        new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(fixedSalt);
        return arr;
      };
      vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(
        mockGetRandomValues as typeof globalThis.crypto.getRandomValues,
      );
      const password = new Uint8Array(Buffer.from("pw", "utf8"));
      const out = await pbkdf2(password);
      const expected = nodePbkdf2Sync(
        Buffer.from(password),
        fixedSalt,
        PBKDF2_DEFAULT_ITERATIONS,
        KEY_LENGTH,
        "sha256",
      );
      expect(out.iterations).toBe(PBKDF2_DEFAULT_ITERATIONS);
      expect(out.digest).toBe(PBKDF2_DIGEST_SHA256);
      expect(Buffer.from(out.salt).equals(fixedSalt)).toBe(true);
      expect(Buffer.from(out.key).equals(expected)).toBe(true);
    });
  });
});
