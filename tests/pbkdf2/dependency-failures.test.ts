import { afterEach, describe, expect, it, vi } from "vitest";
import { LENGTH_16, PBKDF2_DEFAULT_ITERATIONS } from "../../src/constants.js";
import { pbkdf2 } from "../../src/pbkdf2.js";

describe("pbkdf2 when Web Crypto is unavailable or fails", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects when Web Crypto API is unavailable", async () => {
    const originalCrypto = globalThis.crypto;
    try {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: undefined,
      });

      await expect(
        pbkdf2(new Uint8Array([1]), {
          salt: new Uint8Array(LENGTH_16),
          iterations: 1,
        }),
      ).rejects.toThrow("PBKDF2: Web Crypto API is not available");
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: originalCrypto,
      });
    }
  });

  it("rejects when subtle.deriveBits throws", async () => {
    vi.spyOn(globalThis.crypto.subtle, "deriveBits").mockRejectedValueOnce(
      new Error("deriveBits failed"),
    );

    await expect(
      pbkdf2(new Uint8Array([1]), {
        salt: new Uint8Array(LENGTH_16),
        iterations: PBKDF2_DEFAULT_ITERATIONS,
      }),
    ).rejects.toThrow("deriveBits failed");
  });
});
