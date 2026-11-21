import { afterEach, describe, expect, it, vi } from "vitest";
import { LENGTH_16, PBKDF2_DEFAULT_ITERATIONS } from "../../src/constants.js";
import { pbkdf2, pbkdf2Sync } from "../../src/pbkdf2.js";

describe("pbkdf2 when Web Crypto is unavailable or fails", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects async when Web Crypto API is unavailable", async () => {
    const originalCrypto = globalThis.crypto;
    try {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: undefined,
      });

      await expect(
        pbkdf2(new Uint8Array([1]), {
          salt: new Uint8Array(LENGTH_16),
          iterations: PBKDF2_DEFAULT_ITERATIONS,
        }),
      ).rejects.toThrow("PBKDF2: Web Crypto API is not available");
    } finally {
      Object.defineProperty(globalThis, "crypto", {
        configurable: true,
        value: originalCrypto,
      });
    }
  });

  // noble PBKDF2 at OWASP iteration counts is pure-JS and slow on CI runners.
  it(
    "pbkdf2Sync still works when Web Crypto API is unavailable",
    () => {
      const originalCrypto = globalThis.crypto;
      try {
        Object.defineProperty(globalThis, "crypto", {
          configurable: true,
          value: {
            getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto),
          },
        });

        const out = pbkdf2Sync(new Uint8Array([1]), {
          salt: new Uint8Array(LENGTH_16),
        });
        expect(out.key.length).toBe(32);
        expect(out.iterations).toBe(PBKDF2_DEFAULT_ITERATIONS);
      } finally {
        Object.defineProperty(globalThis, "crypto", {
          configurable: true,
          value: originalCrypto,
        });
      }
    },
    60_000,
  );

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
