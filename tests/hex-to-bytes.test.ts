import { describe, expect, it } from "vitest";
import { EC_GROUP_ORDER } from "../src/constants.js";
import { hexToBytes } from "../src/helpers/hex-to-bytes.js";

describe("hexToBytes", () => {
  it("prepends one hex digit when the string has odd length", () => {
    expect(new Uint8Array(hexToBytes("a"))).toEqual(new Uint8Array([0x0a]));
    expect(new Uint8Array(hexToBytes("0a"))).toEqual(new Uint8Array([0x0a]));
  });

  it("parses even-length hex without inserting a digit", () => {
    expect(new Uint8Array(hexToBytes("0f00"))).toEqual(new Uint8Array([0x0f, 0x00]));
  });

  it("matches EC_GROUP_ORDER for the canonical secp256k1 order hex", () => {
    expect(
      new Uint8Array(
        hexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
      ),
    ).toEqual(EC_GROUP_ORDER);
  });
});
