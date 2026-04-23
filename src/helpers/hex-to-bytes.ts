/**
 * Hex string → byte values `0..255`. Odd length implies a leading `0` nibble (unlike {@link hexToBuffer}).
 *
 * @param hex Contiguous hex digits (no `0x` stripping).
 * @returns `number[]` of byte values.
 */
export function hexToBytes(hex: string): number[] {
  const clean = hex.length % 2 ? `0${hex}` : hex;
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    out.push(Number.parseInt(clean.slice(i, i + 2), 16));
  }
  return out;
}
