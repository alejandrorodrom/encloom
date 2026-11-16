---
title: HMAC over JSON in TypeScript — why verify fails in production
published: false
description: Sign the wire bytes, not a re-stringified object. How HMAC-SHA256 breaks on pretty-print, extra DTO fields, and encoding mismatches—and what to put under the MAC.
tags: typescript, javascript, cryptography, node, webdev
# After Medium is live, set canonical_url to the Medium post (or the reverse).
# canonical_url:
---

# HMAC over JSON in TypeScript — why verify fails in production

In the [previous post](https://dev.to/alejandrorodrom/buffer-vs-uint8array-in-typescript-crypto-and-why-it-hurts-289l) we treated bytes as `Uint8Array` and skimmed HMAC for a JSON body. The one-liner looked fine. Then production hit: client signs, server verifies, `ok === false` with the “same” payload.

This piece is only about that failure mode. HMAC is message authentication (integrity + authenticity with a shared secret). It is not encryption. It does not replace TLS. The examples use [encloom](https://www.npmjs.com/package/encloom); the habits apply with Web Crypto or `@noble/hashes` too.

> Not a compliance guide. About bytes on the wire.

## What HMAC actually signs

HMAC-SHA256 takes a **key** and a **message**, both as bytes. The tag is deterministic for that pair. If either side feeds different bytes—different UTF-8 of the secret, different JSON serialization, hex vs Base64 of the tag—verification fails even when humans “see the same JSON.”

```ts
import {
  hmacSha256SignSync,
  hmacSha256VerifySync,
} from "encloom/hmac";
import { utf8ToBuffer, bufferToBase64, base64ToBuffer } from "encloom/helpers/encoding";

const key = utf8ToBuffer("api-shared-secret");
const msg = utf8ToBuffer('{"action":"ping","id":1}');

const mac = hmacSha256SignSync(key, msg);
const ok = hmacSha256VerifySync(key, msg, mac);

console.log({ macB64: bufferToBase64(mac), ok });
```

`hmacSha256VerifySync` returns a boolean and compares the tag as bytes (`equalConstTime`). Decode Base64 or hex first and use that API. Do not invent a `===` on encoded strings.

## The production bug: re-stringify after parse

A convenience helper signs `JSON.stringify(data)` for you. That is safe **only if** the verifier uses the **same** byte sequence.

This is the trap:

1. Client builds an object, signs `JSON.stringify(object)` (compact).
2. The HTTP client, a logger, or the server serializes **again**—pretty-print, a DTO with an extra field, a different key order.
3. Verify runs over those new bytes.

`JSON.parse` of the wire string and `JSON.stringify` of **that** object often keeps key order in modern JS. The usual break is a *second* serialization that is not the wire: `JSON.stringify(obj, null, 2)`, a mapped DTO (`receivedAt`, stripped `undefined`), or Unicode escapes (`\u0061` vs `a`). Key order can still bite if something rebuilds the object from scratch.

### Before — same payload, different bytes → `ok === false`

```ts
import {
  hmacSha256SignJsonUtf8KeyBase64Sync,
  hmacSha256VerifySync,
} from "encloom/hmac";
import { utf8ToBuffer, base64ToBuffer } from "encloom/helpers/encoding";

const secret = "api-shared-secret";
const body = { action: "ping", id: 1 };

// Client signs compact JSON.stringify(body)
const macB64 = hmacSha256SignJsonUtf8KeyBase64Sync(secret, body);
// MAC over: {"action":"ping","id":1}

// Server (or axios interceptor, or a DTO mapper) serializes again
const pretty = JSON.stringify(body, null, 2);
const extraField = JSON.stringify({ ...body, receivedAt: "2026-08-22T00:00:00.000Z" });

const okPretty = hmacSha256VerifySync(
  utf8ToBuffer(secret),
  utf8ToBuffer(pretty),
  base64ToBuffer(macB64)
);
const okDto = hmacSha256VerifySync(
  utf8ToBuffer(secret),
  utf8ToBuffer(extraField),
  base64ToBuffer(macB64)
);

console.log({ okPretty, okDto }); // false, false — same “JSON”, different UTF-8
```

### After — sign and verify the wire (preferred)

Agree that the MAC covers the **exact request body bytes**, not a re-built object.

```ts
import {
  hmacSha256SignUtf8KeyBase64Sync,
  hmacSha256VerifySync,
} from "encloom/hmac";
import { utf8ToBuffer, base64ToBuffer } from "encloom/helpers/encoding";

const secret = "api-shared-secret";

// Client: MAC over the exact string that will be POSTed
const rawBody = JSON.stringify({ action: "ping", id: 1 });
const macB64 = hmacSha256SignUtf8KeyBase64Sync(
  secret,
  utf8ToBuffer(rawBody)
);

// POST rawBody with header X-Signature: macB64

// Server: verify the raw body from the framework (before JSON.parse)
function verifyRequest(rawBody: string, macB64: string): boolean {
  return hmacSha256VerifySync(
    utf8ToBuffer(secret),
    utf8ToBuffer(rawBody),
    base64ToBuffer(macB64)
  );
}

console.log(verifyRequest(rawBody, macB64)); // true
```

In Express/Fastify/etc., read the raw body (or a buffered string) **before** `JSON.parse` for the MAC path. Parse for business logic after verify succeeds.

Signing only the body is enough to catch tampering of that body. A reused MAC can still be posted to another path. If that matters, put more than the body under the MAC—for example `METHOD + path + timestamp + rawBody` as one UTF-8 string both sides build the same way—and reject old timestamps.

## If you must sign objects — canonical JSON

If both sides only have objects, define a canonical form: sorted keys, no extra spaces, UTF-8, and the same number serialization. A minimal sketch:

```ts
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}
```

Then HMAC over `utf8ToBuffer(canonicalJson(body))` on both sides. Homegrown canonicalization has edge cases (dates, `undefined`, bigint). Prefer signing the wire when you control the HTTP stack.

## Encoding checklist

Before debugging crypto, check these mismatches:

| Item | Agree on |
|------|----------|
| Secret | Same UTF-8 bytes (trim, no accidental newline in env vars) |
| Message | Raw body **or** one canonical serializer |
| Tag transport | Base64 **or** hex—decode before verify |
| Algorithm | HMAC-SHA256 vs SHA512 (do not mix) |

Hex vs Base64 of the same tag are different strings; both sides must use the same encoding on the wire and decode to `Uint8Array` before `verify`.

## What HMAC does not give you

- **Confidentiality** — anyone who sees the body still reads it. Use TLS; add AES-GCM (or similar) if you need ciphertext at rest or beyond transport.
- **Non-repudiation** — shared secret means either party can forge tags. For “only this private key signed,” use ECDSA / similar.
- **Replay protection** — a valid MAC can be resent. Bind method, path, and a timestamp (or nonce) into the signed bytes, as above, if that matters.

## When this pattern fits

Use shared-secret HMAC when client and server (or two backends) already share a secret, you need tamper detection on a payload, and you can pin the exact bytes under the MAC.

Skip it for public clients that cannot hold a secret (use user auth + server-side checks), or when you need asymmetric proof of origin.

## References

- [encloom on npm](https://www.npmjs.com/package/encloom) · [repo](https://github.com/alejandrorodrom/encloom) · `encloom/hmac`
- Previous: [Buffer vs Uint8Array in TypeScript crypto](https://dev.to/alejandrorodrom/buffer-vs-uint8array-in-typescript-crypto-and-why-it-hurts-289l)
- Related: Web Crypto `HMAC`, RFC 2104
