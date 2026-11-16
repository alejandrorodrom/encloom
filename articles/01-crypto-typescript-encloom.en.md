# Buffer vs Uint8Array in TypeScript crypto (and why it hurts)

In Node, `Buffer` shows up everywhere. In the browser and on the edge, the real contract is typed arrays (`Uint8Array`)—and often Web Crypto.

When you mix those worlds—an API on Node, a client in the browser, a Worker in between—crypto stops being “call SHA-256” and turns into:

- converting types at every boundary
- guessing whether a helper accepts `string | Buffer | Uint8Array`
- pulling half a library for a single primitive

This post follows that thread (`Uint8Array` end to end) through four flows: hashing, HMAC, AES-GCM, and ECDSA over a digest. The snippets use [encloom](https://www.npmjs.com/package/encloom); the same ideas apply if you prefer `@noble/*` plus Web Crypto by hand.

> This is not a threat-modeling or compliance guide. It is about bytes and APIs.

## The contract: explicit bytes

A string is not a cryptographic message until you define an encoding. UTF-8 is the usual choice for JSON APIs:

```ts
import { sha256Sync, sha256Utf8HexSync } from "encloom/sha2";
import { utf8ToBuffer, bufferToHex } from "encloom/helpers/encoding";

const digest = sha256Sync(utf8ToBuffer("hello"));
console.log(bufferToHex(digest));

// Shortcut when you only need hex of a UTF-8 string
console.log(sha256Utf8HexSync("hello"));
```

`Uint8Array` in the public API avoids “sometimes Buffer, sometimes not” across runtimes. The cost is one conversion line; the win is predictable typing.

Naming note: helpers like `utf8ToBuffer` return `Uint8Array`. The `Buffer` suffix is an enc-utils-style name, not Node’s `Buffer`.

## Per-module imports

If your bundler tree-shakes and the package sets `sideEffects: false`, import the subpath you actually use:

```ts
import { sha256Sync } from "encloom/sha2";
import { aesGcmEncryptSync } from "encloom/aes-gcm";
```

Same idea as preferring `lodash/get` over `import _ from "lodash"` when you need one function. On the frontend and in Workers, size shows up.

## HMAC: integrity for a JSON body

Same byte contract: the MAC is computed over `Uint8Array`, not a loose string or a Node `Buffer`. Scenario: client and server share a secret and want to detect payload tampering. No encryption here—message authentication only.

```ts
import {
  hmacSha256SignJsonUtf8KeyBase64Sync,
  hmacSha256VerifySync,
} from "encloom/hmac";
import { utf8ToBuffer, base64ToBuffer } from "encloom/helpers/encoding";

const secret = "api-shared-secret";
const body = { action: "ping", id: 1 };

const macB64 = hmacSha256SignJsonUtf8KeyBase64Sync(secret, body);

// Same serialization the helper used when signing
const msg = utf8ToBuffer(JSON.stringify(body));
const ok = hmacSha256VerifySync(
  utf8ToBuffer(secret),
  msg,
  base64ToBuffer(macB64)
);

console.log({ macB64, ok });
```

A detail that breaks verification in production: if one side signs the object and the other re-parses JSON from the wire and runs `JSON.stringify` again, key order can change. Agree on canonical bytes (or sign an already-stable string) between client and server.

## AES-GCM: JSON in an envelope

Same thread: plaintext and key as `Uint8Array`; the helper only serializes the result to strings for transport. GCM gives confidentiality plus integrity (the tag). `encryptJsonAes256GcmSync` generates a random key and IV and returns an envelope (`iv`, `key`, `stream`). Decryption returns `unknown`—narrow it at the call site.

```ts
import {
  encryptJsonAes256GcmSync,
  decryptJsonAes256GcmSync,
} from "encloom/aes-gcm";

const wire = encryptJsonAes256GcmSync({ user: "ana", role: "admin" });
// wire: { iv, key, stream } — the key travels inside the envelope

const again = decryptJsonAes256GcmSync(wire) as {
  user: string;
  role: string;
};

console.log(again.user);
```

Important so the example is not misread: **anyone who has the full `wire` can decrypt**, because the key is in the object. That fits a local sealed blob, or a layer you later protect with another key / KMS / ECIES. It is not “I encrypted with a shared secret and only send the ciphertext.”

If you manage the key yourself, the low-level API is `aesGcmEncryptSync(nonce, key, plaintext)`. There the operational rule is: do not reuse the same `(key, nonce)` pair; 12-byte nonces are the usual size.

## ECDSA (secp256k1): sign the digest

Explicit bytes again: UTF-8 → `Uint8Array`, then the digest, then the signature. Many examples sign raw plaintext; in this API `sign` / `verify` expect the message **hash** (e.g. SHA-256). `verify` does not return a `boolean`: if the signature is invalid, it **throws**.

```ts
import { generateKeyPair, sign, verify } from "encloom/ecdsa";
import { sha256Sync } from "encloom/sha2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const { privateKey, publicKey } = generateKeyPair();
const digest = sha256Sync(utf8ToBuffer("transfer:42"));

const sig = sign(privateKey, digest);
verify(publicKey, digest, sig); // ok; on failure → throw
```

For Ethereum-style pipelines, `keccak256` lives in `encloom/sha3`. Keccak-256 ≠ SHA3-256 (FIPS); they are different domains—do not mix them up.

## When this approach helps (and when it doesn’t)

It makes sense if you:

- share the same byte-oriented code across Node / browser / edge
- use a few primitives and care what lands in the bundle
- prefer types that do not lie (`Uint8Array` vs “stringly bytes”)

It adds little if you already live inside a stack that covers ~80% of your case (e.g. a full wallet SDK) and you do not care about size or buffer types.

## References

- Package and module docs: [encloom on npm](https://www.npmjs.com/package/encloom) · [repo](https://github.com/alejandrorodrom/encloom)
- Related ideas: Web Crypto (`SubtleCrypto`), the `@noble` family for pure-JS implementations