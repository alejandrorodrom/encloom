# Buffer vs Uint8Array en crypto con TypeScript (y por qué duele)

En Node es normal ver `Buffer`. En el navegador y en edge, el contrato real son typed arrays (`Uint8Array`) y, a menudo, Web Crypto.

Cuando mezclás ambos mundos —API en Node, cliente en browser, Worker en el medio— la crypto deja de ser “llamar a SHA-256” y pasa a ser:

- convertir tipos en cada frontera
- decidir si un helper acepta `string | Buffer | Uint8Array`
- importar media librería por una sola primitive

Este post recorre ese hilo (`Uint8Array` de punta a punta) con cuatro flujos: hash, HMAC, AES-GCM y ECDSA sobre digest. Los snippets usan [encloom](https://www.npmjs.com/package/encloom); la misma lógica aplica si preferís `@noble/*` + Web Crypto a mano.

> No es una guía de amenaza ni de compliance. Es mecánica de bytes y APIs.

## El contrato: bytes explícitos

Un string no es un mensaje criptográfico hasta que definís encoding. UTF-8 es lo habitual en APIs JSON:

```ts
import { sha256Sync, sha256Utf8HexSync } from "encloom/sha2";
import { utf8ToBuffer, bufferToHex } from "encloom/helpers/encoding";

const digest = sha256Sync(utf8ToBuffer("hola"));
console.log(bufferToHex(digest));

// Equivalente si solo necesitás hex del string UTF-8
console.log(sha256Utf8HexSync("hola"));
```

`Uint8Array` en la firma pública evita el “a veces es Buffer, a veces no” entre runtimes. El costo es una línea de conversión; el beneficio es tipado predecible.

Nota de nombres: helpers como `utf8ToBuffer` devuelven `Uint8Array`. El sufijo `Buffer` es herencia de estilo enc-utils, no el `Buffer` de Node.

## Imports por módulo

Si el bundler hace tree-shaking y el paquete marca `sideEffects: false`, conviene importar el subpath que usás:

```ts
import { sha256Sync } from "encloom/sha2";
import { aesGcmEncryptSync } from "encloom/aes-gcm";
```

Es el mismo criterio que preferir `lodash/get` a `import _ from "lodash"` cuando solo necesitás una función. En front y Workers el tamaño se nota.

## HMAC: integridad de un body JSON

Mismo contrato de bytes: el MAC se calcula sobre `Uint8Array`, no sobre un string suelto ni un `Buffer` de Node. El escenario: cliente y servidor comparten un secreto y quieren detectar manipulación del payload. Acá no hay cifrado: solo autenticación del mensaje.

```ts
import {
  hmacSha256SignJsonUtf8KeyBase64Sync,
  hmacSha256VerifySync,
} from "encloom/hmac";
import { utf8ToBuffer, base64ToBuffer } from "encloom/helpers/encoding";

const secret = "api-shared-secret";
const body = { action: "ping", id: 1 };

const macB64 = hmacSha256SignJsonUtf8KeyBase64Sync(secret, body);

// Misma serialización que usó el helper al firmar
const msg = utf8ToBuffer(JSON.stringify(body));
const ok = hmacSha256VerifySync(
  utf8ToBuffer(secret),
  msg,
  base64ToBuffer(macB64)
);

console.log({ macB64, ok });
```

Detalle que rompe verificaciones en producción: si un lado firma el objeto y el otro re-parsea JSON del wire y vuelve a hacer `JSON.stringify`, el orden de claves puede cambiar. Mejor acordar bytes canónicos (o firmar un string ya estabilizado) entre cliente y servidor.

## AES-GCM: JSON en un envelope

Seguimos en el mismo hilo: plaintext y clave en `Uint8Array`; el helper solo serializa el resultado a strings para transportarlo. GCM aporta confidencialidad e integridad (tag). `encryptJsonAes256GcmSync` genera clave e IV al azar y devuelve un envelope (`iv`, `key`, `stream`). El descifrado devuelve `unknown` (estrechalo en el call site).

```ts
import {
  encryptJsonAes256GcmSync,
  decryptJsonAes256GcmSync,
} from "encloom/aes-gcm";

const wire = encryptJsonAes256GcmSync({ user: "ana", role: "admin" });
// wire: { iv, key, stream } — la clave viaja dentro del envelope

const again = decryptJsonAes256GcmSync(wire) as {
  user: string;
  role: string;
};

console.log(again.user);
```

Importante para no malinterpretar el ejemplo: **quien tenga el `wire` completo puede descifrar**, porque la key va en el objeto. Sirve como blob sellado local, o como capa que después protegés con otra clave / KMS / ECIES. No es “cifré con un secreto compartido y mando solo el ciphertext”.

Si manejás vos la clave, el API de bajo nivel es `aesGcmEncryptSync(nonce, key, plaintext)`. Ahí la regla operativa es no reutilizar el mismo par `(clave, nonce)`; 12 bytes de nonce es el tamaño habitual.

## ECDSA (secp256k1): se firma el digest

Otra vez bytes explícitos: primero UTF-8 → `Uint8Array`, después el digest, después la firma. Muchos ejemplos firman el texto plano; en esta API `sign` / `verify` esperan el **hash** del mensaje (p. ej. SHA-256). `verify` no devuelve `boolean`: si la firma es inválida, **lanza**.

```ts
import { generateKeyPair, sign, verify } from "encloom/ecdsa";
import { sha256Sync } from "encloom/sha2";
import { utf8ToBuffer } from "encloom/helpers/encoding";

const { privateKey, publicKey } = generateKeyPair();
const digest = sha256Sync(utf8ToBuffer("transfer:42"));

const sig = sign(privateKey, digest);
verify(publicKey, digest, sig); // ok; si falla → throw
```

Para pipelines estilo Ethereum existe `keccak256` en `encloom/sha3`. Keccak-256 ≠ SHA3-256 (FIPS); son dominios distintos y conviene no mezclarlos.

## Cuándo este enfoque ayuda (y cuándo no)

Tiene sentido si:

- cruzás Node / browser / edge con el mismo código de bytes
- usás pocas primitives y te importa lo que entra al bundle
- preferís tipos que no mientan (`Uint8Array` vs “stringly bytes”)

No aporta mucho si ya estás dentro de un stack que cubre el 80% de tu caso (p. ej. un SDK de wallet completo) y no te duele el tamaño ni el tipo de buffer.

## Referencias

- Paquete y docs de módulos: [encloom en npm](https://www.npmjs.com/package/encloom) · [repo](https://github.com/alejandrorodrom/encloom)
- Ideas relacionadas: Web Crypto (`SubtleCrypto`), familia `@noble` para implementaciones puras JS