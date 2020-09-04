# ez-jwt

[JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token) and [JSON Web Signature (JWS)](https://en.wikipedia.org/wiki/JSON_Web_Signature) validation using [WEB Cryptography API](https://en.wikipedia.org/wiki/Web_Cryptography_API).

[![npm](https://img.shields.io/npm/v/ez-jwt)](https://www.npmjs.com/package/ez-jwt)
[![npm bundle size](https://img.shields.io/bundlephobia/min/ez-jwt)](https://bundlephobia.com/result?p=ez-jwt)
[![Top Language](https://img.shields.io/github/languages/top/gadicuz/ez-jwt)](https://github.com/gadicuz/ez-jwt)
[![MIT License](https://img.shields.io/github/license/gadicuz/ez-jwt)](https://github.com/Gadicuz/ez-jwt/blob/master/LICENSE)


# Features

* Validates JWT/JWS signature, returns JWT claims
  * <code>jwtValidate(jwt)</code> returns JWT claims
  * <code>jwsValidate(jws)</code> returns JWS (JOSE) header and JWS payload
* Accepts [JWS Compact Serialization](https://tools.ietf.org/html/rfc7515#section-7.1) format for JWT/JWS
* Uses Web Cryptography API to
  * import keys encoded in the JSON key format (JWK)
  * validate messages using digital signatures or MACs (JWS)
* Understands all standard algorithms for digital signatures and MACs (according to RFC 7518). Particular algorithm support depends on a browser.
* Сompliant with Javascript Object Signing and Encryption (JOSE) RFCs
  * [RFC 7515](https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)
  * [RFC 7516](https://tools.ietf.org/html/rfc7516) JSON Web JSON Web Encryption (JWE)
  * [RFC 7517](https://tools.ietf.org/html/rfc7517) JSON Web Key (JWK)
  * [RFC 7518](https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)
  * [RFC 7519](https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)
* Tiny package, no dependencies
* ES6 module, typings available


# Install

```bash
npm i ez-jwt
```

# Usage

The main function to validate a JWT and obtain the JWT claims is `jwtValidate()`. Let's use [RFC 7515 example JWT](https://tools.ietf.org/html/rfc7515#appendix-A.1).

```typescript
// JWS header is { typ: 'JWT', alg: 'HS256' }
// JWT claims is { iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true }
const token =
  'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJle' +
  'HAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnV' +
  'lfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
```

This token has no information about the key to validate it, so we need to provide the key explicitly. The public key to validate the token is present in the same example.
```typescript
const jwk = {
  kty: 'oct',
  k: 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
};
```

Use `jwtValidate()` and provide the key to validate the token, get JWT claims.

```typescript
import { jwtValidate } from 'ez-jwt';

jwtValidate(token, {keys: jwk})
  .then((claims) => {
    // JWT is valid
    // claims value is { iss: 'joe', exp: 1300819380, 'http://example.com/is_root': true }
  });
```

We don't need to provide any keys if a token JWS header has information about the key to validate it. See [Key providers](#keys-providers).

## JWT/JWS validation

Input JWT/JWS should be in JWS Compact Serialization format: a string of three BASE64URL-encoded parts (header, payload, and signature), separated by `.` symbols.

Any digitally signed JWT is a JWS with a well-defined payload, which is [JWT Claims](https://tools.ietf.org/html/rfc7519#section-4).

| Compact Serialization Format | `BASE64URL(JSON( x ))` | `.` | `BASE64URL( x )` | `.` | `BASE64URL( x )` |
|:---|:---:|:---:|:---:|:---:|:---:|
| JWS | `JWS Header` | | `ArrayBuffer` | | `JWS Signature` |
| JWT | `JWS Header` | | `JSON(JWT Claims)` | | `JWS Signature` |

JWT validation process performed by `jwtValidate()`:
* Validate JWT as JWS using `jwsValidate()`.
   - Split the input JWS into three parts: header, payload, signature.
   - `BASE64URL_DECODE()` all the parts.
   - UTF-8 decode and JSON parse the header, get JWS header.
   - Check JWS header parameter `crit` (should be undefined).
   - Check JWS header parameter `alg` (should be one of the standard algorithms).
   - Apply the key provider function to the header and get an array of keys.
   - Filter key array by key ID, algorithm, usage, and operations.
   - Use the remaining key(s) to verify JWS signature.
   - Return JWS header and payload.
* Check JWS header parameters `typ` (should be undefined or equals `'JWT'`) and `cty` (should be undefined).
* UTF-8 decode and JSON parse JWS payload, get JWT claims object.
* Validate JWT claims `exp` and `nbf` (if present).
* Return JWT claims.

## Keys providers

To validate a JWS Signature the correct public key is required. The key should be provided to `jwsValidate()` function. A token issuer can provide the public key to validate the token in several ways and different formats.

### JWK/JWKS public key
This is the main format of key data supported by the package.
* A JWK is provided in JWS header (parameter `jwk`).
* One or more JWK is known to the application.
* URI of [JWKS endpoint](#jwks-endpoint) is provided in JWS header (parameter `jku`).
* URI of JWKS endpoint is known to the application (for example `.well-known/jwks.json` for OAuth2 applications).

The default key provider `jwsHeaderKeysProvider()` gets `jwk` parameter key and adds all the keys from JWKS endpoint defined  by `jku` parameter. One can add some more application keys by passing them as an argument for `jwsHeaderKeysProvider(appKeys)`. `appKeys` value can be `JWK`, `JWK[]`, or `JWKS` object.

Two application keys providers `jwkAppKeysProvider()` and `jwkAppUriProvider()` ignore JWS header parameters and provide application keys only.

One can design a custom key provider function and pass it to `jwsValidate()`.
Key provider is a function that takes JWS header and returns keys to validate the JWS.
```typescript
type JwsKeyProvider = (h: JWSHeader) => Promise<JWK[]>;
```

Key provider functions summary:
| Key provider | JWS header `jkw` | JWS header `jku` | Application JWK/JWK[]/JWKS | Application JWKS endpoint |
|---|:---:|:---:|:---:|:---:|
|`jwsHeaderKeysProvider()`| + | + | | |
|`jwsHeaderKeysProvider(appKeys)`| + | + | `appKeys` | |
|`jwkAppKeysProvider(appKeys)`| | | `appKeys` | |
|`jwkAppUriProvider(jwks_uri)`| | | | `jwks_uri` |

Note: one can download all the keys from JWKS endpoint to `appKeys` variable in advance and use `jwkAppKeysProvider(appKeys)` (or `jwsHeaderKeysProvider(appKeys)`) provider instead of `jwkAppUriProvider()`.

### JWKS endpoint
A token issuer JWKS endpoint returns all the public keys the issuer uses to sign tokens. One can filter the keys by `kid` or try to use all the keys. For example, [Google's OpenID Connect services JWKS endpoint](https://www.googleapis.com/oauth2/v3/certs) returns the following two keys:
```json
{
  "keys": [
    {
      "kid": "0a7dc12664590c957ffaebf7b6718297b864ba91",
      "use": "sig",
      "kty": "RSA",
      "alg": "RS256",
      "e": "AQAB",
      "n": "7NfiTQcshWgrEdKbHC2e..............eNVz39274ippJSQ"
    },
    {
      "kid": "bc49530e1ff9083dd5eeaa06be2ce437f49c905e",
      "use": "sig",
      "kty": "RSA",
      "alg": "RS256",
      "e": "AQAB",
      "n": "xPXUFDnAQQ5daLQTcQsV..............Na3BbnAhj7miR0w"
    }
  ]
}
```

### X.509 certificate public key

Public key data can be provided X.509 certificate as a `SubjectPublicKeyInfo` object. JWS header parameters `x5u`, `x5c`, `x5t`, `x5t#S256` provide key data in form of an X.509 certificate.

Web Cryptography API doesn't support X.509 certificate processing so the package doesn't support those keys data. One can create a custom key provider function and use a third-party library to parse X.509 cert and convert key data to JWK format.
