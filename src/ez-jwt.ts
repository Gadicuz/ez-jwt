/**
 * RFC 7518 (https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)
 */

/** Cryptographic Algorithms for Digital Signatures and MACs */
type JWSAlg =
  | 'HS256' // HMAC using SHA-256
  | 'HS384' // HMAC using SHA-384
  | 'HS512' // HMAC using SHA-512
  | 'RS256' // RSASSA-PKCS1-v1_5 using SHA-256
  | 'RS384' // RSASSA-PKCS1-v1_5 using SHA-384
  | 'RS512' // RSASSA-PKCS1-v1_5 using SHA-512
  | 'ES256' // ECDSA using P-256 and SHA-256
  | 'ES384' // ECDSA using P-384 and SHA-384
  | 'ES512' // ECDSA using P-512 and SHA-512
  | 'PS256' // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  | 'PS384' // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  | 'PS512' // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  | 'none'; // No digital signature or MAC performed

/**
 * RFC 7517 (https://tools.ietf.org/html/rfc7517) JSON Web Key (JWK)
 */

/** A JWK is a JSON object that represents a cryptographic key. */
export interface JWK extends JsonWebKey {
  /** The "kid" (key ID) parameter is used to match a specific key. */
  kid?: string;
  /** Identifies the intended use of the public key */
  use?: 'sig' | 'enc';
  /** Identifies the operation(s) for which the key is intended to be used. */
  key_ops?: KeyUsage[];
}

/** A JWK Set is a JSON object that represents a set of JWKs. */
export interface JWKS {
  /** The value of the "keys" parameter is an array of JWK values. */
  keys: JWK[];
}

/**
 * RFC 7515 (https://tools.ietf.org/html/rfc7515) JSON Web Signature (JWS)
 */

/** JWS Compact Serialization
 *
 * The JWS Compact Serialization represents digitally signed or MACed
 * content as a compact, URL-safe string.
 * ```
 * BASE64URL(UTF8(JWS Protected Header)) . BASE64URL(JWS Payload) . BASE64URL(JWS Signature)
 * ```
 */
export type JWSCompactSerialization = string;

/** JOSE Header for JWS
 *
 * The members of the JSON object(s) describe the digital signature or MAC applied to
 * the JWS Protected Header and the JWS Payload and optionally additional properties of the JWS.
 */
export interface JWSHeader {
  /** The media type of this complete JWS. */
  typ?: string;
  /** The media type of the secured content (the payload). */
  cty?: string;
  /** Extensions to this specification and/or [JWA] are being used that MUST be understood and processed. */
  crit?: string[];
  /** Cryptographic algorithm used to secure the JWS. */
  alg: JWSAlg;
  /** A hint indicating which key was used to secure the JWS. */
  kid?: string;
  /** The public key that corresponds to the key used to digitally sign the JWS. */
  jwk?: JWK;
  /** A URI that refers to a resource for a set of JSON-encoded public keys. */
  jku?: string;
  /** URI to download X.509 cert (chain) with the public key was used to secure JWS. */
  x5u?: string;
  /** array of base64-encoded strings of X.509 cert (chain) */
  x5c?: string[];
  /** base64url-encoded SHA-1 thumbprint of X.509 cert with the key */
  x5t?: string;
  /** base64url-encoded SHA-256 thumbprint of X.509 cert with the key */
  'x5t#S256'?: string;
}

/** JWS represents digitally signed or MACed content using JSON data structures and base64url encoding. */
export interface JWS {
  /** JOSE Header */
  header: JWSHeader;
  /** Payload */
  payload: ArrayBuffer;
}

/**
 * RFC 7519 (https://tools.ietf.org/html/rfc7519) JSON Web Token (JWT)
 */

/** JWTs represent a set of claims as a JSON object that is encoded in a JWS and/or JWE structure. */
export interface JWT {
  /** Identifies the principal that issued the JWT. */
  iss?: string;
  /** Identifies the principal that is the subject of the JWT. */
  sub?: string;
  /** Identifies the recipients that the JWT is intended for. */
  aud?: string[] | string;
  /** Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. */
  exp?: number;
  /** Identifies the time before which the JWT MUST NOT be accepted for processing. */
  nbf?: number;
  /** Identifies the time at which the JWT was issued. */
  iat?: number;
  /** Provides a unique identifier for the JWT. */
  jti?: string;
}

/** A function to provide an array of JWK for a JWS Header. The keys are used to verify the JWS signature. */
export type JwsKeyProvider = (h: JWSHeader) => Promise<JWK[]>;

/** Application provided key(s) or key set */
export type JwsAppKeys = JWK | JWK[] | JWKS;

/** An JWT validation options */
export interface JWTValidationOptions {
  /** Key(s), key set, JWKS endpoint URI or custom keys provider. */
  keys?: JwsAppKeys | string | JwsKeyProvider;
  /** Grace period (in sec.) to validate `exp` and `nbf` JWT claims. */
  grace?: number;
}

/**
 * Validates JSON Web Token (JWT).
 *
 * JWT is provided in JWS Compact Serialization format:
 * ```
 * BASE64URL(UTF8(JWS Protected Header)) . BASE64URL(UTF8(JWT)) . BASE64URL(JWS Signature)
 * ```
 *
 * @param jwscs - JWT to validate
 * @param opt - validation options
 * @returns JWT claims
 */
export function jwtValidate<T extends JWT>(jwscs: JWSCompactSerialization, opt?: JWTValidationOptions): Promise<T> {
  return jwsValidate(jwscs, jwkAppProvider(opt?.keys)).then((jws) => {
    if (jws.header.typ && jws.header.typ !== 'JWT') throw 'JWT: invalid type';
    if (jws.header.cty) throw 'JWT: invalid content type';
    const claims = JSON.parse(abDecode(jws.payload)) as T;
    const grace = opt?.grace ?? 0;
    const now = Date.now() / 1000;
    if (claims.exp != undefined && claims.exp + grace < now) throw 'JWT: expired';
    if (claims.nbf != undefined && claims.nbf - grace > now) throw 'JWT: premature';
    return claims;
  });
}

type HmacSetup = HmacImportParams & Algorithm; // 'HS256' | 'HS384' | 'HS512'
type RsaPkcs1Setup = RsaHashedImportParams & Algorithm; // 'RS256' | 'RS384' | 'RS512'
type EcdsaSetup = EcKeyImportParams & EcdsaParams; // 'ES256' | 'ES384' | 'ES512'
type RsaPssSetup = RsaHashedImportParams & RsaPssParams; // 'PS256' | 'PS384' | 'PS512'
type NoneSetup = undefined; // none

function jwsGetSetup(alg: JWSAlg): HmacSetup | RsaPkcs1Setup | EcdsaSetup | RsaPssSetup | NoneSetup | string {
  const r = /(HS|RS|ES|PS)(256|384|512)$|^(none)$/.exec(alg);
  if (r) {
    if (r[3]) return undefined;
    const bits = +r[2];
    const hash = `SHA-${bits}`;
    switch (r[1]) {
      case 'HS':
        return { name: 'HMAC', hash };
      case 'RS':
        return { name: 'RSASSA-PKCS1-v1_5', hash };
      case 'ES':
        return { name: 'ECDSA', hash, namedCurve: `P-${bits}` };
      case 'PS':
        return { name: 'RSASSA-PSS', hash, saltLength: bits / 8 };
    }
  }
  return `JWS: unsupported algorithm '${alg}'`;
}

function isValidJWKS(obj: unknown): obj is JWKS {
  return typeof obj === 'object' && obj != undefined && Array.isArray((obj as JWKS).keys);
}

/** Loads JWKS for `uri` */
export function jwkLoadKeySet(uri: string): Promise<JWKS> {
  return fetch(uri).then((resp) => {
    if (!resp.ok) throw resp.statusText;
    return resp.json().then((data) => {
      if (!isValidJWKS(data)) throw 'invalid format';
      return data;
    });
  });
}

/** 'Default' keys provider
 *
 * Returns a function to provide array of the keys:
 * ```
 * [ keys, headerJwkKey, headerJkuDownloadedKeys ]
 * ```
 * @param keys - additional application keys
 */
export function jwsHeaderKeysProvider(keys?: JwsAppKeys): JwsKeyProvider {
  return (h) => {
    const k = jwkAppKeys(keys) || [];
    if (h.jwk) k.push(h.jwk);
    const uri = h.jku;
    return !uri
      ? Promise.resolve(k)
      : jwkLoadKeySet(uri)
          .then((jwks) => k.concat(jwks.keys))
          .catch((e) => {
            console.log(`JWS: key set '${uri}' download error '${String(e)}`);
            return k;
          });
  };
}

function jwkAppKeys(keys: JwsAppKeys): JWK[];
function jwkAppKeys(keys?: JwsAppKeys): JWK[] | undefined;
function jwkAppKeys(keys?: JwsAppKeys): JWK[] | undefined {
  return keys && (isValidJWKS(keys) ? keys.keys : Array.isArray(keys) ? keys : [keys]);
}

/**
 * Returns a function to provide array of keys, passed as `keys` parameter. JWS header is ignored.
 */
export function jwkAppKeysProvider(keys: JwsAppKeys): JwsKeyProvider {
  return () => Promise.resolve(jwkAppKeys(keys));
}

/**
 * Returns a function to provide array of keys form key set, available at `uri`. JWS header is ignored.
 */
export function jwkAppUriProvider(uri: string): JwsKeyProvider {
  return () => jwkLoadKeySet(uri).then((jwks) => jwks.keys);
}

function jwkAppProvider(keys?: JwsAppKeys | string | JwsKeyProvider): JwsKeyProvider | undefined {
  if (keys == undefined) return undefined;
  if (typeof keys === 'function') return keys;
  if (typeof keys === 'string') return jwkAppUriProvider(keys);
  return jwkAppKeysProvider(keys);
}

/**
 * Validates JSON Web Signature (JWS).
 *
 * JWS is provided in JWS Compact Serialization format:
 * ```
 * BASE64URL(UTF8(JWS Protected Header)) . BASE64URL(JWS Payload) . BASE64URL(JWS Signature)
 * ```
 *
 * @param jwscs - JWS to validate
 * @param keyProvider - provider function to validate JWS signature, JWS header keys are used by default
 * @returns JWS = header + payload
 */
export function jwsValidate(
  jwscs: JWSCompactSerialization,
  keyProvider: JwsKeyProvider = jwsHeaderKeysProvider()
): Promise<JWS> {
  const parts = /^([\w-]*)\.([\w-]*)\.([\w-]*)$/.exec(jwscs);
  if (!parts) return Promise.reject('JWS: invalid serialization format');
  const [h, p, s] = parts.slice(1); // h, p, s - string_b64url
  const input = u8stoab(`${h}.${p}`);
  const sign = b64urlDecode(s);
  const jws = {
    header: JSON.parse(abDecode(b64urlDecode(h), 'utf-8')) as JWSHeader,
    payload: b64urlDecode(p),
  };
  if (jws.header.crit?.length) return Promise.reject('JWS: unknown extention');
  const setup = jwsGetSetup(jws.header.alg);
  if (typeof setup === 'string') return Promise.reject(setup);
  const verifier =
    setup == undefined
      ? Promise.resolve(!s.length)
      : keyProvider(jws.header).then((keys) => {
          const hdr = jws.header;
          if (hdr.kid != undefined) keys = keys.filter((k) => k.kid === hdr.kid);
          keys = keys.filter(
            (k) =>
              (k.alg == undefined || k.alg === hdr.alg) &&
              (k.use == undefined || k.use === 'sig') &&
              (k.key_ops == undefined || k.key_ops.includes('verify'))
          );
          if (!keys.length) throw 'JWS: no key found';
          if (keys.length > 1) throw 'JWS: multiple keys found';
          return crypto.subtle
            .importKey('jwk', keys[0], setup, false, ['verify'])
            .then((key) => crypto.subtle.verify(setup, key, sign, input));
        });
  return verifier.then((status) => {
    if (!status) throw 'JWS: validation failed';
    return jws;
  });
}

type string_uint8 = string; // #0x00..#0xFF
type string_b64 = string; // A..Za..z0..9+/ padding =
type string_b64url = string; // A..Za..z0..9-_ no padding

function b64urlUnpack(b64u: string_b64url): string_b64 {
  // if (s === '') return '';
  const pad = b64u.length % 4;
  if (pad == 1 || !/^[\w-]*$/.test(b64u)) throw 'Invalid base64url string';
  return b64u.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(-pad & 3);
}

function abDecode(ab: ArrayBuffer, decoder: TextDecoder | string = 'utf-8'): string {
  if (typeof decoder === 'string') decoder = new TextDecoder(decoder);
  return decoder.decode(ab);
}

function u8stoab(u8s: string_uint8): ArrayBuffer {
  return Uint8Array.from(u8s, (c) => c.charCodeAt(0)).buffer;
}

function b64urlDecode(b64u: string_b64url): ArrayBuffer {
  return u8stoab(atob(b64urlUnpack(b64u)));
}
