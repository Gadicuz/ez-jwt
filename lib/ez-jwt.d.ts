/**
 * RFC 7518 (https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)
 */
/** Cryptographic Algorithms for Digital Signatures and MACs */
declare type JWSAlg = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'none';
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
export declare type JWSCompactSerialization = string;
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
export declare type JwsKeyProvider = (h: JWSHeader) => Promise<JWK[]>;
/** Application provided key(s) or key set */
export declare type JwsAppKeys = JWK | JWK[] | JWKS;
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
export declare function jwtValidate<T extends JWT>(jwscs: JWSCompactSerialization, opt?: JWTValidationOptions): Promise<T>;
/** Loads JWKS for `uri` */
export declare function jwkLoadKeySet(uri: string): Promise<JWKS>;
/** 'Default' keys provider
 *
 * Returns a function to provide array of the keys:
 * ```
 * [ keys, headerJwkKey, headerJkuDownloadedKeys ]
 * ```
 * @param keys - additional application keys
 */
export declare function jwsHeaderKeysProvider(keys?: JwsAppKeys): JwsKeyProvider;
/**
 * Returns a function to provide array of keys, passed as `keys` parameter. JWS header is ignored.
 */
export declare function jwkAppKeysProvider(keys: JwsAppKeys): JwsKeyProvider;
/**
 * Returns a function to provide array of keys form key set, available at `uri`. JWS header is ignored.
 */
export declare function jwkAppUriProvider(uri: string): JwsKeyProvider;
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
export declare function jwsValidate(jwscs: JWSCompactSerialization, keyProvider?: JwsKeyProvider): Promise<JWS>;
export {};
