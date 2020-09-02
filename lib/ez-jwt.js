/**
 * RFC 7518 (https://tools.ietf.org/html/rfc7518) JSON Web Algorithms (JWA)
 */
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
export function jwtValidate(jwscs, opt) {
    return jwsValidate(jwscs, jwkAppProvider(opt === null || opt === void 0 ? void 0 : opt.keys)).then((jws) => {
        var _a;
        if (jws.header.typ && jws.header.typ !== 'JWT')
            throw 'JWT: invalid type';
        if (jws.header.cty)
            throw 'JWT: invalid content type';
        const claims = JSON.parse(abDecode(jws.payload));
        const grace = (_a = opt === null || opt === void 0 ? void 0 : opt.grace) !== null && _a !== void 0 ? _a : 0;
        const now = Date.now() / 1000;
        if (claims.exp != undefined && claims.exp + grace < now)
            throw 'JWT: expired';
        if (claims.nbf != undefined && claims.nbf - grace > now)
            throw 'JWT: premature';
        return claims;
    });
}
function jwsGetSetup(alg) {
    const r = /(HS|RS|ES|PS)(256|384|512)$|^(none)$/.exec(alg);
    if (r) {
        if (r[3])
            return undefined;
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
function isValidJWKS(obj) {
    return typeof obj === 'object' && obj != undefined && Array.isArray(obj.keys);
}
/** Loads JWKS for `uri` */
export function jwkLoadKeySet(uri) {
    return fetch(uri).then((resp) => {
        if (!resp.ok)
            throw resp.statusText;
        return resp.json().then((data) => {
            if (!isValidJWKS(data))
                throw 'invalid format';
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
export function jwsHeaderKeysProvider(keys) {
    return (h) => {
        const k = jwkAppKeys(keys) || [];
        if (h.jwk)
            k.push(h.jwk);
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
function jwkAppKeys(keys) {
    return keys && (isValidJWKS(keys) ? keys.keys : Array.isArray(keys) ? keys : [keys]);
}
/**
 * Returns a function to provide array of keys, passed as `keys` parameter. JWS header is ignored.
 */
export function jwkAppKeysProvider(keys) {
    return () => Promise.resolve(jwkAppKeys(keys));
}
/**
 * Returns a function to provide array of keys form key set, available at `uri`. JWS header is ignored.
 */
export function jwkAppUriProvider(uri) {
    return () => jwkLoadKeySet(uri).then((jwks) => jwks.keys);
}
function jwkAppProvider(keys) {
    if (keys == undefined)
        return undefined;
    if (typeof keys === 'function')
        return keys;
    if (typeof keys === 'string')
        return jwkAppUriProvider(keys);
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
export function jwsValidate(jwscs, keyProvider = jwsHeaderKeysProvider()) {
    var _a;
    const parts = /^([\w-]*)\.([\w-]*)\.([\w-]*)$/.exec(jwscs);
    if (!parts)
        return Promise.reject('JWS: invalid serialization format');
    const [h, p, s] = parts.slice(1); // h, p, s - string_b64url
    const input = u8stoab(`${h}.${p}`);
    const sign = b64urlDecode(s);
    const jws = {
        header: JSON.parse(abDecode(b64urlDecode(h), 'utf-8')),
        payload: b64urlDecode(p),
    };
    if ((_a = jws.header.crit) === null || _a === void 0 ? void 0 : _a.length)
        return Promise.reject('JWS: unknown extention');
    const setup = jwsGetSetup(jws.header.alg);
    if (typeof setup === 'string')
        return Promise.reject(setup);
    const verifier = setup == undefined
        ? Promise.resolve(!s.length)
        : keyProvider(jws.header).then((keys) => {
            const hdr = jws.header;
            if (hdr.kid != undefined)
                keys = keys.filter((k) => k.kid === hdr.kid);
            keys = keys.filter((k) => (k.alg == undefined || k.alg === hdr.alg) &&
                (k.use == undefined || k.use === 'sig') &&
                (k.key_ops == undefined || k.key_ops.includes('verify')));
            if (!keys.length)
                throw 'JWS: no key found';
            if (keys.length > 1)
                throw 'JWS: multiple keys found';
            return crypto.subtle
                .importKey('jwk', keys[0], setup, false, ['verify'])
                .then((key) => crypto.subtle.verify(setup, key, sign, input));
        });
    return verifier.then((status) => {
        if (!status)
            throw 'JWS: validation failed';
        return jws;
    });
}
function b64urlUnpack(b64u) {
    // if (s === '') return '';
    const pad = b64u.length % 4;
    if (pad == 1 || !/^[\w-]*$/.test(b64u))
        throw 'Invalid base64url string';
    return b64u.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(-pad & 3);
}
function abDecode(ab, decoder = 'utf-8') {
    if (typeof decoder === 'string')
        decoder = new TextDecoder(decoder);
    return decoder.decode(ab);
}
function u8stoab(u8s) {
    return Uint8Array.from(u8s, (c) => c.charCodeAt(0)).buffer;
}
function b64urlDecode(b64u) {
    return u8stoab(atob(b64urlUnpack(b64u)));
}
//# sourceMappingURL=ez-jwt.js.map