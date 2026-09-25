import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK as JoseJwk } from 'jose';
import type { JWK, JWKS } from 'oidc-provider';
import { formatMessage, messages } from './messages.ts';
import type { SigningKeyStore } from './stores.ts';

const ALGORITHM: string = 'ES256';

function toProviderJwk(key: JoseJwk, keyId: string): JWK {
    if (key.kty == null || key.crv == null || key.x == null || key.y == null || key.d == null) {
        throw new Error(formatMessage(messages.generatedKeyLacksComponents, ALGORITHM));
    }
    return {
        kty: key.kty,
        crv: key.crv,
        x: key.x,
        y: key.y,
        d: key.d,
        kid: keyId,
        alg: ALGORITHM,
        use: 'sig',
    };
}

/**
 * Returns the signing key set. If the store has none it generates an ES256 pair and saves it.
 * The stored keys include the private part.
 */
export async function getKeySet(store: SigningKeyStore): Promise<JWKS> {
    var keys: JWK[] = await store.list();
    if (keys.length > 0) {
        return { keys: keys };
    }
    var pair = await generateKeyPair(ALGORITHM, { extractable: true });
    var privateKey: JoseJwk = await exportJWK(pair.privateKey);
    await store.add(toProviderJwk(privateKey, randomUUID()));
    // Read back: if another instance generated a key at the same time, both are published.
    return { keys: await store.list() };
}
