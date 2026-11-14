import { randomUUID } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK as JoseJwk } from 'jose';
import type { JWK, JWKS } from 'oidc-provider';
import { formatMessage, messages } from './messages.ts';
import type { SigningKeyAdminStore, SigningKeyStore } from './stores.ts';

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
 * Returns the signing key set. The keys are created at installation time (create-signing-key),
 * so the authentication service only reads them; without any it cannot start.
 */
export async function getKeySet(store: SigningKeyStore): Promise<JWKS> {
    var keys: JWK[] = await store.list();
    if (keys.length === 0) {
        throw new Error(messages.noSigningKey);
    }
    return { keys: keys };
}

/** Generates an ES256 pair and saves it (the stored key includes the private part). Returns its kid. */
export async function createSigningKey(store: SigningKeyAdminStore): Promise<string> {
    var pair = await generateKeyPair(ALGORITHM, { extractable: true });
    var privateKey: JoseJwk = await exportJWK(pair.privateKey);
    var key: JWK = toProviderJwk(privateKey, randomUUID());
    await store.add(key);
    return String(key.kid);
}
