import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { exportJWK, generateKeyPair, type JWK as JoseJwk } from 'jose';
import type { JWK, JWKS } from 'oidc-provider';
import { formatMessage, messages } from './messages.ts';

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

function isKeySet(content: unknown): content is JWKS {
    if (typeof content !== 'object' || content === null) return false;
    var keys: unknown = Reflect.get(content, 'keys');
    return Array.isArray(keys) && keys.length > 0;
}

/**
 * Returns the signing key set. If the file does not exist it generates an ES256 pair and saves it.
 * The file holds the private key: it stays out of version control.
 */
export async function getKeySet(file: string): Promise<JWKS> {
    var text: string | undefined;
    try {
        text = await readFile(file, 'utf8');
    } catch (error: unknown) {
        if (!(error instanceof Error && Reflect.get(error, 'code') === 'ENOENT')) {
            throw error;
        }
        text = undefined;
    }
    if (text != null) {
        var content: unknown = JSON.parse(text);
        if (!isKeySet(content)) {
            throw new Error(formatMessage(messages.keysFileInvalid, file));
        }
        return content;
    }
    var pair = await generateKeyPair(ALGORITHM, { extractable: true });
    var privateKey: JoseJwk = await exportJWK(pair.privateKey);
    var keySet: JWKS = { keys: [toProviderJwk(privateKey, randomUUID())] };
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(keySet, null, 4), { encoding: 'utf8', mode: 0o600 });
    return keySet;
}
