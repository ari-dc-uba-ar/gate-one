import { strict as assert } from 'node:assert';
import type { JWKS } from 'oidc-provider';
import type { Pool } from 'pg';
import { createSigningKey, getKeySet } from '../src/keys.ts';
import { createPgSigningKeyStore } from '../src/pg-auth-stores.ts';
import { createPgSigningKeyAdminStore } from '../src/pg-signing-key-admin-store.ts';
import { poolAs, prepareDatabase, TEST_ROLES } from './database.ts';

describe('signing keys', function (): void {
    var pool: Pool;
    var authPool: Pool;

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        authPool = poolAs(TEST_ROLES.auth);
    });

    after(async function (): Promise<void> {
        await authPool.end();
        await pool.end();
    });

    it('the authentication service refuses to start without a key', async function (): Promise<void> {
        await assert.rejects(getKeySet(createPgSigningKeyStore(authPool)), /create-signing-key/);
    });

    it('the authentication service cannot create keys', async function (): Promise<void> {
        await assert.rejects(createSigningKey(createPgSigningKeyAdminStore(authPool)), /permission denied/);
    });

    it('an administrator creates an ES256 key and the authentication service reads it', async function (): Promise<void> {
        var kid: string = await createSigningKey(createPgSigningKeyAdminStore(pool));
        var keySet: JWKS = await getKeySet(createPgSigningKeyStore(authPool));
        assert.equal(keySet.keys.length, 1);
        assert.equal(keySet.keys[0].kid, kid);
        assert.equal(keySet.keys[0].alg, 'ES256');
        assert.equal(typeof Reflect.get(keySet.keys[0], 'd'), 'string');
    });

    it('rejects a stored key whose kid does not match', async function (): Promise<void> {
        await pool.query(`insert into gate_one.signing_keys (kid, jwk) values ('k2', '{"kty":"EC","kid":"other"}')`);
        await assert.rejects(createPgSigningKeyStore(authPool).list(), /signing key k2/);
    });
});
