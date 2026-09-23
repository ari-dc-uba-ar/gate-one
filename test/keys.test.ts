import { strict as assert } from 'node:assert';
import type { JWKS } from 'oidc-provider';
import type { Pool } from 'pg';
import { getKeySet } from '../src/keys.ts';
import { createPgSigningKeyStore } from '../src/pg-stores.ts';
import { prepareDatabase } from './database.ts';

describe('signing keys', function (): void {
    var pool: Pool;

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
    });

    after(async function (): Promise<void> {
        await pool.end();
    });

    it('generates an ES256 key once and then reuses it', async function (): Promise<void> {
        var first: JWKS = await getKeySet(createPgSigningKeyStore(pool));
        assert.equal(first.keys.length, 1);
        assert.equal(first.keys[0].alg, 'ES256');
        assert.equal(typeof Reflect.get(first.keys[0], 'd'), 'string');
        var second: JWKS = await getKeySet(createPgSigningKeyStore(pool));
        assert.deepEqual(second, first);
    });

    it('rejects a stored key whose kid does not match', async function (): Promise<void> {
        await pool.query(`insert into gate_one.signing_keys (kid, jwk) values ('k2', '{"kty":"EC","kid":"other"}')`);
        await assert.rejects(createPgSigningKeyStore(pool).list(), /signing key k2/);
    });
});
