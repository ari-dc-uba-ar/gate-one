import { strict as assert } from 'node:assert';
import type { Adapter, AdapterFactory, AdapterPayload } from 'oidc-provider';
import type { Pool } from 'pg';
import { createPgAdapterFactory, deleteExpiredModels } from '../src/pg-stores.ts';
import { prepareDatabase } from './database.ts';

describe('oidc-provider adapter', function (): void {
    var pool: Pool;
    var factory: AdapterFactory;

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        factory = createPgAdapterFactory(pool);
    });

    after(async function (): Promise<void> {
        await pool.end();
    });

    it('stores, finds, replaces and destroys records', async function (): Promise<void> {
        var adapter: Adapter = factory('Interaction');
        await adapter.upsert('i1', { returnTo: 'first' }, 60);
        assert.deepEqual(await adapter.find('i1'), { returnTo: 'first' });
        await adapter.upsert('i1', { returnTo: 'second' }, 60);
        assert.deepEqual(await adapter.find('i1'), { returnTo: 'second' });
        await adapter.destroy('i1');
        assert.equal(await adapter.find('i1'), undefined);
    });

    it('keeps models apart', async function (): Promise<void> {
        await factory('Interaction').upsert('same-id', { returnTo: 'interaction' }, 60);
        await factory('Grant').upsert('same-id', { accountId: 'grant' }, 60);
        assert.deepEqual(await factory('Interaction').find('same-id'), { returnTo: 'interaction' });
        assert.deepEqual(await factory('Grant').find('same-id'), { accountId: 'grant' });
    });

    it('does not return expired records and deleteExpiredModels removes them', async function (): Promise<void> {
        var adapter: Adapter = factory('AuthorizationCode');
        await adapter.upsert('old', { accountId: 'ana' }, 60);
        await pool.query("update gate_one.oidc_models set expires_at = current_timestamp - interval '1 second' where id = 'old'");
        assert.equal(await adapter.find('old'), undefined);
        assert.ok(await deleteExpiredModels(pool) >= 1);
        var result = await pool.query("select 1 from gate_one.oidc_models where id = 'old'");
        assert.equal(result.rows.length, 0);
    });

    it('keeps records without expiration', async function (): Promise<void> {
        await factory('Session').upsert('s0', { accountId: 'ana', uid: 'u0' });
        await deleteExpiredModels(pool);
        assert.deepEqual(await factory('Session').find('s0'), { accountId: 'ana', uid: 'u0' });
    });

    it('marks a record as consumed', async function (): Promise<void> {
        var adapter: Adapter = factory('AuthorizationCode');
        await adapter.upsert('c1', { accountId: 'ana' }, 60);
        await adapter.consume('c1');
        var payload: AdapterPayload | undefined | void = await adapter.find('c1');
        assert.equal(typeof payload?.consumed, 'number');
        assert.ok(Math.abs(Number(payload?.consumed) - Date.now() / 1000) < 60);
    });

    it('finds a session by uid', async function (): Promise<void> {
        var adapter: Adapter = factory('Session');
        await adapter.upsert('s1', { accountId: 'ana', uid: 'uid-1' }, 60);
        assert.deepEqual(await adapter.findByUid('uid-1'), { accountId: 'ana', uid: 'uid-1' });
        assert.equal(await adapter.findByUid('uid-2'), undefined);
    });

    it('finds a device code by user code', async function (): Promise<void> {
        var adapter: Adapter = factory('DeviceCode');
        await adapter.upsert('d1', { userCode: 'ABCD-EFGH' }, 60);
        assert.deepEqual(await adapter.findByUserCode('ABCD-EFGH'), { userCode: 'ABCD-EFGH' });
    });

    it('revokes every record of a grant', async function (): Promise<void> {
        await factory('AuthorizationCode').upsert('g-code', { grantId: 'g1' }, 60);
        await factory('RefreshToken').upsert('g-refresh', { grantId: 'g1' }, 60);
        await factory('RefreshToken').upsert('other-refresh', { grantId: 'g2' }, 60);
        await factory('Interaction').upsert('g-interaction', { grantId: 'g1' }, 60);
        await factory('Grant').revokeByGrantId('g1');
        assert.equal(await factory('AuthorizationCode').find('g-code'), undefined);
        assert.equal(await factory('RefreshToken').find('g-refresh'), undefined);
        assert.deepEqual(await factory('RefreshToken').find('other-refresh'), { grantId: 'g2' });
        // Interactions are not grantable, as in oidc-provider's memory adapter.
        assert.deepEqual(await factory('Interaction').find('g-interaction'), { grantId: 'g1' });
    });
});
