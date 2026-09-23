import { strict as assert } from 'node:assert';
import type { Pool } from 'pg';
import { createPgClientStore } from '../src/pg-stores.ts';
import type { ClientStore } from '../src/stores.ts';
import { prepareDatabase } from './database.ts';

describe('clients', function (): void {
    var pool: Pool;
    var store: ClientStore;

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        store = createPgClientStore(pool);
        await pool.query(`
            insert into gate_one.clients (client_id, client_secret, redirect_uris, backchannel_logout_uri)
                values ('app1', 'secret1', array['http://app1.example/cb'], 'http://app1.example:80/logout'),
                       ('app2', 'secret2', array['http://app2.example/cb'], null);
            insert into gate_one.resource_servers (resource, scopes, access_token_ttl)
                values ('http://api1.example', array['read', 'write'], 300),
                       ('http://api2.example', array['admin'], 600);
            insert into gate_one.client_resources (client_id, resource, scopes)
                values ('app1', 'http://api1.example', array['read', 'delete']),
                       ('app1', 'http://api2.example', array['other']);
        `);
    });

    after(async function (): Promise<void> {
        await pool.end();
    });

    it('finds a registered client', async function (): Promise<void> {
        assert.deepEqual(await store.findClient('app1'), {
            clientId: 'app1',
            clientSecret: 'secret1',
            redirectUris: ['http://app1.example/cb'],
            postLogoutRedirectUris: [],
            backchannelLogoutUri: 'http://app1.example:80/logout',
        });
        assert.equal(await store.findClient('app3'), undefined);
    });

    it('gives only the scopes both granted and defined by the resource server', async function (): Promise<void> {
        assert.deepEqual(await store.findResources('app1'), [
            { resource: 'http://api1.example', scopes: ['read'], accessTokenTtl: 300 },
        ]);
        assert.deepEqual(await store.findResources('app2'), []);
    });

    it('recognizes back-channel logout URLs comparing them normalized', async function (): Promise<void> {
        assert.equal(await store.isBackchannelLogoutUri('http://app1.example/logout'), true);
        assert.equal(await store.isBackchannelLogoutUri('http://app1.example/other'), false);
        assert.equal(await store.isBackchannelLogoutUri('http://app2.example/logout'), false);
    });
});
