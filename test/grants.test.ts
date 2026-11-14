import { strict as assert } from 'node:assert';
import type { Pool, PoolClient } from 'pg';
import { poolAs, prepareDatabase, TEST_ROLES } from './database.ts';

/** Runs the statement inside a transaction that is rolled back; tells whether the role may run it. */
async function allowed(pool: Pool, sql: string): Promise<boolean> {
    var client: PoolClient = await pool.connect();
    try {
        await client.query('begin');
        await client.query(sql);
        return true;
    } catch (error: unknown) {
        if (Reflect.get(Object(error), 'code') === '42501') {
            return false;
        }
        throw error;
    } finally {
        await client.query('rollback');
        client.release();
    }
}

describe('database roles', function (): void {
    var pool: Pool;
    var pools: Map<string, Pool> = new Map<string, Pool>();

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        await pool.query(`
            insert into gate_one.users (username, verifier, given_name, family_name)
                values ('ana', 'SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5', 'Ana', 'Muñoz');
            insert into gate_one.clients (client_id, client_secret, redirect_uris) values ('app', 'secret', array['http://app.example/cb']);
        `);
        for (var role of Object.values(TEST_ROLES)) {
            pools.set(role, poolAs(role));
        }
    });

    after(async function (): Promise<void> {
        for (var rolePool of pools.values()) {
            await rolePool.end();
        }
        await pool.end();
    });

    function as(role: string): Pool {
        var rolePool: Pool | undefined = pools.get(role);
        assert.ok(rolePool != null);
        return rolePool;
    }

    var cases: readonly (readonly [string, string, boolean])[] = [
        // 1. Authentication: reads users and clients, writes only its own records.
        [TEST_ROLES.auth, "select verifier, totp_secret, active from gate_one.users where username = 'ana'", true],
        [TEST_ROLES.auth, "update gate_one.users set totp_last_step = 1 where username = 'ana'", true],
        [TEST_ROLES.auth, "update gate_one.users set verifier = 'x' where username = 'ana'", false],
        [TEST_ROLES.auth, "update gate_one.users set active = true where username = 'ana'", false],
        [TEST_ROLES.auth, "update gate_one.users set totp_secret = null where username = 'ana'", false],
        [TEST_ROLES.auth, "insert into gate_one.users (username, verifier, given_name, family_name) values ('x', 'SCRAM-SHA-256$x', 'x', 'x')", false],
        [TEST_ROLES.auth, "select client_secret from gate_one.clients", true],
        [TEST_ROLES.auth, "update gate_one.clients set client_secret = 'x'", false],
        [TEST_ROLES.auth, "insert into gate_one.client_resources (client_id, resource, scopes) values ('app', 'x', array['x'])", false],
        [TEST_ROLES.auth, "select jwk from gate_one.signing_keys", true],
        [TEST_ROLES.auth, "insert into gate_one.signing_keys (kid, jwk) values ('x', '{}')", false],
        // 2. Applications: only clients, APIs and their permissions.
        [TEST_ROLES.apps, "update gate_one.clients set client_secret = 'x'", true],
        [TEST_ROLES.apps, "insert into gate_one.resource_servers (resource, scopes) values ('http://api.example', array['x'])", true],
        [TEST_ROLES.apps, "select username from gate_one.users", false],
        [TEST_ROLES.apps, "select payload from gate_one.oidc_models", false],
        [TEST_ROLES.apps, "select jwk from gate_one.signing_keys", false],
        // 3. Users: only users and, to reset the second factor, removing remembered devices.
        [TEST_ROLES.userAdmin, "insert into gate_one.users (username, verifier, given_name, family_name) values ('x', 'SCRAM-SHA-256$x', 'x', 'x')", true],
        [TEST_ROLES.userAdmin, "update gate_one.users set verifier = 'SCRAM-SHA-256$y', active = false where username = 'ana'", true],
        [TEST_ROLES.userAdmin, "delete from gate_one.users where username = 'ana'", false],
        [TEST_ROLES.userAdmin, "delete from gate_one.trusted_devices where username = 'ana'", true],
        [TEST_ROLES.userAdmin, "insert into gate_one.trusted_devices (token_hash, username, expires_at) values ('x', 'ana', current_timestamp)", false],
        [TEST_ROLES.userAdmin, "select client_secret from gate_one.clients", false],
        [TEST_ROLES.userAdmin, "select payload from gate_one.oidc_models", false],
        [TEST_ROLES.userAdmin, "select key from gate_one.auth_failures", false],
        [TEST_ROLES.userAdmin, "select jwk from gate_one.signing_keys", false],
    ];

    cases.forEach(function ([role, sql, expected]: readonly [string, string, boolean]): void {
        it((expected ? 'allows ' : 'denies ') + role + ': ' + sql, async function (): Promise<void> {
            assert.equal(await allowed(as(role), sql), expected);
        });
    });
});
