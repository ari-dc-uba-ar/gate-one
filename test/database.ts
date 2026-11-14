import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Pool } from 'pg';

/** Test roles, one per service, with the permissions of install/grants.sql. */
export const TEST_ROLES = {
    auth: 'gate_one_test_auth',
    apps: 'gate_one_test_apps',
    users: 'gate_one_test_users',
} as const;

/**
 * Recreates the gate_one schema from install/schema.sql in the database given by the
 * standard PG* environment variables, creates the test roles if they do not exist and gives them
 * the permissions of install/grants.sql. Since it drops the schema, it refuses to run
 * unless the database name contains "test". The connection must be a superuser's.
 */
export async function prepareDatabase(): Promise<Pool> {
    var database: string = process.env.PGDATABASE ?? '';
    if (!database.includes('test')) {
        throw new Error('the tests drop and recreate the gate_one schema: PGDATABASE must name a test database (containing "test"), it is "' + database + '"');
    }
    var pool: Pool = new Pool();
    await pool.query('drop schema if exists gate_one cascade');
    await pool.query(await readFile(resolve(process.cwd(), 'install', 'schema.sql'), 'utf8'));
    for (var role of Object.values(TEST_ROLES)) {
        var exists = await pool.query('select 1 from pg_roles where rolname = $1', [role]);
        if (exists.rows.length === 0) {
            await pool.query('create role "' + role + '" nologin');
        }
    }
    // install/grants.sql uses psql variables; here they are replaced by the test roles.
    var grants: string = (await readFile(resolve(process.cwd(), 'install', 'grants.sql'), 'utf8'))
        .replaceAll(':"auth_role"', '"' + TEST_ROLES.auth + '"')
        .replaceAll(':"apps_role"', '"' + TEST_ROLES.apps + '"')
        .replaceAll(':"users_role"', '"' + TEST_ROLES.users + '"');
    if (grants.includes(':"')) {
        throw new Error('install/grants.sql uses a psql variable the tests do not replace');
    }
    await pool.query(grants);
    return pool;
}

/** A pool whose connections act as the given role (set at connection time; an unknown role fails the connection). */
export function poolAs(role: string): Pool {
    return new Pool({ options: '-c role=' + role });
}
