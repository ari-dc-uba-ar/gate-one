import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { Pool } from 'pg';

/**
 * Recreates the gate_one schema from install/schema.sql in the database given by the
 * standard PG* environment variables. Since it drops the schema, it refuses to run
 * unless the database name contains "test".
 */
export async function prepareDatabase(): Promise<Pool> {
    var database: string = process.env.PGDATABASE ?? '';
    if (!database.includes('test')) {
        throw new Error('the tests drop and recreate the gate_one schema: PGDATABASE must name a test database (containing "test"), it is "' + database + '"');
    }
    var pool: Pool = new Pool();
    await pool.query('drop schema if exists gate_one cascade');
    await pool.query(await readFile(resolve(process.cwd(), 'install', 'schema.sql'), 'utf8'));
    return pool;
}
