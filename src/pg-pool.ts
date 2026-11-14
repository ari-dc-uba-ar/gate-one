import { Pool } from 'pg';
import { messages } from './messages.ts';

/**
 * The connection is configured with the standard PostgreSQL environment variables
 * (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, ...), which pg reads by itself.
 * Each service connects with its own role (see install/grants.sql).
 */
export function createPool(): Pool {
    var pool: Pool = new Pool();
    pool.on('error', function (error: Error): void {
        console.error(messages.databasePoolError, error);
    });
    return pool;
}
