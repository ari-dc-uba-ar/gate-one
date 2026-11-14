import { strict as assert } from 'node:assert';
import type { Pool } from 'pg';
import { createPgFailureStore, deleteExpiredSecurityRecords } from '../src/pg-stores.ts';
import { FAILURE_WINDOW_SECONDS, IP_FAILURE_LIMIT, isBlocked, recordFailure, recordSuccess, USER_FAILURE_LIMIT, type Attempt } from '../src/rate-limit.ts';
import type { FailureStore } from '../src/stores.ts';
import { prepareDatabase } from './database.ts';

describe('rate limit', function (): void {
    var pool: Pool;
    var store: FailureStore;

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        store = createPgFailureStore(pool);
    });

    after(async function (): Promise<void> {
        await pool.end();
    });

    async function fail(attempt: Attempt, times: number): Promise<void> {
        for (var i: number = 0; i < times; i++) {
            await recordFailure(store, attempt);
        }
    }

    it('blocks a username after 5 failures and a success resets it', async function (): Promise<void> {
        var attempt: Attempt = { username: 'ana', ip: '10.0.0.1' };
        await fail(attempt, USER_FAILURE_LIMIT - 1);
        assert.equal(await isBlocked(store, attempt), false);
        await recordSuccess(store, attempt);
        await fail(attempt, USER_FAILURE_LIMIT - 1);
        assert.equal(await isBlocked(store, attempt), false);
        await fail(attempt, 1);
        assert.equal(await isBlocked(store, attempt), true);
        assert.equal(await isBlocked(store, { username: 'ana', ip: '10.0.0.2' }), true);
        assert.equal(await isBlocked(store, { username: 'bea', ip: '10.0.0.2' }), false);
    });

    it('unblocks 15 minutes after the last failure', async function (): Promise<void> {
        var attempt: Attempt = { username: 'carla', ip: '10.0.0.3' };
        await fail(attempt, USER_FAILURE_LIMIT);
        assert.equal(await isBlocked(store, attempt), true);
        await pool.query("update gate_one.auth_failures set window_start = current_timestamp - interval '16 minutes' where key = 'user:carla'");
        assert.equal(await isBlocked(store, attempt), false);
        // The window expired, so the count starts again.
        await fail(attempt, 1);
        assert.equal(await isBlocked(store, attempt), false);
    });

    it('blocks an IP address after 50 failures, whatever the usernames', async function (): Promise<void> {
        for (var i: number = 0; i < IP_FAILURE_LIMIT; i++) {
            await recordFailure(store, { username: 'user' + i, ip: '10.0.0.4' });
        }
        assert.equal(await isBlocked(store, { username: 'dora', ip: '10.0.0.4' }), true);
        assert.equal(await isBlocked(store, { username: 'dora', ip: '10.0.0.5' }), false);
    });

    it('deletes the counts whose window ended', async function (): Promise<void> {
        await pool.query("update gate_one.auth_failures set window_start = current_timestamp - interval '16 minutes' where key = 'ip:10.0.0.4'");
        await deleteExpiredSecurityRecords(pool, FAILURE_WINDOW_SECONDS);
        var result = await pool.query("select key from gate_one.auth_failures where key = 'ip:10.0.0.4'");
        assert.equal(result.rows.length, 0);
    });
});
