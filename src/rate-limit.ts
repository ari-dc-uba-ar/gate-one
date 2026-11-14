import type { FailureStore } from './stores.ts';

/**
 * Limits on failed sign-in attempts (wrong password or wrong second factor code):
 * - by username: 5 failures in a row lock it for 15 minutes; a successful sign-in resets the count.
 * - by IP address: 50 failures within 15 minutes block it until 15 minutes after the last one.
 * Unknown usernames count too, so the answer does not reveal which users exist.
 */
export const USER_FAILURE_LIMIT: number = 5;
export const IP_FAILURE_LIMIT: number = 50;
export const FAILURE_WINDOW_SECONDS: number = 15 * 60;

export interface Attempt {
    readonly username: string;
    readonly ip: string;
}

function userKey(attempt: Attempt): string {
    return 'user:' + attempt.username;
}

function ipKey(attempt: Attempt): string {
    return 'ip:' + attempt.ip;
}

export async function isBlocked(store: FailureStore, attempt: Attempt): Promise<boolean> {
    return await store.isBlocked(userKey(attempt), USER_FAILURE_LIMIT, FAILURE_WINDOW_SECONDS)
        || await store.isBlocked(ipKey(attempt), IP_FAILURE_LIMIT, FAILURE_WINDOW_SECONDS);
}

export async function recordFailure(store: FailureStore, attempt: Attempt): Promise<void> {
    await store.recordFailure(userKey(attempt), USER_FAILURE_LIMIT, FAILURE_WINDOW_SECONDS);
    await store.recordFailure(ipKey(attempt), IP_FAILURE_LIMIT, FAILURE_WINDOW_SECONDS);
}

export async function recordSuccess(store: FailureStore, attempt: Attempt): Promise<void> {
    await store.reset(userKey(attempt));
}
