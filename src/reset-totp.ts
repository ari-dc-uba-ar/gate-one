import type { Pool } from 'pg';
import { readLang } from './config.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createPool } from './pg-pool.ts';
import { createPgUserAdminStore } from './pg-user-admin-store.ts';

/** Removes the second factor of a user (for example, after losing the phone) and forgets the remembered devices. */
async function main(): Promise<void> {
    setLang(readLang());
    var args: string[] = process.argv.slice(2);
    if (args.length !== 1) {
        throw new Error(messages.resetTotpUsage);
    }
    var username: string = args[0];
    var pool: Pool = createPool();
    try {
        if (!await createPgUserAdminStore(pool).resetTotp(username)) {
            throw new Error(formatMessage(messages.userNotFound, username));
        }
        console.log(formatMessage(messages.totpReset, username));
    } finally {
        await pool.end();
    }
}

main().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
