import type { Pool } from 'pg';
import { readLang } from './config.ts';
import { createSigningKey } from './keys.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createPool } from './pg-pool.ts';
import { createPgSigningKeyAdminStore } from './pg-signing-key-admin-store.ts';

/**
 * Creates a signing key. It is run at installation time by an administrator (the authentication
 * service can only read the keys), with the connection given by the PG* environment variables.
 */
async function main(): Promise<void> {
    setLang(readLang());
    var pool: Pool = createPool();
    try {
        var kid: string = await createSigningKey(createPgSigningKeyAdminStore(pool));
        console.log(formatMessage(messages.signingKeyCreated, kid));
    } finally {
        await pool.end();
    }
}

main().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
