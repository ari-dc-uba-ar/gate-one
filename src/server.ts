import type { Express } from 'express';
import type { Pool } from 'pg';
import { createApp } from './app.ts';
import { readConfig, readLang, type Config } from './config.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import {
    createPgAdapterFactory,
    createPgClientStore,
    createPgSigningKeyStore,
    createPgUserStore,
    createPool,
    deleteExpiredModels,
} from './pg-stores.ts';

const EXPIRED_CLEANUP_INTERVAL_MS: number = 10 * 60 * 1000;

function scheduleExpiredCleanup(pool: Pool): void {
    setInterval(function (): void {
        deleteExpiredModels(pool).catch(function (error: unknown): void {
            console.error(messages.expiredCleanupFailed, error);
        });
    }, EXPIRED_CLEANUP_INTERVAL_MS);
}

async function main(): Promise<void> {
    setLang(readLang());
    var config: Config = readConfig();
    var pool: Pool = createPool();
    var app: Express = await createApp(config, {
        users: createPgUserStore(pool),
        clients: createPgClientStore(pool),
        signingKeys: createPgSigningKeyStore(pool),
        oidcAdapter: createPgAdapterFactory(pool),
    });

    // Express 5 passes listen errors (for example, a port in use) to the callback.
    await new Promise<void>(function (resolve: () => void, reject: (error: Error) => void): void {
        app.listen(config.port, function (error?: Error): void {
            if (error != null) {
                reject(error);
                return;
            }
            resolve();
        });
    });
    scheduleExpiredCleanup(pool);
    console.log(formatMessage(messages.listeningOn, config.issuer));
    console.log(formatMessage(messages.oidcConfigurationAt, config.issuer + '/.well-known/openid-configuration'));
}

main().catch(function (error: unknown): void {
    console.error(messages.startupFailed, error);
    process.exit(1);
});
