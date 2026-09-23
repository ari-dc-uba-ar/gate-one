import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { Client, JWKS } from 'oidc-provider';
import type { Pool } from 'pg';
import { getKeySet } from './keys.ts';
import { readConfig, readLang, type Config } from './config.ts';
import { createInteractionRoutes } from './interactions.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createPgAdapterFactory, createPgSigningKeyStore, createPgUserStore, createPool, deleteExpiredModels } from './pg-stores.ts';
import { createProvider } from './provider.ts';
import type { UserStore } from './stores.ts';

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
    var userStore: UserStore = createPgUserStore(pool);
    var keySet: JWKS = await getKeySet(createPgSigningKeyStore(pool));
    var provider: Provider = createProvider(config, keySet, userStore, createPgAdapterFactory(pool));

    provider.on('server_error', function (_context: unknown, error: Error): void {
        console.error(messages.providerInternalError, error);
    });
    provider.on('backchannel.success', function (_context: unknown, client: Client, accountId: string, sid: string): void {
        console.log(formatMessage(messages.backchannelLogoutSent, client.clientId, accountId, sid));
    });
    provider.on('backchannel.error', function (_context: unknown, error: Error, client: Client, accountId: string, sid: string): void {
        console.error(formatMessage(messages.backchannelLogoutFailed, client.clientId, accountId, sid), error);
    });

    var app: Express = express();
    app.use(createInteractionRoutes(provider, config, userStore));
    app.use(provider.callback());
    app.use(function (error: unknown, _request: Request, response: Response, _next: NextFunction): void {
        console.error(messages.unhandledError, error);
        response.status(500);
        response.set('Content-Type', 'text/plain; charset=utf-8');
        response.send(messages.internalError);
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
