import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { AdapterFactory, Client, JWKS } from 'oidc-provider';
import type { Config } from './config.ts';
import { createInteractionRoutes } from './interactions.ts';
import { getKeySet } from './keys.ts';
import { formatMessage, messages } from './messages.ts';
import { createProvider } from './provider.ts';
import type { ClientStore, SigningKeyStore, UserStore } from './stores.ts';

export interface Stores {
    readonly users: UserStore;
    readonly clients: ClientStore;
    readonly signingKeys: SigningKeyStore;
    readonly oidcAdapter: AdapterFactory;
}

/** Builds the gate-one web application (provider plus login pages) over the given stores. */
export async function createApp(config: Config, stores: Stores): Promise<Express> {
    var keySet: JWKS = await getKeySet(stores.signingKeys);
    var provider: Provider = createProvider(config, keySet, stores.users, stores.clients, stores.oidcAdapter);

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
    app.use(createInteractionRoutes(provider, config, stores.users));
    app.use(provider.callback());
    app.use(function (error: unknown, _request: Request, response: Response, _next: NextFunction): void {
        console.error(messages.unhandledError, error);
        response.status(500);
        response.set('Content-Type', 'text/plain; charset=utf-8');
        response.send(messages.internalError);
    });
    return app;
}
