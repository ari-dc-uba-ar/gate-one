import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type Provider from 'oidc-provider';
import type { Client, JWKS } from 'oidc-provider';
import { getKeySet } from './keys.ts';
import { readConfig, readLang, type Config } from './config.ts';
import { createInteractionRoutes } from './interactions.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createProvider } from './provider.ts';

async function main(): Promise<void> {
    setLang(readLang());
    var config: Config = readConfig();
    var keySet: JWKS = await getKeySet(config.keysFile);
    var provider: Provider = createProvider(config, keySet);

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
    app.use(createInteractionRoutes(provider, config));
    app.use(provider.callback());
    app.use(function (error: unknown, _request: Request, response: Response, _next: NextFunction): void {
        console.error(messages.unhandledError, error);
        response.status(500);
        response.set('Content-Type', 'text/plain; charset=utf-8');
        response.send(messages.internalError);
    });

    app.listen(config.port, function (): void {
        console.log(formatMessage(messages.listeningOn, config.issuer));
        console.log(formatMessage(messages.oidcConfigurationAt, config.issuer + '/.well-known/openid-configuration'));
    });
}

main().catch(function (error: unknown): void {
    console.error(messages.startupFailed, error);
    process.exit(1);
});
