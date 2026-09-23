import { strict as assert } from 'node:assert';
import { createHash, randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
import { createServer } from 'node:net';
import type { Express } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { Pool } from 'pg';
import { createApp } from '../src/app.ts';
import { createPgAdapterFactory, createPgClientStore, createPgSigningKeyStore, createPgUserStore } from '../src/pg-stores.ts';
import { POSTGRES_SCRAM_PARAMETERS } from '../src/scram.ts';
import { addUser } from '../src/users.ts';
import { prepareDatabase } from './database.ts';

function freePort(): Promise<number> {
    return new Promise<number>(function (resolve: (port: number) => void, reject: (error: Error) => void): void {
        var server = createServer();
        server.on('error', reject);
        server.listen(0, function (): void {
            var address = server.address();
            if (address == null || typeof address === 'string') {
                reject(new Error('no port'));
                return;
            }
            var port: number = address.port;
            server.close(function (): void { resolve(port); });
        });
    });
}

/** A browser reduced to what the flow needs: cookies and manual redirects. */
class Browser {
    private readonly cookies: Map<string, string> = new Map<string, string>();

    async request(url: string, options: RequestInit = {}): Promise<Response> {
        var headers: Headers = new Headers(options.headers);
        headers.set('Cookie', [...this.cookies].map(function ([name, value]: [string, string]): string {
            return name + '=' + value;
        }).join('; '));
        var response: Response = await fetch(url, { ...options, headers: headers, redirect: 'manual' });
        response.headers.getSetCookie().forEach((cookie: string): void => {
            var pair: string = cookie.split(';')[0];
            var separator: number = pair.indexOf('=');
            this.cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
        });
        return response;
    }
}

function location(response: Response, base: string): string {
    var value: string | null = response.headers.get('location');
    assert.ok(value != null, 'expected a redirect, got ' + response.status);
    return new URL(value, base).href;
}

describe('authorization code flow', function (): void {
    var pool: Pool;
    var server: Server;
    var issuer: string;
    const REDIRECT_URI: string = 'http://app.example/callback';
    const API: string = 'http://api.example';

    before(async function (): Promise<void> {
        pool = await prepareDatabase();
        await pool.query(`
            insert into gate_one.clients (client_id, client_secret, redirect_uris, backchannel_logout_uri)
                values ('app', 'app-secret', array['${REDIRECT_URI}'], 'http://app.example/backchannel-logout');
            insert into gate_one.resource_servers (resource, scopes, access_token_ttl)
                values ('${API}', array['profile:read'], 300), ('http://other-api.example', array['x'], 300);
            insert into gate_one.client_resources (client_id, resource, scopes)
                values ('app', '${API}', array['profile:read']);
        `);
        var users = createPgUserStore(pool);
        await addUser(users, 'ana', 'ana password', { givenName: 'Ana', familyName: 'Muñoz', email: 'ana@example.com', emailVerified: false }, POSTGRES_SCRAM_PARAMETERS);
        var port: number = await freePort();
        issuer = 'http://localhost:' + port;
        var app: Express = await createApp({ issuer: issuer, port: port, cookieKeys: ['test-key'], scramParameters: POSTGRES_SCRAM_PARAMETERS }, {
            users: users,
            clients: createPgClientStore(pool),
            signingKeys: createPgSigningKeyStore(pool),
            oidcAdapter: createPgAdapterFactory(pool),
        });
        server = await new Promise<Server>(function (resolve: (server: Server) => void, reject: (error: Error) => void): void {
            var listening: Server = app.listen(port, function (error?: Error): void {
                if (error != null) {
                    reject(error);
                    return;
                }
                resolve(listening);
            });
        });
    });

    after(async function (): Promise<void> {
        server.closeAllConnections();
        await new Promise<void>(function (resolve: () => void): void { server.close(function (): void { resolve(); }); });
        await pool.end();
    });

    function authorizationUrl(verifier: string, extra: Record<string, string> = {}): string {
        var url: URL = new URL(issuer + '/auth');
        url.search = new URLSearchParams({
            client_id: 'app',
            response_type: 'code',
            scope: 'openid profile email profile:read',
            redirect_uri: REDIRECT_URI,
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256',
            state: 'state-1',
            ...extra,
        }).toString();
        return url.href;
    }

    async function signIn(browser: Browser, verifier: string, password: string, extra: Record<string, string> = {}): Promise<Response> {
        var interaction: string = location(await browser.request(authorizationUrl(verifier, extra)), issuer);
        return browser.request(interaction + '/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ username: 'ana', password: password }).toString(),
        });
    }

    it('rejects a wrong password', async function (): Promise<void> {
        var response: Response = await signIn(new Browser(), 'v'.repeat(43), 'wrong');
        assert.equal(response.status, 401);
    });

    it('issues an ID token with the profile claims and an access token for the API', async function (): Promise<void> {
        var browser: Browser = new Browser();
        var verifier: string = randomBytes(32).toString('base64url');
        var resume: string = location(await signIn(browser, verifier, 'ana password'), issuer);
        var callback: URL = new URL(location(await browser.request(resume), issuer));
        assert.equal(callback.origin + callback.pathname, REDIRECT_URI);
        var code: string | null = callback.searchParams.get('code');
        assert.ok(code != null, 'callback without code: ' + callback.href);

        var tokenResponse: Response = await fetch(issuer + '/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + Buffer.from('app:app-secret').toString('base64'),
            },
            body: new URLSearchParams({ grant_type: 'authorization_code', code: code, redirect_uri: REDIRECT_URI, code_verifier: verifier }).toString(),
        });
        var tokens: unknown = await tokenResponse.json();
        assert.equal(tokenResponse.status, 200, JSON.stringify(tokens));
        var idToken: unknown = Reflect.get(Object(tokens), 'id_token');
        var accessToken: unknown = Reflect.get(Object(tokens), 'access_token');
        assert.ok(typeof idToken === 'string' && typeof accessToken === 'string');

        var keys = createRemoteJWKSet(new URL(issuer + '/jwks'));
        var id: JWTPayload = (await jwtVerify(idToken, keys, { issuer: issuer, audience: 'app' })).payload;
        assert.equal(id.sub, 'ana');
        assert.equal(Reflect.get(id, 'name'), 'Ana Muñoz');
        assert.equal(Reflect.get(id, 'given_name'), 'Ana');
        assert.equal(Reflect.get(id, 'family_name'), 'Muñoz');
        assert.equal(Reflect.get(id, 'preferred_username'), 'ana');
        assert.equal(Reflect.get(id, 'email'), 'ana@example.com');
        assert.equal(Reflect.get(id, 'email_verified'), false);

        var access: JWTPayload = (await jwtVerify(accessToken, keys, { issuer: issuer, audience: API, typ: 'at+jwt' })).payload;
        assert.equal(access.sub, 'ana');
        assert.equal(Reflect.get(access, 'scope'), 'profile:read');
        // The client uses back-channel logout, so the ID token and the access token carry the same sid.
        assert.equal(typeof Reflect.get(access, 'sid'), 'string');
        assert.equal(Reflect.get(access, 'sid'), Reflect.get(id, 'sid'));
        assert.equal(Number(access.exp) - Number(access.iat), 300);
    });

    it('refuses an API the client is not allowed to use', async function (): Promise<void> {
        var response: Response = await new Browser().request(authorizationUrl('v'.repeat(43), { resource: 'http://other-api.example' }));
        var redirect: URL = new URL(location(response, issuer));
        assert.equal(redirect.searchParams.get('error'), 'invalid_target');
    });

    it('does not know unregistered clients', async function (): Promise<void> {
        var response: Response = await new Browser().request(authorizationUrl('v'.repeat(43), { client_id: 'unknown' }));
        assert.equal(response.status, 400);
    });
});
