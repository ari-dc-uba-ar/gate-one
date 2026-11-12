import { strict as assert } from 'node:assert';
import { createHash, randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
import { createServer } from 'node:net';
import type { Express } from 'express';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { Pool } from 'pg';
import { createApp } from '../src/app.ts';
import { createPgAdapterFactory, createPgClientStore, createPgFailureStore, createPgSigningKeyStore, createPgTrustedDeviceStore, createPgUserStore } from '../src/pg-stores.ts';
import { POSTGRES_SCRAM_PARAMETERS } from '../src/scram.ts';
import { encryptTotpSecret, generateTotpSecret, totpCodeAt } from '../src/totp.ts';
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
    readonly setCookieHeaders: string[] = [];

    copyCookie(from: Browser, name: string): void {
        var value: string | undefined = from.cookies.get(name);
        assert.ok(value != null, 'no cookie ' + name);
        this.cookies.set(name, value);
    }

    async request(url: string, options: RequestInit = {}): Promise<Response> {
        var headers: Headers = new Headers(options.headers);
        headers.set('Cookie', [...this.cookies].map(function ([name, value]: [string, string]): string {
            return name + '=' + value;
        }).join('; '));
        var response: Response = await fetch(url, { ...options, headers: headers, redirect: 'manual' });
        this.setCookieHeaders.push(...response.headers.getSetCookie());
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
    const TOTP_KEY: Buffer = randomBytes(32);
    /** Users with a second factor, and their secrets. */
    const TOTP_SECRETS: Map<string, string> = new Map<string, string>([['bea', generateTotpSecret()], ['carla', generateTotpSecret()]]);

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
        for (var name of ['bea', 'carla', 'dora']) {
            await addUser(users, name, name + ' password', { givenName: name, familyName: 'Test', email: null, emailVerified: false }, POSTGRES_SCRAM_PARAMETERS);
        }
        for (var [username, secret] of TOTP_SECRETS) {
            await users.setTotpSecret(username, encryptTotpSecret(TOTP_KEY, username, secret));
        }
        var port: number = await freePort();
        issuer = 'http://localhost:' + port;
        var app: Express = await createApp({ issuer: issuer, port: port, cookieKeys: ['test-key'], sessionTtlSeconds: 8 * 60 * 60, scramParameters: POSTGRES_SCRAM_PARAMETERS, totpKey: TOTP_KEY }, {
            users: users,
            trustedDevices: createPgTrustedDeviceStore(pool),
            failures: createPgFailureStore(pool),
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

    async function signIn(browser: Browser, verifier: string, password: string, extra: Record<string, string> = {}, username: string = 'ana'): Promise<Response> {
        var interaction: string = location(await browser.request(authorizationUrl(verifier, extra)), issuer);
        return browser.request(interaction + '/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ username: username, password: password }).toString(),
        });
    }

    function postForm(browser: Browser, url: string, fields: Record<string, string>): Promise<Response> {
        return browser.request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(fields).toString(),
        });
    }

    /** The action of the form of a page. */
    async function formAction(response: Response): Promise<string> {
        var html: string = await response.text();
        var match: RegExpExecArray | null = /<form method="post" action="([^"]+)"/.exec(html);
        assert.ok(match != null, 'page without a form: ' + html);
        return new URL(match[1], issuer).href;
    }

    /** The code of a user with a second factor, `steps` steps of 30 seconds away from now. */
    function codeOf(username: string, steps: number): string {
        var secret: string | undefined = TOTP_SECRETS.get(username);
        assert.ok(secret != null);
        return totpCodeAt(username, secret, Date.now() + steps * 30000);
    }

    /** Follows the redirect back to the client and exchanges the code; returns the verified ID token. */
    async function finishAtClient(browser: Browser, response: Response, verifier: string): Promise<JWTPayload> {
        var callback: URL = new URL(location(await browser.request(location(response, issuer)), issuer));
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
        assert.ok(typeof idToken === 'string');
        return (await jwtVerify(idToken, createRemoteJWKSet(new URL(issuer + '/jwks')), { issuer: issuer, audience: 'app' })).payload;
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
        assert.equal(Number(id.exp) - Number(id.iat), 600);
    });

    it('keeps the session 8 hours, with a cookie that ends with the browser', async function (): Promise<void> {
        var browser: Browser = new Browser();
        var resume: string = location(await signIn(browser, 'v'.repeat(43), 'ana password'), issuer);
        await browser.request(resume);
        var sessionCookie: string | undefined = browser.setCookieHeaders.find(function (header: string): boolean {
            return header.startsWith('_session=');
        });
        assert.ok(sessionCookie != null);
        assert.doesNotMatch(sessionCookie, /expires=|max-age=/i);
        var result = await pool.query<{ seconds: number }>(
            "select extract(epoch from expires_at - current_timestamp)::integer as seconds from gate_one.oidc_models where model = 'Session'"
        );
        assert.ok(result.rows.length > 0);
        result.rows.forEach(function (row: { seconds: number }): void {
            assert.ok(row.seconds > 8 * 60 * 60 - 60 && row.seconds <= 8 * 60 * 60, 'session expires in ' + row.seconds + ' seconds');
        });
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

    describe('second factor', function (): void {

        it('a user without second factor signs in with the password (acr pwd)', async function (): Promise<void> {
            var browser: Browser = new Browser();
            var verifier: string = randomBytes(32).toString('base64url');
            var id: JWTPayload = await finishAtClient(browser, await signIn(browser, verifier, 'ana password'), verifier);
            assert.equal(Reflect.get(id, 'acr'), 'pwd');
            assert.deepEqual(Reflect.get(id, 'amr'), ['pwd']);
        });

        it('asks the code after the password, rejects a wrong one and a reused one', async function (): Promise<void> {
            var browser: Browser = new Browser();
            var verifier: string = randomBytes(32).toString('base64url');
            var passwordResponse: Response = await signIn(browser, verifier, 'bea password', {}, 'bea');
            assert.equal(passwordResponse.status, 200);
            var action: string = await formAction(passwordResponse);
            assert.match(action, /\/totp$/);
            var wrong: Response = await postForm(browser, action, { code: '000000' === codeOf('bea', 0) ? '111111' : '000000' });
            assert.equal(wrong.status, 401);
            await wrong.text();
            var previousCode: string = codeOf('bea', -1);
            var id: JWTPayload = await finishAtClient(browser, await postForm(browser, action, { code: previousCode }), verifier);
            assert.equal(id.sub, 'bea');
            assert.equal(Reflect.get(id, 'acr'), 'mfa');
            assert.deepEqual(Reflect.get(id, 'amr'), ['pwd', 'otp', 'mfa']);

            var other: Browser = new Browser();
            var reused: Response = await postForm(other, await formAction(await signIn(other, verifier, 'bea password', {}, 'bea')), { code: previousCode });
            assert.equal(reused.status, 401);
        });

        it('remembers the device when asked, except when the service asks for a recent sign-in', async function (): Promise<void> {
            var browser: Browser = new Browser();
            var verifier: string = randomBytes(32).toString('base64url');
            var action: string = await formAction(await signIn(browser, verifier, 'carla password', {}, 'carla'));
            var verified: Response = await postForm(browser, action, { code: codeOf('carla', -1), remember: 'yes' });
            var deviceCookie: string | undefined = browser.setCookieHeaders.find(function (header: string): boolean {
                return header.startsWith('gate_one_device=');
            });
            assert.ok(deviceCookie != null);
            assert.match(deviceCookie, /HttpOnly/i);
            assert.match(deviceCookie, /Max-Age=2592000/i);
            await finishAtClient(browser, verified, verifier);

            // A new session (the session cookie is gone) on the same device: only the password.
            var sameDevice: Browser = new Browser();
            sameDevice.copyCookie(browser, 'gate_one_device');
            var id: JWTPayload = await finishAtClient(sameDevice, await signIn(sameDevice, verifier, 'carla password', {}, 'carla'), verifier);
            assert.equal(Reflect.get(id, 'acr'), 'mfa');
            assert.deepEqual(Reflect.get(id, 'amr'), ['pwd', 'mfa']);

            // A recent sign-in requested (max_age, or prompt=login): the code is asked again.
            var recentSignIns: Record<string, string>[] = [{ max_age: '0' }, { max_age: '60' }, { prompt: 'login' }];
            for (var extra of recentSignIns) {
                var recent: Browser = new Browser();
                recent.copyCookie(browser, 'gate_one_device');
                var response: Response = await signIn(recent, verifier, 'carla password', extra, 'carla');
                assert.equal(response.status, 200, JSON.stringify(extra));
                assert.match(await formAction(response), /\/totp$/);
            }
        });

        it('rejects a service that requires a second factor for a user without one', async function (): Promise<void> {
            var browser: Browser = new Browser();
            var response: Response = await signIn(browser, 'v'.repeat(43), 'ana password', { acr_values: 'mfa' });
            var redirect: URL = new URL(location(await browser.request(location(response, issuer)), issuer));
            assert.equal(redirect.searchParams.get('error'), 'access_denied');
        });

        it('asks for the sign-in again when a service requires a second factor the session does not have', async function (): Promise<void> {
            var browser: Browser = new Browser();
            var verifier: string = randomBytes(32).toString('base64url');
            await finishAtClient(browser, await signIn(browser, verifier, 'ana password'), verifier);
            var withoutMfa: Response = await browser.request(authorizationUrl(verifier));
            assert.equal(new URL(location(withoutMfa, issuer)).origin + new URL(location(withoutMfa, issuer)).pathname, REDIRECT_URI);
            var withMfa: Response = await browser.request(authorizationUrl(verifier, { acr_values: 'mfa' }));
            assert.match(location(withMfa, issuer), /\/interaction\//);
        });

        it('locks the user after 5 failures, even with the right password', async function (): Promise<void> {
            for (var i: number = 0; i < 5; i++) {
                var failed: Response = await signIn(new Browser(), 'v'.repeat(43), 'wrong', {}, 'dora');
                assert.equal(failed.status, 401);
                await failed.text();
            }
            var locked: Response = await signIn(new Browser(), 'v'.repeat(43), 'dora password', {}, 'dora');
            assert.equal(locked.status, 429);
        });
    });
});
