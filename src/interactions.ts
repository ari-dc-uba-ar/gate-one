import { createHash, randomBytes } from 'node:crypto';
import { parseCookie } from 'cookie';
import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import type Provider from 'oidc-provider';
import type { Interaction, InteractionResults } from 'oidc-provider';
import { MFA_ACR, PASSWORD_ACR, requestsMfa } from './acr.ts';
import type { Config } from './config.ts';
import { formatMessage, lang, messages } from './messages.ts';
import { isBlocked, recordFailure, recordSuccess, type Attempt } from './rate-limit.ts';
import type { FailureStore, TrustedDeviceStore, UserStore } from './stores.ts';
import { decryptTotpSecret, verifyTotpCode } from './totp.ts';
import { verifyCredentials } from './users.ts';

export interface InteractionStores {
    readonly users: UserStore;
    readonly trustedDevices: TrustedDeviceStore;
    readonly failures: FailureStore;
}

/** Cookie of a device where the user chose not to enter the second factor for a while. */
const DEVICE_COOKIE: string = 'gate_one_device';
const TRUSTED_DEVICE_DAYS: number = 30;
/** Key, in the interaction result, of the user whose password was verified and who still has to enter the code. */
const PENDING_SECOND_FACTOR: string = 'pendingSecondFactor';

type Handler = (request: Request<{ uid: string }, string, unknown>, response: Response) => Promise<void>;

function withCatch(handler: Handler) {
    return function (request: Request<{ uid: string }, string, unknown>, response: Response, next: NextFunction): void {
        handler(request, response).catch(function (error: unknown): void {
            next(error);
        });
    };
}

export function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function textField(body: unknown, name: string): string | undefined {
    if (typeof body !== 'object' || body === null) {
        return undefined;
    }
    var value: unknown = Reflect.get(body, name);
    return typeof value === 'string' ? value : undefined;
}

function loginPage(uid: string, username: string, message: string | undefined): string {
    var error: string = message == null ? '' : '<p class="error">' + escapeHtml(message) + '</p>';
    return '<!DOCTYPE html>'
        + '<html lang="' + escapeHtml(lang) + '"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
        + '<title>' + escapeHtml(messages.signInTitle) + '</title>'
        + '<style>body{font-family:sans-serif;max-width:22rem;margin:4rem auto}'
        + 'label{display:block;margin:0.75rem 0 0.25rem}input{width:100%;padding:0.4rem}'
        + 'button{margin-top:1rem;padding:0.5rem 1rem}.error{color:#b00}</style>'
        + '</head><body><h1>' + escapeHtml(messages.signInTitle) + '</h1>' + error
        + '<form method="post" action="/interaction/' + escapeHtml(uid) + '/login">'
        + '<label for="username">' + escapeHtml(messages.usernameLabel) + '</label>'
        + '<input id="username" name="username" autocomplete="username" value="' + escapeHtml(username) + '" required>'
        + '<label for="password">' + escapeHtml(messages.passwordLabel) + '</label>'
        + '<input id="password" name="password" type="password" autocomplete="current-password" required>'
        + '<button type="submit">' + escapeHtml(messages.signInButton) + '</button>'
        + '</form></body></html>';
}

function secondFactorPage(uid: string, message: string | undefined): string {
    var error: string = message == null ? '' : '<p class="error">' + escapeHtml(message) + '</p>';
    return '<!DOCTYPE html>'
        + '<html lang="' + escapeHtml(lang) + '"><head><meta charset="utf-8">'
        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
        + '<title>' + escapeHtml(messages.secondFactorTitle) + '</title>'
        + '<style>body{font-family:sans-serif;max-width:22rem;margin:4rem auto}'
        + 'label{display:block;margin:0.75rem 0 0.25rem}input{width:100%;padding:0.4rem}'
        + 'label.check{display:flex;gap:0.5rem;align-items:center}label.check input{width:auto}'
        + 'button{margin-top:1rem;padding:0.5rem 1rem}.error{color:#b00}</style>'
        + '</head><body><h1>' + escapeHtml(messages.secondFactorTitle) + '</h1>' + error
        + '<form method="post" action="/interaction/' + escapeHtml(uid) + '/totp">'
        + '<label for="code">' + escapeHtml(messages.codeLabel) + '</label>'
        + '<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" required autofocus>'
        + '<label class="check"><input type="checkbox" name="remember" value="yes">' + escapeHtml(messages.rememberDeviceLabel) + '</label>'
        + '<button type="submit">' + escapeHtml(messages.verifyButton) + '</button>'
        + '</form></body></html>';
}

/** The service asks for a recent sign-in: max_age, or prompt=login (oidc-provider turns max_age=0 into it). */
function requestsRecentSignIn(params: { [key: string]: unknown }): boolean {
    return params.max_age !== undefined
        || (typeof params.prompt === 'string' && params.prompt.split(' ').includes('login'));
}

function hashDeviceToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

function sendHtml(response: Response, status: number, html: string): void {
    response.status(status);
    response.set('Content-Type', 'text/html; charset=utf-8');
    response.set('Cache-Control', 'no-store');
    response.send(html);
}

export function createInteractionRoutes(provider: Provider, config: Config, stores: InteractionStores): Router {
    var routes: Router = express.Router();
    var formBody = express.urlencoded({ extended: false });

    var attemptOf = function (request: Request<{ uid: string }, string, unknown>, username: string): Attempt {
        return { username: username, ip: request.ip ?? '' };
    };

    var finishLogin = async function (request: Request<{ uid: string }, string, unknown>, response: Response, username: string, acr: string, amr: string[]): Promise<void> {
        // remember: false makes the session cookie transient: it goes away when the browser is closed.
        var result: InteractionResults = { login: { accountId: username, acr: acr, amr: amr, remember: false } };
        await provider.interactionFinished(request, response, result, { mergeWithLastSubmission: false });
    };

    var isTrustedDevice = async function (request: Request<{ uid: string }, string, unknown>, username: string): Promise<boolean> {
        var token: string | undefined = parseCookie(request.headers.cookie ?? '')[DEVICE_COOKIE];
        return token != null && token !== '' && await stores.trustedDevices.isTrusted(hashDeviceToken(token), username);
    };

    var trustDevice = async function (response: Response, username: string): Promise<void> {
        var token: string = randomBytes(32).toString('base64url');
        await stores.trustedDevices.add(hashDeviceToken(token), username, TRUSTED_DEVICE_DAYS);
        response.cookie(DEVICE_COOKIE, token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: config.issuer.startsWith('https:'),
            path: '/',
            maxAge: TRUSTED_DEVICE_DAYS * 24 * 60 * 60 * 1000,
        });
    };

    routes.get('/interaction/:uid', withCatch(async function (request, response): Promise<void> {
        var interaction: Interaction = await provider.interactionDetails(request, response);
        if (interaction.prompt.name !== 'login') {
            sendHtml(response, 400, '<p>' + escapeHtml(formatMessage(messages.unsupportedInteraction, interaction.prompt.name)) + '</p>');
            return;
        }
        sendHtml(response, 200, loginPage(interaction.uid, '', undefined));
    }));

    routes.post('/interaction/:uid/login', formBody, withCatch(async function (request, response): Promise<void> {
        var interaction: Interaction = await provider.interactionDetails(request, response);
        var username: string | undefined = textField(request.body, 'username');
        var password: string | undefined = textField(request.body, 'password');
        if (username == null || password == null) {
            sendHtml(response, 400, loginPage(interaction.uid, '', messages.missingFields));
            return;
        }
        var attempt: Attempt = attemptOf(request, username);
        if (await isBlocked(stores.failures, attempt)) {
            sendHtml(response, 429, loginPage(interaction.uid, username, messages.tooManyAttempts));
            return;
        }
        var valid: boolean = await verifyCredentials(stores.users, username, password, config.scramParameters);
        if (!valid) {
            await recordFailure(stores.failures, attempt);
            sendHtml(response, 401, loginPage(interaction.uid, username, messages.invalidCredentials));
            return;
        }
        if (await stores.users.findTotpSecret(username) == null) {
            await recordSuccess(stores.failures, attempt);
            if (requestsMfa(interaction.params.acr_values)) {
                var denied: InteractionResults = { error: 'access_denied', error_description: messages.mfaRequiredNotEnabled };
                await provider.interactionFinished(request, response, denied, { mergeWithLastSubmission: false });
                return;
            }
            await finishLogin(request, response, username, PASSWORD_ACR, ['pwd']);
            return;
        }
        // A remembered device skips the code, unless the service asks for a recent sign-in.
        if (!requestsRecentSignIn(interaction.params) && await isTrustedDevice(request, username)) {
            await recordSuccess(stores.failures, attempt);
            await finishLogin(request, response, username, MFA_ACR, ['pwd', 'mfa']);
            return;
        }
        interaction.result = { [PENDING_SECOND_FACTOR]: username };
        await interaction.persist();
        sendHtml(response, 200, secondFactorPage(interaction.uid, undefined));
    }));

    routes.post('/interaction/:uid/totp', formBody, withCatch(async function (request, response): Promise<void> {
        var interaction: Interaction = await provider.interactionDetails(request, response);
        var pending: unknown = interaction.result?.[PENDING_SECOND_FACTOR];
        if (typeof pending !== 'string') {
            sendHtml(response, 400, loginPage(interaction.uid, '', messages.signInAgain));
            return;
        }
        var username: string = pending;
        var attempt: Attempt = attemptOf(request, username);
        if (await isBlocked(stores.failures, attempt)) {
            sendHtml(response, 429, secondFactorPage(interaction.uid, messages.tooManyAttempts));
            return;
        }
        var encryptedSecret: string | undefined = await stores.users.findTotpSecret(username);
        if (encryptedSecret == null) {
            // The second factor was reset while the user was signing in.
            sendHtml(response, 400, loginPage(interaction.uid, '', messages.signInAgain));
            return;
        }
        var secret: string = decryptTotpSecret(config.totpKey, username, encryptedSecret);
        var step: number | undefined = verifyTotpCode(username, secret, textField(request.body, 'code') ?? '');
        if (step == null || !await stores.users.useTotpStep(username, step)) {
            await recordFailure(stores.failures, attempt);
            sendHtml(response, 401, secondFactorPage(interaction.uid, messages.invalidCode));
            return;
        }
        await recordSuccess(stores.failures, attempt);
        if (textField(request.body, 'remember') === 'yes') {
            await trustDevice(response, username);
        }
        await finishLogin(request, response, username, MFA_ACR, ['pwd', 'otp', 'mfa']);
    }));

    return routes;
}
