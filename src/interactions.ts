import express, { type NextFunction, type Request, type Response, type Router } from 'express';
import type Provider from 'oidc-provider';
import type { Interaction, InteractionResults } from 'oidc-provider';
import type { Config } from './config.ts';
import { formatMessage, lang, messages } from './messages.ts';
import { verifyCredentials } from './users.ts';

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

function sendHtml(response: Response, status: number, html: string): void {
    response.status(status);
    response.set('Content-Type', 'text/html; charset=utf-8');
    response.set('Cache-Control', 'no-store');
    response.send(html);
}

export function createInteractionRoutes(provider: Provider, config: Config): Router {
    var routes: Router = express.Router();
    var formBody = express.urlencoded({ extended: false });

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
        var valid: boolean = await verifyCredentials(config.usersFile, username, password, config.scramParameters);
        if (!valid) {
            sendHtml(response, 401, loginPage(interaction.uid, username, messages.invalidCredentials));
            return;
        }
        var result: InteractionResults = { login: { accountId: username } };
        await provider.interactionFinished(request, response, result, { mergeWithLastSubmission: false });
    }));

    return routes;
}
