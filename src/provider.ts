import Provider, {
    errors,
    type Account,
    type AccountClaims,
    type ClientCredentials,
    type AccessToken,
    type Configuration,
    type Interaction,
    type JWKS,
    type KoaContextWithOIDC,
    type ResourceServer,
    type UnknownObject,
} from 'oidc-provider';
import type { Config } from './config.ts';
import { escapeHtml } from './interactions.ts';
import { createFetchWithInternalDestinations } from './internal-fetch.ts';
import { lang, messages } from './messages.ts';
import { readUsers, type StoredUser } from './users.ts';

const OPENID_SCOPE: string = 'openid';

export function createProvider(config: Config, keySet: JWKS): Provider {
    var providerConfiguration: Configuration = {
        clients: [{
            client_id: config.clientId,
            client_secret: config.clientSecret,
            grant_types: ['authorization_code'],
            response_types: ['code'],
            redirect_uris: [config.redirectUri],
            token_endpoint_auth_method: 'client_secret_basic',
            // Consistent with the single key pair published in the JWKS.
            id_token_signed_response_alg: 'ES256',
            backchannel_logout_uri: config.backchannelLogoutUri,
            // Makes the logout token, the ID token and the access token carry the same sid.
            backchannel_logout_session_required: true,
            post_logout_redirect_uris: [config.postLogoutRedirectUri],
        }],
        jwks: keySet,
        // Back-channel notifications go to services on the internal network; see internal-fetch.ts.
        fetch: createFetchWithInternalDestinations([config.backchannelLogoutUri]),
        cookies: {
            keys: config.cookieKeys,
        },
        pkce: {
            required: function (): boolean { return true; },
        },
        interactions: {
            url: function (_context: KoaContextWithOIDC, interaction: Interaction): string {
                return '/interaction/' + interaction.uid;
            },
        },
        features: {
            devInteractions: { enabled: false },
            backchannelLogout: { enabled: true },
            rpInitiatedLogout: {
                enabled: true,
                logoutSource: function (context: KoaContextWithOIDC, form: string): void {
                    context.type = 'html';
                    context.body = '<!DOCTYPE html>'
                        + '<html lang="' + escapeHtml(lang) + '"><head><meta charset="utf-8">'
                        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
                        + '<title>' + escapeHtml(messages.logoutTitle) + '</title>'
                        + '<style>body{font-family:sans-serif;max-width:22rem;margin:4rem auto}'
                        + 'button{margin:0.5rem 0.5rem 0 0;padding:0.5rem 1rem}</style>'
                        + '</head><body><h1>' + escapeHtml(messages.logoutQuestion) + '</h1>'
                        + '<p>' + escapeHtml(messages.logoutExplanation) + '</p>'
                        + form
                        + '<button autofocus type="submit" form="op.logoutForm" name="logout" value="yes">' + escapeHtml(messages.logoutButton) + '</button>'
                        + '<button type="submit" form="op.logoutForm">' + escapeHtml(messages.cancelButton) + '</button>'
                        + '</body></html>';
                },
            },
            resourceIndicators: {
                enabled: true,
                defaultResource: function (): string {
                    return config.serviceResource;
                },
                useGrantedResource: function (): boolean {
                    return true;
                },
                getResourceServerInfo: function (_context: KoaContextWithOIDC, resourceIndicator: string): ResourceServer {
                    if (resourceIndicator !== config.serviceResource) {
                        throw new errors.InvalidTarget(messages.resourceNotRegistered);
                    }
                    return {
                        scope: config.resourceScope,
                        audience: config.serviceResource,
                        accessTokenFormat: 'jwt',
                        accessTokenTTL: config.accessTokenTtlSeconds,
                        jwt: { sign: { alg: 'ES256' } },
                    };
                },
            },
        },
        findAccount: async function (_context: KoaContextWithOIDC, accountId: string): Promise<Account | undefined> {
            var users: readonly StoredUser[] = await readUsers(config.usersFile);
            var exists: boolean = users.some(function (user: StoredUser): boolean {
                return user.username === accountId;
            });
            if (!exists) {
                return undefined;
            }
            return {
                accountId: accountId,
                claims: function (): AccountClaims {
                    return { sub: accountId };
                },
            };
        },
        /**
         * The client is first-party (same organization), so the grant is given
         * automatically and no consent screen is shown.
         */
        loadExistingGrant: async function (context: KoaContextWithOIDC) {
            var client = context.oidc.client;
            var session = context.oidc.session;
            if (client == null || session == null || session.accountId == null) {
                return undefined;
            }
            var existingGrantId: string | undefined = session.grantIdFor(client.clientId);
            if (existingGrantId != null) {
                return context.oidc.provider.Grant.find(existingGrantId);
            }
            var grant = new context.oidc.provider.Grant({
                clientId: client.clientId,
                accountId: session.accountId,
            });
            grant.addOIDCScope(OPENID_SCOPE);
            grant.addResourceScope(config.serviceResource, config.resourceScope);
            await grant.save();
            return grant;
        },
        /**
         * The sid is the same one gate-one sends in the back-channel logout token:
         * that way each service can reject the access tokens of a closed session.
         */
        extraTokenClaims: function (_context: KoaContextWithOIDC, token: AccessToken | ClientCredentials): UnknownObject {
            if (token.kind === 'AccessToken' && token.sid != null) {
                return { sid: token.sid };
            }
            return {};
        },
    };
    return new Provider(config.issuer, providerConfiguration);
}
