import Provider, {
    errors,
    type Account,
    type AccountClaims,
    type ClientCredentials,
    type AccessToken,
    type Adapter,
    type AdapterFactory,
    type AdapterPayload,
    type Client,
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
import type { ClientRecord, ClientResource, ClientStore, UserProfile, UserStore } from './stores.ts';

const INTERACTION_TTL_SECONDS: number = 30 * 60;
const ID_TOKEN_TTL_SECONDS: number = 10 * 60;
/** Access tokens for an API take its lifetime from gate_one.resource_servers; this is for any other. */
const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: number = 10 * 60;

/** Every client gets the standard OIDC scopes; the claims each one carries are in `claims` below. */
const OIDC_SCOPES: string = 'openid profile email';

function clientMetadata(client: ClientRecord): AdapterPayload {
    var metadata: AdapterPayload = {
        client_id: client.clientId,
        client_secret: client.clientSecret,
        grant_types: ['authorization_code'],
        response_types: ['code'],
        redirect_uris: [...client.redirectUris],
        post_logout_redirect_uris: [...client.postLogoutRedirectUris],
        token_endpoint_auth_method: 'client_secret_basic',
        // Consistent with the key pair published in the JWKS.
        id_token_signed_response_alg: 'ES256',
    };
    if (client.backchannelLogoutUri != null) {
        metadata.backchannel_logout_uri = client.backchannelLogoutUri;
        // Makes the logout token, the ID token and the access token carry the same sid.
        metadata.backchannel_logout_session_required = true;
    }
    return metadata;
}

/** oidc-provider reads the clients through its adapter; they are only read, never written. */
function createClientAdapter(clientStore: ClientStore): Adapter {
    var readOnly = async function (): Promise<void> {
        throw new Error(messages.clientsAreReadOnly);
    };
    return {
        find: async function (clientId: string): Promise<AdapterPayload | undefined> {
            var client: ClientRecord | undefined = await clientStore.findClient(clientId);
            return client == null ? undefined : clientMetadata(client);
        },
        upsert: readOnly,
        findByUserCode: readOnly,
        findByUid: readOnly,
        consume: readOnly,
        destroy: readOnly,
        revokeByGrantId: async function (): Promise<void> {
            // Clients have no grant records.
        },
    };
}

async function findClientResource(clientStore: ClientStore, client: Client, resource: string): Promise<ClientResource | undefined> {
    var resources: ClientResource[] = await clientStore.findResources(client.clientId);
    return resources.find(function (candidate: ClientResource): boolean {
        return candidate.resource === resource;
    });
}

export function createProvider(config: Config, keySet: JWKS, userStore: UserStore, clientStore: ClientStore, adapter: AdapterFactory): Provider {
    var providerConfiguration: Configuration = {
        jwks: keySet,
        adapter: function (model: string): Adapter {
            return model === 'Client' ? createClientAdapter(clientStore) : adapter(model);
        },
        claims: {
            openid: ['sub'],
            profile: ['name', 'given_name', 'family_name', 'preferred_username'],
            email: ['email', 'email_verified'],
        },
        // Like Entra ID and Google, the ID token carries the claims of the requested scopes.
        conformIdTokenClaims: false,
        // Back-channel notifications go to services on the internal network; see internal-fetch.ts.
        fetch: createFetchWithInternalDestinations(clientStore.isBackchannelLogoutUri),
        cookies: {
            keys: config.cookieKeys,
        },
        /**
         * The session lasts a working day, and its cookie goes away when the browser is closed
         * (see remember: false in interactions.ts), because of shared computers.
         * The grant lives as long as the session. Clients only have the authorization_code
         * grant type, so no refresh tokens are issued.
         */
        ttl: {
            Interaction: INTERACTION_TTL_SECONDS,
            Session: config.sessionTtlSeconds,
            Grant: config.sessionTtlSeconds,
            IdToken: ID_TOKEN_TTL_SECONDS,
            AccessToken: function (_context: KoaContextWithOIDC, token: AccessToken): number {
                return token.resourceServer?.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
            },
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
                /** When the client has a single API, it does not need to send the resource parameter. */
                defaultResource: async function (_context: KoaContextWithOIDC, client: Client): Promise<string | undefined> {
                    var resources: ClientResource[] = await clientStore.findResources(client.clientId);
                    return resources.length === 1 ? resources[0].resource : undefined;
                },
                useGrantedResource: function (): boolean {
                    return true;
                },
                getResourceServerInfo: async function (_context: KoaContextWithOIDC, resourceIndicator: string, client: Client): Promise<ResourceServer> {
                    var clientResource: ClientResource | undefined = await findClientResource(clientStore, client, resourceIndicator);
                    if (clientResource == null) {
                        throw new errors.InvalidTarget(messages.resourceNotRegistered);
                    }
                    return {
                        scope: clientResource.scopes.join(' '),
                        audience: clientResource.resource,
                        accessTokenFormat: 'jwt',
                        accessTokenTTL: clientResource.accessTokenTtl,
                        jwt: { sign: { alg: 'ES256' } },
                    };
                },
            },
        },
        findAccount: async function (_context: KoaContextWithOIDC, accountId: string): Promise<Account | undefined> {
            var profile: UserProfile | undefined = await userStore.findProfile(accountId);
            if (profile == null) {
                return undefined;
            }
            var claims: AccountClaims = {
                sub: accountId,
                name: profile.givenName + ' ' + profile.familyName,
                given_name: profile.givenName,
                family_name: profile.familyName,
                preferred_username: accountId,
            };
            if (profile.email != null) {
                claims.email = profile.email;
                claims.email_verified = profile.emailVerified;
            }
            return {
                accountId: accountId,
                claims: function (): AccountClaims {
                    return claims;
                },
            };
        },
        /**
         * The clients are first-party (same organization), so the grant is given automatically
         * and no consent screen is shown: the standard OIDC scopes plus the API scopes registered
         * for the client (gate_one.client_resources). A grant already in the session is kept as is.
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
            grant.addOIDCScope(OIDC_SCOPES);
            var resources: ClientResource[] = await clientStore.findResources(client.clientId);
            resources.forEach(function (clientResource: ClientResource): void {
                grant.addResourceScope(clientResource.resource, clientResource.scopes.join(' '));
            });
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
