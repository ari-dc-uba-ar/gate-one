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
import type { Configuracion } from './configuracion.ts';
import { crearFetchConDestinosInternos } from './fetch-interno.ts';
import { leerUsuarios, type UsuarioAlmacenado } from './usuarios.ts';

const ALCANCE_OPENID: string = 'openid';

export function crearProveedor(configuracion: Configuracion, juegoDeClaves: JWKS): Provider {
    var configuracionDelProveedor: Configuration = {
        clients: [{
            client_id: configuracion.clienteId,
            client_secret: configuracion.clienteSecreto,
            grant_types: ['authorization_code'],
            response_types: ['code'],
            redirect_uris: [configuracion.urlDeRetorno],
            token_endpoint_auth_method: 'client_secret_basic',
            // Coherente con el único par de claves publicado en el JWKS.
            id_token_signed_response_alg: 'ES256',
            backchannel_logout_uri: configuracion.urlDeLogoutBackchannel,
            // Hace que el logout token, el ID token y el access token lleven el mismo sid.
            backchannel_logout_session_required: true,
            post_logout_redirect_uris: [configuracion.urlPosteriorAlLogout],
        }],
        jwks: juegoDeClaves,
        // Los avisos de back-channel van a servicios de la red interna; ver fetch-interno.ts.
        fetch: crearFetchConDestinosInternos([configuracion.urlDeLogoutBackchannel]),
        cookies: {
            keys: configuracion.clavesDeCookies,
        },
        pkce: {
            required: function (): boolean { return true; },
        },
        interactions: {
            url: function (_contexto: KoaContextWithOIDC, interaccion: Interaction): string {
                return '/interaccion/' + interaccion.uid;
            },
        },
        features: {
            devInteractions: { enabled: false },
            backchannelLogout: { enabled: true },
            rpInitiatedLogout: {
                enabled: true,
                logoutSource: function (contexto: KoaContextWithOIDC, formulario: string): void {
                    contexto.type = 'html';
                    contexto.body = '<!DOCTYPE html>'
                        + '<html lang="es"><head><meta charset="utf-8">'
                        + '<meta name="viewport" content="width=device-width, initial-scale=1">'
                        + '<title>Cerrar sesión</title>'
                        + '<style>body{font-family:sans-serif;max-width:22rem;margin:4rem auto}'
                        + 'button{margin:0.5rem 0.5rem 0 0;padding:0.5rem 1rem}</style>'
                        + '</head><body><h1>¿Cerrar la sesión?</h1>'
                        + '<p>Se cerrará en todos los servicios que la usan.</p>'
                        + formulario
                        + '<button autofocus type="submit" form="op.logoutForm" name="logout" value="yes">Cerrar sesión</button>'
                        + '<button type="submit" form="op.logoutForm">Cancelar</button>'
                        + '</body></html>';
                },
            },
            resourceIndicators: {
                enabled: true,
                defaultResource: function (): string {
                    return configuracion.recursoDelServicio;
                },
                useGrantedResource: function (): boolean {
                    return true;
                },
                getResourceServerInfo: function (_contexto: KoaContextWithOIDC, identificador: string): ResourceServer {
                    if (identificador !== configuracion.recursoDelServicio) {
                        throw new errors.InvalidTarget('el recurso solicitado no está registrado');
                    }
                    return {
                        scope: configuracion.alcanceDelRecurso,
                        audience: configuracion.recursoDelServicio,
                        accessTokenFormat: 'jwt',
                        accessTokenTTL: configuracion.duracionDelAccessTokenEnSegundos,
                        jwt: { sign: { alg: 'ES256' } },
                    };
                },
            },
        },
        findAccount: async function (_contexto: KoaContextWithOIDC, identificador: string): Promise<Account | undefined> {
            var usuarios: readonly UsuarioAlmacenado[] = await leerUsuarios(configuracion.archivoDeUsuarios);
            var existe: boolean = usuarios.some(function (usuario: UsuarioAlmacenado): boolean {
                return usuario.usuario === identificador;
            });
            if (!existe) {
                return undefined;
            }
            return {
                accountId: identificador,
                claims: function (): AccountClaims {
                    return { sub: identificador };
                },
            };
        },
        /**
         * El cliente es propio (de la misma organización), así que el permiso se otorga
         * automáticamente y no se muestra pantalla de consentimiento.
         */
        loadExistingGrant: async function (contexto: KoaContextWithOIDC) {
            var cliente = contexto.oidc.client;
            var sesion = contexto.oidc.session;
            if (cliente == null || sesion == null || sesion.accountId == null) {
                return undefined;
            }
            var identificadorExistente: string | undefined = sesion.grantIdFor(cliente.clientId);
            if (identificadorExistente != null) {
                return contexto.oidc.provider.Grant.find(identificadorExistente);
            }
            var permiso = new contexto.oidc.provider.Grant({
                clientId: cliente.clientId,
                accountId: sesion.accountId,
            });
            permiso.addOIDCScope(ALCANCE_OPENID);
            permiso.addResourceScope(configuracion.recursoDelServicio, configuracion.alcanceDelRecurso);
            await permiso.save();
            return permiso;
        },
        /**
         * El sid es el mismo que el gate-one envía en el logout token del back-channel:
         * así cada servicio puede rechazar los access tokens de una sesión cerrada.
         */
        extraTokenClaims: function (_contexto: KoaContextWithOIDC, token: AccessToken | ClientCredentials): UnknownObject {
            if (token.kind === 'AccessToken' && token.sid != null) {
                return { sid: token.sid };
            }
            return {};
        },
    };
    return new Provider(configuracion.emisor, configuracionDelProveedor);
}
