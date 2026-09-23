import { formatMessage, messages } from './messages.ts';
import { POSTGRES_SCRAM_PARAMETERS, type ScramParameters } from './scram.ts';

export interface Config {
    readonly issuer: string;
    readonly port: number;
    readonly cookieKeys: readonly string[];
    readonly clientId: string;
    readonly clientSecret: string;
    readonly redirectUri: string;
    readonly backchannelLogoutUri: string;
    readonly postLogoutRedirectUri: string;
    readonly serviceResource: string;
    readonly resourceScope: string;
    readonly accessTokenTtlSeconds: number;
    readonly scramParameters: ScramParameters;
}

function requiredVariable(name: string): string {
    var value: string | undefined = process.env[name];
    if (value == null || value === '') {
        throw new Error(formatMessage(messages.missingEnvVar, name));
    }
    return value;
}

function optionalVariable(name: string, defaultValue: string): string {
    var value: string | undefined = process.env[name];
    if (value == null || value === '') {
        return defaultValue;
    }
    return value;
}

function numericVariable(name: string, defaultValue: number): number {
    var value: string | undefined = process.env[name];
    if (value == null || value === '') {
        return defaultValue;
    }
    var number: number = Number(value);
    if (!Number.isInteger(number) || number <= 0) {
        throw new Error(formatMessage(messages.envVarMustBePositiveInteger, name));
    }
    return number;
}

/** Language of the messages (see messages.ts). */
export function readLang(): string {
    return optionalVariable('AUTH_LANG', 'en');
}

/** Parameters for new verifiers. PostgreSQL's by default. */
export function readScramParameters(): ScramParameters {
    return {
        iterations: numericVariable('AUTH_SCRAM_ITERATIONS', POSTGRES_SCRAM_PARAMETERS.iterations),
        saltLength: numericVariable('AUTH_SCRAM_SALT_LENGTH', POSTGRES_SCRAM_PARAMETERS.saltLength),
    };
}

export function readConfig(): Config {
    var cookieKeys: string[] = requiredVariable('AUTH_COOKIE_KEYS')
        .split(',')
        .map(function (key: string): string { return key.trim(); })
        .filter(function (key: string): boolean { return key !== ''; });
    if (cookieKeys.length === 0) {
        throw new Error(messages.cookieKeysEmpty);
    }
    return {
        issuer: optionalVariable('AUTH_ISSUER', 'http://localhost:3993'),
        port: numericVariable('AUTH_PORT', 3993),
        cookieKeys: cookieKeys,
        clientId: optionalVariable('AUTH_CLIENT_ID', 'one-entrance'),
        clientSecret: requiredVariable('AUTH_CLIENT_SECRET'),
        redirectUri: optionalVariable('AUTH_REDIRECT_URI', 'http://localhost:3004/callback'),
        backchannelLogoutUri: optionalVariable('AUTH_BACKCHANNEL_LOGOUT_URI', 'http://localhost:3004/backchannel-logout'),
        postLogoutRedirectUri: optionalVariable('AUTH_POST_LOGOUT_REDIRECT_URI', 'http://localhost:3004/'),
        serviceResource: optionalVariable('AUTH_RESOURCE', 'http://localhost:3004/api'),
        resourceScope: optionalVariable('AUTH_SCOPE', 'perfil:leer'),
        accessTokenTtlSeconds: numericVariable('AUTH_ACCESS_TOKEN_TTL', 600),
        scramParameters: readScramParameters(),
    };
}
