import { resolve } from 'node:path';
import { PARAMETROS_SCRAM_DE_POSTGRES, type ParametrosScram } from './scram.ts';

export interface Configuracion {
    readonly emisor: string;
    readonly puerto: number;
    readonly clavesDeCookies: readonly string[];
    readonly clienteId: string;
    readonly clienteSecreto: string;
    readonly urlDeRetorno: string;
    readonly urlDeLogoutBackchannel: string;
    readonly urlPosteriorAlLogout: string;
    readonly recursoDelServicio: string;
    readonly alcanceDelRecurso: string;
    readonly duracionDelAccessTokenEnSegundos: number;
    readonly archivoDeUsuarios: string;
    readonly archivoDeClaves: string;
    readonly parametrosScram: ParametrosScram;
}

function variableObligatoria(nombre: string): string {
    var valor: string | undefined = process.env[nombre];
    if (valor == null || valor === '') {
        throw new Error('Falta la variable de entorno ' + nombre);
    }
    return valor;
}

function variableOpcional(nombre: string, valorPorOmision: string): string {
    var valor: string | undefined = process.env[nombre];
    if (valor == null || valor === '') {
        return valorPorOmision;
    }
    return valor;
}

function numeroDeVariable(nombre: string, valorPorOmision: number): number {
    var valor: string | undefined = process.env[nombre];
    if (valor == null || valor === '') {
        return valorPorOmision;
    }
    var numero: number = Number(valor);
    if (!Number.isInteger(numero) || numero <= 0) {
        throw new Error('La variable de entorno ' + nombre + ' debe ser un entero positivo');
    }
    return numero;
}

export function rutaDelArchivoDeUsuarios(): string {
    return resolve(process.cwd(), 'datos', 'usuarios.json');
}

export function rutaDelArchivoDeClaves(): string {
    return resolve(process.cwd(), 'datos', 'jwks.json');
}

/** Parámetros de los verificadores nuevos. Por omisión, los de PostgreSQL. */
export function leerParametrosScram(): ParametrosScram {
    return {
        iteraciones: numeroDeVariable('AUTH_SCRAM_ITERACIONES', PARAMETROS_SCRAM_DE_POSTGRES.iteraciones),
        longitudDeLaSal: numeroDeVariable('AUTH_SCRAM_LONGITUD_DE_LA_SAL', PARAMETROS_SCRAM_DE_POSTGRES.longitudDeLaSal),
    };
}

export function leerConfiguracion(): Configuracion {
    var clavesDeCookies: string[] = variableObligatoria('AUTH_CLAVES_DE_COOKIES')
        .split(',')
        .map(function (clave: string): string { return clave.trim(); })
        .filter(function (clave: string): boolean { return clave !== ''; });
    if (clavesDeCookies.length === 0) {
        throw new Error('AUTH_CLAVES_DE_COOKIES no contiene ninguna clave');
    }
    return {
        emisor: variableOpcional('AUTH_EMISOR', 'http://localhost:3993'),
        puerto: numeroDeVariable('AUTH_PUERTO', 3993),
        clavesDeCookies: clavesDeCookies,
        clienteId: variableOpcional('AUTH_CLIENTE_ID', 'one-entrance'),
        clienteSecreto: variableObligatoria('AUTH_CLIENTE_SECRETO'),
        urlDeRetorno: variableOpcional('AUTH_URL_DE_RETORNO', 'http://localhost:3004/callback'),
        urlDeLogoutBackchannel: variableOpcional('AUTH_URL_DE_LOGOUT_BACKCHANNEL', 'http://localhost:3004/backchannel-logout'),
        urlPosteriorAlLogout: variableOpcional('AUTH_URL_POSTERIOR_AL_LOGOUT', 'http://localhost:3004/'),
        recursoDelServicio: variableOpcional('AUTH_RECURSO', 'http://localhost:3004/api'),
        alcanceDelRecurso: variableOpcional('AUTH_ALCANCE', 'perfil:leer'),
        duracionDelAccessTokenEnSegundos: numeroDeVariable('AUTH_DURACION_ACCESS_TOKEN', 600),
        archivoDeUsuarios: rutaDelArchivoDeUsuarios(),
        archivoDeClaves: rutaDelArchivoDeClaves(),
        parametrosScram: leerParametrosScram(),
    };
}
