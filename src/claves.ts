import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { exportJWK, generateKeyPair, type JWK as JwkDeJose } from 'jose';
import type { JWK, JWKS } from 'oidc-provider';

const ALGORITMO: string = 'ES256';

function aJwkDeProveedor(clave: JwkDeJose, identificador: string): JWK {
    if (clave.kty == null || clave.crv == null || clave.x == null || clave.y == null || clave.d == null) {
        throw new Error('La clave generada no tiene los componentes esperados para ' + ALGORITMO);
    }
    return {
        kty: clave.kty,
        crv: clave.crv,
        x: clave.x,
        y: clave.y,
        d: clave.d,
        kid: identificador,
        alg: ALGORITMO,
        use: 'sig',
    };
}

function esJuegoDeClaves(contenido: unknown): contenido is JWKS {
    if (typeof contenido !== 'object' || contenido === null) return false;
    var claves: unknown = Reflect.get(contenido, 'keys');
    return Array.isArray(claves) && claves.length > 0;
}

/**
 * Devuelve el juego de claves de firma. Si el archivo no existe genera un par ES256 y lo guarda.
 * El archivo contiene la clave privada: queda fuera del control de versiones.
 */
export async function obtenerJuegoDeClaves(archivo: string): Promise<JWKS> {
    var texto: string | undefined;
    try {
        texto = await readFile(archivo, 'utf8');
    } catch (error: unknown) {
        if (!(error instanceof Error && Reflect.get(error, 'code') === 'ENOENT')) {
            throw error;
        }
        texto = undefined;
    }
    if (texto != null) {
        var contenido: unknown = JSON.parse(texto);
        if (!esJuegoDeClaves(contenido)) {
            throw new Error('El archivo de claves ' + archivo + ' no tiene el formato esperado');
        }
        return contenido;
    }
    var par = await generateKeyPair(ALGORITMO, { extractable: true });
    var privada: JwkDeJose = await exportJWK(par.privateKey);
    var juego: JWKS = { keys: [aJwkDeProveedor(privada, randomUUID())] };
    await mkdir(dirname(archivo), { recursive: true });
    await writeFile(archivo, JSON.stringify(juego, null, 4), { encoding: 'utf8', mode: 0o600 });
    return juego;
}
