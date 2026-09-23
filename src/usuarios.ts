import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const LONGITUD_DEL_HASH: number = 64;
const LONGITUD_DE_LA_SAL: number = 16;

export interface UsuarioAlmacenado {
    readonly usuario: string;
    readonly sal: string;
    readonly hash: string;
}

interface ArchivoDeUsuarios {
    readonly usuarios: readonly UsuarioAlmacenado[];
}

function derivarHash(contrasena: string, sal: Buffer): Promise<Buffer> {
    return new Promise<Buffer>(function (resolver: (valor: Buffer) => void, rechazar: (error: Error) => void): void {
        scrypt(contrasena, sal, LONGITUD_DEL_HASH, function (error: Error | null, derivado: Buffer): void {
            if (error != null) {
                rechazar(error);
                return;
            }
            resolver(derivado);
        });
    });
}

function esArchivoDeUsuarios(contenido: unknown): contenido is ArchivoDeUsuarios {
    if (typeof contenido !== 'object' || contenido === null) return false;
    var usuarios: unknown = Reflect.get(contenido, 'usuarios');
    if (!Array.isArray(usuarios)) return false;
    return usuarios.every(function (usuario: unknown): boolean {
        if (typeof usuario !== 'object' || usuario === null) return false;
        return typeof Reflect.get(usuario, 'usuario') === 'string'
            && typeof Reflect.get(usuario, 'sal') === 'string'
            && typeof Reflect.get(usuario, 'hash') === 'string';
    });
}

export async function leerUsuarios(archivo: string): Promise<readonly UsuarioAlmacenado[]> {
    var texto: string;
    try {
        texto = await readFile(archivo, 'utf8');
    } catch (error: unknown) {
        if (error instanceof Error && Reflect.get(error, 'code') === 'ENOENT') {
            return [];
        }
        throw error;
    }
    var contenido: unknown = JSON.parse(texto);
    if (!esArchivoDeUsuarios(contenido)) {
        throw new Error('El archivo de usuarios ' + archivo + ' no tiene el formato esperado');
    }
    return contenido.usuarios;
}

/**
 * Verifica usuario y contraseña. Cuando el usuario no existe igual calcula un hash
 * descartable, para que el tiempo de respuesta no revele qué usuarios están dados de alta.
 */
export async function verificarCredenciales(archivo: string, usuario: string, contrasena: string): Promise<boolean> {
    var usuarios: readonly UsuarioAlmacenado[] = await leerUsuarios(archivo);
    var encontrado: UsuarioAlmacenado | undefined = usuarios.find(function (candidato: UsuarioAlmacenado): boolean {
        return candidato.usuario === usuario;
    });
    if (encontrado == null) {
        await derivarHash(contrasena, randomBytes(LONGITUD_DE_LA_SAL));
        return false;
    }
    var esperado: Buffer = Buffer.from(encontrado.hash, 'base64');
    var obtenido: Buffer = await derivarHash(contrasena, Buffer.from(encontrado.sal, 'base64'));
    if (esperado.length !== obtenido.length) {
        return false;
    }
    return timingSafeEqual(esperado, obtenido);
}

export async function agregarUsuario(archivo: string, usuario: string, contrasena: string): Promise<void> {
    var usuarios: readonly UsuarioAlmacenado[] = await leerUsuarios(archivo);
    if (usuarios.some(function (candidato: UsuarioAlmacenado): boolean { return candidato.usuario === usuario; })) {
        throw new Error('El usuario ' + usuario + ' ya existe');
    }
    var sal: Buffer = randomBytes(LONGITUD_DE_LA_SAL);
    var hash: Buffer = await derivarHash(contrasena, sal);
    var nuevos: UsuarioAlmacenado[] = usuarios.concat([{
        usuario: usuario,
        sal: sal.toString('base64'),
        hash: hash.toString('base64'),
    }]);
    var contenido: ArchivoDeUsuarios = { usuarios: nuevos };
    await mkdir(dirname(archivo), { recursive: true });
    await writeFile(archivo, JSON.stringify(contenido, null, 4), { encoding: 'utf8', mode: 0o600 });
}
