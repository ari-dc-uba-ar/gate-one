import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { generarVerificador, verificarContrasena, type ParametrosScram } from './scram.ts';

/**
 * Usuarios y contraseñas se limitan a ASCII imprimible. Así el verificador SCRAM coincide
 * con el que calcula PostgreSQL sin necesidad de aplicar SASLprep.
 */
const ASCII_IMPRIMIBLE: RegExp = /^[\x20-\x7E]+$/;

export interface UsuarioAlmacenado {
    readonly usuario: string;
    readonly verificador: string;
}

interface ArchivoDeUsuarios {
    readonly usuarios: readonly UsuarioAlmacenado[];
}

export function esAsciiImprimible(texto: string): boolean {
    return ASCII_IMPRIMIBLE.test(texto);
}

function esArchivoDeUsuarios(contenido: unknown): contenido is ArchivoDeUsuarios {
    if (typeof contenido !== 'object' || contenido === null) return false;
    var usuarios: unknown = Reflect.get(contenido, 'usuarios');
    if (!Array.isArray(usuarios)) return false;
    return usuarios.every(function (usuario: unknown): boolean {
        if (typeof usuario !== 'object' || usuario === null) return false;
        return typeof Reflect.get(usuario, 'usuario') === 'string'
            && typeof Reflect.get(usuario, 'verificador') === 'string';
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
 * Verifica usuario y contraseña. Cuando el usuario no existe (o no es ASCII imprimible) igual
 * calcula un verificador descartable, para que el tiempo de respuesta no revele qué usuarios
 * están dados de alta.
 */
export async function verificarCredenciales(archivo: string, usuario: string, contrasena: string, parametros: ParametrosScram): Promise<boolean> {
    var usuarios: readonly UsuarioAlmacenado[] = await leerUsuarios(archivo);
    var encontrado: UsuarioAlmacenado | undefined = usuarios.find(function (candidato: UsuarioAlmacenado): boolean {
        return candidato.usuario === usuario;
    });
    if (encontrado == null || !esAsciiImprimible(usuario) || !esAsciiImprimible(contrasena)) {
        await generarVerificador(contrasena, parametros);
        return false;
    }
    return verificarContrasena(contrasena, encontrado.verificador);
}

export async function agregarUsuario(archivo: string, usuario: string, contrasena: string, parametros: ParametrosScram): Promise<void> {
    if (!esAsciiImprimible(usuario) || !esAsciiImprimible(contrasena)) {
        throw new Error('El usuario y la contraseña solo pueden tener caracteres ASCII imprimibles');
    }
    var usuarios: readonly UsuarioAlmacenado[] = await leerUsuarios(archivo);
    if (usuarios.some(function (candidato: UsuarioAlmacenado): boolean { return candidato.usuario === usuario; })) {
        throw new Error('El usuario ' + usuario + ' ya existe');
    }
    var verificador: string = await generarVerificador(contrasena, parametros);
    var nuevos: UsuarioAlmacenado[] = usuarios.concat([{
        usuario: usuario,
        verificador: verificador,
    }]);
    var contenido: ArchivoDeUsuarios = { usuarios: nuevos };
    await mkdir(dirname(archivo), { recursive: true });
    await writeFile(archivo, JSON.stringify(contenido, null, 4), { encoding: 'utf8', mode: 0o600 });
}
