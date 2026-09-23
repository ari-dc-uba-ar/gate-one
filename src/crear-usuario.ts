import { createInterface, type Interface } from 'node:readline/promises';
import { leerParametrosScram, rutaDelArchivoDeUsuarios } from './configuracion.ts';
import { agregarUsuario } from './usuarios.ts';

/**
 * La contraseña se lee por entrada estándar y no por argumento de línea de comandos,
 * para que no quede visible en la lista de procesos ni en el historial del intérprete.
 */
async function principal(): Promise<void> {
    var argumentos: string[] = process.argv.slice(2);
    if (argumentos.length !== 1) {
        throw new Error('uso: node dist/crear-usuario.js <usuario>  (la contraseña se ingresa a continuación)');
    }
    var lector: Interface = createInterface({ input: process.stdin, output: process.stderr });
    try {
        var contrasena: string = await lector.question('contraseña: ');
        if (contrasena === '') {
            throw new Error('la contraseña no puede estar vacía');
        }
        var archivo: string = rutaDelArchivoDeUsuarios();
        await agregarUsuario(archivo, argumentos[0], contrasena, leerParametrosScram());
        console.log('usuario ' + argumentos[0] + ' dado de alta en ' + archivo);
    } finally {
        lector.close();
    }
}

principal().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
