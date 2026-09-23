import { strict as assert } from 'node:assert';
import { generarVerificador, PARAMETROS_SCRAM_DE_POSTGRES, verificarContrasena } from '../src/scram.ts';

/**
 * Verificadores generados por PostgreSQL 16 con:
 *     SET scram_iterations = <n>; CREATE ROLE r PASSWORD 'Clave de prueba 123!';
 *     SELECT rolpassword FROM pg_authid WHERE rolname = 'r';
 */
const CONTRASENA_DE_POSTGRES: string = 'Clave de prueba 123!';
const VERIFICADOR_DE_POSTGRES_4096: string = 'SCRAM-SHA-256$4096:+0KaIrUzxRQ65WrIwT5YgA==$LoiRBk0KG7KFKgxhx6zpOuxBm/Bg2mTf25KAE4DU42o=:TwmB0BfnxCj5DEwLKhpqOGdedTrR7GojaiUlJdnTZzo=';
const VERIFICADOR_DE_POSTGRES_10000: string = 'SCRAM-SHA-256$10000:bXiQmA68uJG0cJBCaYBwWQ==$HEIELoMOLtrOyMAxjrQ77KyYjxZw3dvfWOhhSkYOQsg=:nOFxeuaRue7rBtg/nIMZxCodpn+Yk16VjXQPEmuAVQY=';

const FORMATO: RegExp = /^SCRAM-SHA-256\$([0-9]+):([^$:]+)\$([^$:]+):([^$:]+)$/;

function partesDe(verificador: string): { iteraciones: number, sal: Buffer, claveAlmacenada: Buffer, claveDelServidor: Buffer } {
    var partes: RegExpExecArray | null = FORMATO.exec(verificador);
    if (partes == null) {
        throw new Error('formato inesperado: ' + verificador);
    }
    return {
        iteraciones: Number(partes[1]),
        sal: Buffer.from(partes[2], 'base64'),
        claveAlmacenada: Buffer.from(partes[3], 'base64'),
        claveDelServidor: Buffer.from(partes[4], 'base64'),
    };
}

describe('scram', function (): void {

    describe('parámetros predeterminados', function (): void {
        it('son los de PostgreSQL', function (): void {
            assert.deepEqual(PARAMETROS_SCRAM_DE_POSTGRES, { iteraciones: 4096, longitudDeLaSal: 16 });
        });
    });

    describe('verificadores generados por PostgreSQL', function (): void {
        it('acepta la contraseña correcta con 4096 iteraciones', async function (): Promise<void> {
            assert.equal(await verificarContrasena(CONTRASENA_DE_POSTGRES, VERIFICADOR_DE_POSTGRES_4096), true);
        });
        it('acepta la contraseña correcta con 10000 iteraciones', async function (): Promise<void> {
            assert.equal(await verificarContrasena(CONTRASENA_DE_POSTGRES, VERIFICADOR_DE_POSTGRES_10000), true);
        });
        it('rechaza una contraseña incorrecta', async function (): Promise<void> {
            assert.equal(await verificarContrasena('Clave de prueba 124!', VERIFICADOR_DE_POSTGRES_4096), false);
        });
    });

    describe('generarVerificador', function (): void {
        it('usa el formato y los parámetros de PostgreSQL por omisión', async function (): Promise<void> {
            var partes = partesDe(await generarVerificador('una clave', PARAMETROS_SCRAM_DE_POSTGRES));
            assert.equal(partes.iteraciones, 4096);
            assert.equal(partes.sal.length, 16);
            assert.equal(partes.claveAlmacenada.length, 32);
            assert.equal(partes.claveDelServidor.length, 32);
        });
        it('respeta los parámetros cambiados', async function (): Promise<void> {
            var verificador: string = await generarVerificador('una clave', { iteraciones: 5000, longitudDeLaSal: 32 });
            var partes = partesDe(verificador);
            assert.equal(partes.iteraciones, 5000);
            assert.equal(partes.sal.length, 32);
            assert.equal(await verificarContrasena('una clave', verificador), true);
        });
        it('usa una sal distinta cada vez', async function (): Promise<void> {
            var primero: string = await generarVerificador('una clave', PARAMETROS_SCRAM_DE_POSTGRES);
            var segundo: string = await generarVerificador('una clave', PARAMETROS_SCRAM_DE_POSTGRES);
            assert.notEqual(primero, segundo);
        });
        it('genera verificadores que se pueden volver a verificar', async function (): Promise<void> {
            var verificador: string = await generarVerificador('otra clave: ~{}', PARAMETROS_SCRAM_DE_POSTGRES);
            assert.equal(await verificarContrasena('otra clave: ~{}', verificador), true);
            assert.equal(await verificarContrasena('otra clave: ~{]', verificador), false);
        });
    });

    describe('verificadores mal formados', function (): void {
        var casos: readonly (readonly [string, string])[] = [
            ['otro algoritmo', 'SCRAM-SHA-1$4096:+0KaIrUzxRQ65WrIwT5YgA==$LoiRBk0KG7KFKgxhx6zpOuxBm/Bg2mTf25KAE4DU42o=:TwmB0BfnxCj5DEwLKhpqOGdedTrR7GojaiUlJdnTZzo='],
            ['md5 de PostgreSQL', 'md5a3556571e93b0d20722ba62be61e8c2d'],
            ['cero iteraciones', 'SCRAM-SHA-256$0:+0KaIrUzxRQ65WrIwT5YgA==$LoiRBk0KG7KFKgxhx6zpOuxBm/Bg2mTf25KAE4DU42o=:TwmB0BfnxCj5DEwLKhpqOGdedTrR7GojaiUlJdnTZzo='],
            ['clave almacenada corta', 'SCRAM-SHA-256$4096:+0KaIrUzxRQ65WrIwT5YgA==$LoiRBk0KG7KFKgxhx6zpOuxBm/Bg2mTf:TwmB0BfnxCj5DEwLKhpqOGdedTrR7GojaiUlJdnTZzo='],
            ['falta la clave del servidor', 'SCRAM-SHA-256$4096:+0KaIrUzxRQ65WrIwT5YgA==$LoiRBk0KG7KFKgxhx6zpOuxBm/Bg2mTf25KAE4DU42o='],
        ];
        casos.forEach(function ([descripcion, verificador]: readonly [string, string]): void {
            it('lanza una excepción: ' + descripcion, async function (): Promise<void> {
                await assert.rejects(verificarContrasena(CONTRASENA_DE_POSTGRES, verificador));
            });
        });
    });
});
