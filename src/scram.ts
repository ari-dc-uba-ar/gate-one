import { createHash, createHmac, pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Verificadores SCRAM-SHA-256 con el mismo formato que PostgreSQL guarda en pg_authid:
 *     SCRAM-SHA-256$<iteraciones>:<sal>$<StoredKey>:<ServerKey>
 * (sal y claves en base64). Con los parámetros predeterminados, los verificadores
 * son intercambiables con los que emite PostgreSQL en un dump.
 *
 * PostgreSQL aplica SASLprep a la contraseña antes de derivarla. Acá no se aplica:
 * para contraseñas ASCII imprimibles SASLprep no cambia nada, y gate-one solo acepta esas.
 */

const PREFIJO: string = 'SCRAM-SHA-256';
const LONGITUD_DE_LA_CLAVE: number = 32;
const FORMATO: RegExp = /^SCRAM-SHA-256\$([0-9]+):([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2}):([A-Za-z0-9+/]+={0,2})$/;

export interface ParametrosScram {
    readonly iteraciones: number;
    readonly longitudDeLaSal: number;
}

/** Los valores predeterminados de PostgreSQL (scram_iterations y SCRAM_DEFAULT_SALT_LEN). */
export const PARAMETROS_SCRAM_DE_POSTGRES: ParametrosScram = {
    iteraciones: 4096,
    longitudDeLaSal: 16,
};

interface VerificadorScram {
    readonly iteraciones: number;
    readonly sal: Buffer;
    readonly claveAlmacenada: Buffer;
    readonly claveDelServidor: Buffer;
}

function derivarContrasena(contrasena: string, sal: Buffer, iteraciones: number): Promise<Buffer> {
    return new Promise<Buffer>(function (resolver: (valor: Buffer) => void, rechazar: (error: Error) => void): void {
        pbkdf2(contrasena, sal, iteraciones, LONGITUD_DE_LA_CLAVE, 'sha256', function (error: Error | null, derivada: Buffer): void {
            if (error != null) {
                rechazar(error);
                return;
            }
            resolver(derivada);
        });
    });
}

function hmac(clave: Buffer, texto: string): Buffer {
    return createHmac('sha256', clave).update(texto).digest();
}

async function calcularClaves(contrasena: string, sal: Buffer, iteraciones: number): Promise<{ claveAlmacenada: Buffer, claveDelServidor: Buffer }> {
    var contrasenaSalada: Buffer = await derivarContrasena(contrasena, sal, iteraciones);
    var claveDelCliente: Buffer = hmac(contrasenaSalada, 'Client Key');
    return {
        claveAlmacenada: createHash('sha256').update(claveDelCliente).digest(),
        claveDelServidor: hmac(contrasenaSalada, 'Server Key'),
    };
}

function analizarVerificador(texto: string): VerificadorScram {
    var partes: RegExpExecArray | null = FORMATO.exec(texto);
    if (partes == null) {
        throw new Error('El verificador no tiene el formato ' + PREFIJO + '$<iteraciones>:<sal>$<StoredKey>:<ServerKey>');
    }
    var iteraciones: number = Number(partes[1]);
    var sal: Buffer = Buffer.from(partes[2], 'base64');
    var claveAlmacenada: Buffer = Buffer.from(partes[3], 'base64');
    var claveDelServidor: Buffer = Buffer.from(partes[4], 'base64');
    if (!Number.isSafeInteger(iteraciones) || iteraciones <= 0) {
        throw new Error('El verificador ' + PREFIJO + ' tiene una cantidad de iteraciones inválida');
    }
    if (claveAlmacenada.length !== LONGITUD_DE_LA_CLAVE || claveDelServidor.length !== LONGITUD_DE_LA_CLAVE) {
        throw new Error('El verificador ' + PREFIJO + ' tiene claves de longitud inválida');
    }
    return { iteraciones: iteraciones, sal: sal, claveAlmacenada: claveAlmacenada, claveDelServidor: claveDelServidor };
}

export async function generarVerificador(contrasena: string, parametros: ParametrosScram): Promise<string> {
    var sal: Buffer = randomBytes(parametros.longitudDeLaSal);
    var claves = await calcularClaves(contrasena, sal, parametros.iteraciones);
    return PREFIJO + '$' + parametros.iteraciones + ':' + sal.toString('base64')
        + '$' + claves.claveAlmacenada.toString('base64') + ':' + claves.claveDelServidor.toString('base64');
}

/**
 * Indica si la contraseña corresponde al verificador. Si el verificador está mal formado
 * lanza una excepción: es un error en los datos guardados, no una contraseña incorrecta.
 */
export async function verificarContrasena(contrasena: string, verificador: string): Promise<boolean> {
    var esperado: VerificadorScram = analizarVerificador(verificador);
    var obtenido = await calcularClaves(contrasena, esperado.sal, esperado.iteraciones);
    var coincideLaAlmacenada: boolean = timingSafeEqual(obtenido.claveAlmacenada, esperado.claveAlmacenada);
    var coincideLaDelServidor: boolean = timingSafeEqual(obtenido.claveDelServidor, esperado.claveDelServidor);
    return coincideLaAlmacenada && coincideLaDelServidor;
}
