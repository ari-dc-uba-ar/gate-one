import { createHash, createHmac, pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto';
import { messages } from './messages.ts';

/**
 * SCRAM-SHA-256 verifiers in the same format PostgreSQL stores in pg_authid:
 *     SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
 * (salt and keys in base64). With the default parameters, the verifiers are
 * interchangeable with the ones PostgreSQL emits in a dump.
 *
 * PostgreSQL applies SASLprep to the password before deriving it. It is not applied here:
 * SASLprep changes nothing for printable ASCII passwords, and gate-one only accepts those.
 */

const PREFIX: string = 'SCRAM-SHA-256';
const KEY_LENGTH: number = 32;
const FORMAT: RegExp = /^SCRAM-SHA-256\$([0-9]+):([A-Za-z0-9+/]+={0,2})\$([A-Za-z0-9+/]+={0,2}):([A-Za-z0-9+/]+={0,2})$/;

export interface ScramParameters {
    readonly iterations: number;
    readonly saltLength: number;
}

/** PostgreSQL defaults (scram_iterations and SCRAM_DEFAULT_SALT_LEN). */
export const POSTGRES_SCRAM_PARAMETERS: ScramParameters = {
    iterations: 4096,
    saltLength: 16,
};

interface ScramVerifier {
    readonly iterations: number;
    readonly salt: Buffer;
    readonly storedKey: Buffer;
    readonly serverKey: Buffer;
}

function derivePassword(password: string, salt: Buffer, iterations: number): Promise<Buffer> {
    return new Promise<Buffer>(function (resolve: (value: Buffer) => void, reject: (error: Error) => void): void {
        pbkdf2(password, salt, iterations, KEY_LENGTH, 'sha256', function (error: Error | null, derived: Buffer): void {
            if (error != null) {
                reject(error);
                return;
            }
            resolve(derived);
        });
    });
}

function hmac(key: Buffer, text: string): Buffer {
    return createHmac('sha256', key).update(text).digest();
}

async function computeKeys(password: string, salt: Buffer, iterations: number): Promise<{ storedKey: Buffer, serverKey: Buffer }> {
    var saltedPassword: Buffer = await derivePassword(password, salt, iterations);
    var clientKey: Buffer = hmac(saltedPassword, 'Client Key');
    return {
        storedKey: createHash('sha256').update(clientKey).digest(),
        serverKey: hmac(saltedPassword, 'Server Key'),
    };
}

function parseVerifier(text: string): ScramVerifier {
    var parts: RegExpExecArray | null = FORMAT.exec(text);
    if (parts == null) {
        throw new Error(messages.scramInvalidFormat);
    }
    var iterations: number = Number(parts[1]);
    var salt: Buffer = Buffer.from(parts[2], 'base64');
    var storedKey: Buffer = Buffer.from(parts[3], 'base64');
    var serverKey: Buffer = Buffer.from(parts[4], 'base64');
    if (!Number.isSafeInteger(iterations) || iterations <= 0) {
        throw new Error(messages.scramInvalidIterations);
    }
    if (storedKey.length !== KEY_LENGTH || serverKey.length !== KEY_LENGTH) {
        throw new Error(messages.scramInvalidKeyLength);
    }
    return { iterations: iterations, salt: salt, storedKey: storedKey, serverKey: serverKey };
}

export async function generateVerifier(password: string, parameters: ScramParameters): Promise<string> {
    var salt: Buffer = randomBytes(parameters.saltLength);
    var keys = await computeKeys(password, salt, parameters.iterations);
    return PREFIX + '$' + parameters.iterations + ':' + salt.toString('base64')
        + '$' + keys.storedKey.toString('base64') + ':' + keys.serverKey.toString('base64');
}

/**
 * Tells whether the password matches the verifier. A malformed verifier throws:
 * it is an error in the stored data, not a wrong password.
 */
export async function verifyPassword(password: string, verifier: string): Promise<boolean> {
    var expected: ScramVerifier = parseVerifier(verifier);
    var obtained = await computeKeys(password, expected.salt, expected.iterations);
    var storedKeyMatches: boolean = timingSafeEqual(obtained.storedKey, expected.storedKey);
    var serverKeyMatches: boolean = timingSafeEqual(obtained.serverKey, expected.serverKey);
    return storedKeyMatches && serverKeyMatches;
}
