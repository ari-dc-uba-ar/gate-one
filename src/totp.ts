import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';
import { formatMessage, messages } from './messages.ts';

/**
 * Second factor with time-based one-time passwords (TOTP, RFC 6238): 6 digits every 30 seconds,
 * HMAC-SHA1, the parameters every authenticator app (Microsoft Authenticator, Google Authenticator, ...)
 * understands. The secret is stored encrypted, because it has to be read back to check the codes.
 */

const ISSUER: string = 'gate-one';
const PERIOD_SECONDS: number = 30;
const DIGITS: number = 6;
const SECRET_BYTES: number = 20;
/** Accepts the previous and the next 30 second step, for clocks that are slightly off. */
const WINDOW: number = 1;

const KEY_BYTES: number = 32;
const IV_BYTES: number = 12;
const TAG_BYTES: number = 16;
const ENCRYPTED_PREFIX: string = 'v1:';

function totpFor(username: string, secret: Secret): TOTP {
    return new TOTP({ issuer: ISSUER, label: username, secret: secret, algorithm: 'SHA1', digits: DIGITS, period: PERIOD_SECONDS });
}

/** A new random secret, in base32 (the usual text form of TOTP secrets). */
export function generateTotpSecret(): string {
    return new Secret({ size: SECRET_BYTES }).base32;
}

/** The otpauth:// URI the authenticator app reads from the QR code. */
export function totpUri(username: string, secret: string): string {
    return totpFor(username, Secret.fromBase32(secret)).toString();
}

/**
 * Returns the 30 second step the code belongs to, or undefined when the code is wrong.
 * The caller must reject a step that is not after the last one used, so a code is not used twice.
 */
export function verifyTotpCode(username: string, secret: string, code: string, timestamp: number = Date.now()): number | undefined {
    var token: string = code.replace(/\s/g, '');
    if (!/^[0-9]{6}$/.test(token)) {
        return undefined;
    }
    var delta: number | null = totpFor(username, Secret.fromBase32(secret)).validate({ token: token, timestamp: timestamp, window: WINDOW });
    if (delta == null) {
        return undefined;
    }
    return TOTP.counter({ period: PERIOD_SECONDS, timestamp: timestamp }) + delta;
}

/** The code for a given time; for tests. */
export function totpCodeAt(username: string, secret: string, timestamp: number): string {
    return totpFor(username, Secret.fromBase32(secret)).generate({ timestamp: timestamp });
}

/** Checks the encryption key read from AUTH_TOTP_KEY (32 bytes in base64). */
export function parseTotpKey(text: string): Buffer {
    var key: Buffer = Buffer.from(text, 'base64');
    if (key.length !== KEY_BYTES) {
        throw new Error(messages.totpKeyInvalid);
    }
    return key;
}

/**
 * AES-256-GCM. The username is authenticated data: a secret copied to another user's row
 * cannot be decrypted.
 */
export function encryptTotpSecret(key: Buffer, username: string, secret: string): string {
    var iv: Buffer = randomBytes(IV_BYTES);
    var cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(username, 'utf8'));
    var encrypted: Buffer = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
    return ENCRYPTED_PREFIX + Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
}

export function decryptTotpSecret(key: Buffer, username: string, stored: string): string {
    try {
        if (!stored.startsWith(ENCRYPTED_PREFIX)) {
            throw new Error('unknown format');
        }
        var data: Buffer = Buffer.from(stored.slice(ENCRYPTED_PREFIX.length), 'base64');
        var decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, IV_BYTES));
        decipher.setAAD(Buffer.from(username, 'utf8'));
        decipher.setAuthTag(data.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
        return Buffer.concat([decipher.update(data.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]).toString('utf8');
    } catch (error: unknown) {
        throw new Error(formatMessage(messages.totpSecretUnreadable, username), { cause: error });
    }
}
