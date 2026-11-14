import type { Pool } from 'pg';
import QRCode from 'qrcode';
import { readLang, readTotpKey } from './config.ts';
import { createConsoleInput, type ConsoleInput } from './console-input.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createPgUserStore, createPool } from './pg-stores.ts';
import type { UserStore } from './stores.ts';
import { encryptTotpSecret, generateTotpSecret, totpUri, verifyTotpCode } from './totp.ts';

/**
 * Enables the second factor of a user. The user scans the QR code with the authenticator app
 * and types the first code; the secret is saved only if that code is right.
 */
async function main(): Promise<void> {
    setLang(readLang());
    var args: string[] = process.argv.slice(2);
    if (args.length !== 1) {
        throw new Error(messages.enableTotpUsage);
    }
    var username: string = args[0];
    var key: Buffer = readTotpKey();
    var input: ConsoleInput = createConsoleInput();
    var pool: Pool = createPool();
    try {
        var users: UserStore = createPgUserStore(pool);
        if (await users.findProfile(username) == null) {
            throw new Error(formatMessage(messages.userNotFound, username));
        }
        if (await users.findTotpSecret(username) != null) {
            throw new Error(formatMessage(messages.totpAlreadyEnabled, username));
        }
        var secret: string = generateTotpSecret();
        var uri: string = totpUri(username, secret);
        console.log(messages.totpScanQr);
        console.log(await QRCode.toString(uri, { type: 'terminal', small: true }));
        console.log(uri);
        var code: string = await input.ask(messages.totpCodePrompt);
        if (verifyTotpCode(username, secret, code) == null) {
            throw new Error(messages.invalidCode);
        }
        if (!await users.setTotpSecret(username, encryptTotpSecret(key, username, secret))) {
            throw new Error(formatMessage(messages.userNotFound, username));
        }
        console.log(formatMessage(messages.totpEnabled, username));
    } finally {
        input.close();
        await pool.end();
    }
}

main().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
