import { createInterface, type Interface } from 'node:readline/promises';
import type { Pool } from 'pg';
import { readLang, readScramParameters } from './config.ts';
import { formatMessage, messages, setLang } from './messages.ts';
import { createPgUserStore, createPool } from './pg-stores.ts';
import type { UserProfile } from './stores.ts';
import { addUser } from './users.ts';

/**
 * The password is read from standard input and not from a command line argument,
 * so it does not show up in the process list nor in the shell history.
 */
async function main(): Promise<void> {
    setLang(readLang());
    var args: string[] = process.argv.slice(2);
    if (args.length !== 1) {
        throw new Error(messages.createUserUsage);
    }
    var reader: Interface = createInterface({ input: process.stdin });
    // The iterator keeps the lines that arrive before each prompt (for example, from a pipe).
    var lines: AsyncIterator<string> = reader[Symbol.asyncIterator]();
    var ask = async function (prompt: string): Promise<string> {
        process.stderr.write(prompt);
        var line: IteratorResult<string> = await lines.next();
        if (line.done === true) {
            throw new Error(messages.inputEnded);
        }
        return line.value;
    };
    var pool: Pool = createPool();
    try {
        var givenName: string = (await ask(messages.givenNamePrompt)).trim();
        var familyName: string = (await ask(messages.familyNamePrompt)).trim();
        var email: string = (await ask(messages.emailPrompt)).trim();
        var password: string = await ask(messages.passwordPrompt);
        if (password === '') {
            throw new Error(messages.passwordEmpty);
        }
        var profile: UserProfile = {
            givenName: givenName,
            familyName: familyName,
            email: email === '' ? null : email,
            emailVerified: false,
        };
        await addUser(createPgUserStore(pool), args[0], password, profile, readScramParameters());
        console.log(formatMessage(messages.userCreated, args[0]));
    } finally {
        reader.close();
        await pool.end();
    }
}

main().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
