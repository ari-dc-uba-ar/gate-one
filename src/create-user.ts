import { createInterface, type Interface } from 'node:readline/promises';
import { readLang, readScramParameters, usersFilePath } from './config.ts';
import { formatMessage, messages, setLang } from './messages.ts';
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
    var reader: Interface = createInterface({ input: process.stdin, output: process.stderr });
    try {
        var password: string = await reader.question(messages.passwordPrompt);
        if (password === '') {
            throw new Error(messages.passwordEmpty);
        }
        var file: string = usersFilePath();
        await addUser(file, args[0], password, readScramParameters());
        console.log(formatMessage(messages.userCreated, args[0], file));
    } finally {
        reader.close();
    }
}

main().catch(function (error: unknown): void {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
