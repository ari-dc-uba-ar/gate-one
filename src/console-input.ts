import { createInterface, type Interface } from 'node:readline/promises';
import { messages } from './messages.ts';

export interface ConsoleInput {
    ask(prompt: string): Promise<string>;
    close(): void;
}

/**
 * Reads answers from standard input, one line each. The iterator keeps the lines that arrive
 * before each prompt (for example, from a pipe). An early end of the input is an error.
 */
export function createConsoleInput(): ConsoleInput {
    var reader: Interface = createInterface({ input: process.stdin });
    var lines: AsyncIterator<string> = reader[Symbol.asyncIterator]();
    return {
        ask: async function (prompt: string): Promise<string> {
            process.stderr.write(prompt);
            var line: IteratorResult<string> = await lines.next();
            if (line.done === true) {
                throw new Error(messages.inputEnded);
            }
            return line.value;
        },
        close: function (): void {
            reader.close();
        },
    };
}
