import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { formatMessage, messages } from './messages.ts';
import { generateVerifier, verifyPassword, type ScramParameters } from './scram.ts';

/**
 * Usernames and passwords are limited to printable ASCII. That way the SCRAM verifier matches
 * the one PostgreSQL computes without applying SASLprep.
 */
const PRINTABLE_ASCII: RegExp = /^[\x20-\x7E]+$/;

export interface StoredUser {
    readonly username: string;
    readonly verifier: string;
}

interface UsersFile {
    readonly users: readonly StoredUser[];
}

export function isPrintableAscii(text: string): boolean {
    return PRINTABLE_ASCII.test(text);
}

function isUsersFile(content: unknown): content is UsersFile {
    if (typeof content !== 'object' || content === null) return false;
    var users: unknown = Reflect.get(content, 'users');
    if (!Array.isArray(users)) return false;
    return users.every(function (user: unknown): boolean {
        if (typeof user !== 'object' || user === null) return false;
        return typeof Reflect.get(user, 'username') === 'string'
            && typeof Reflect.get(user, 'verifier') === 'string';
    });
}

export async function readUsers(file: string): Promise<readonly StoredUser[]> {
    var text: string;
    try {
        text = await readFile(file, 'utf8');
    } catch (error: unknown) {
        if (error instanceof Error && Reflect.get(error, 'code') === 'ENOENT') {
            return [];
        }
        throw error;
    }
    var content: unknown = JSON.parse(text);
    if (!isUsersFile(content)) {
        throw new Error(formatMessage(messages.usersFileInvalid, file));
    }
    return content.users;
}

/**
 * Verifies username and password. When the user does not exist (or is not printable ASCII)
 * it still computes a throwaway verifier, so the response time does not reveal which users
 * are registered.
 */
export async function verifyCredentials(file: string, username: string, password: string, parameters: ScramParameters): Promise<boolean> {
    var users: readonly StoredUser[] = await readUsers(file);
    var found: StoredUser | undefined = users.find(function (candidate: StoredUser): boolean {
        return candidate.username === username;
    });
    if (found == null || !isPrintableAscii(username) || !isPrintableAscii(password)) {
        await generateVerifier(password, parameters);
        return false;
    }
    return verifyPassword(password, found.verifier);
}

export async function addUser(file: string, username: string, password: string, parameters: ScramParameters): Promise<void> {
    if (!isPrintableAscii(username) || !isPrintableAscii(password)) {
        throw new Error(messages.nonAsciiCredentials);
    }
    var users: readonly StoredUser[] = await readUsers(file);
    if (users.some(function (candidate: StoredUser): boolean { return candidate.username === username; })) {
        throw new Error(formatMessage(messages.userAlreadyExists, username));
    }
    var verifier: string = await generateVerifier(password, parameters);
    var newUsers: StoredUser[] = users.concat([{
        username: username,
        verifier: verifier,
    }]);
    var content: UsersFile = { users: newUsers };
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify(content, null, 4), { encoding: 'utf8', mode: 0o600 });
}
