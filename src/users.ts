import { formatMessage, messages } from './messages.ts';
import { generateVerifier, verifyPassword, type ScramParameters } from './scram.ts';
import type { UserProfile, UserStore } from './stores.ts';

/**
 * Usernames and passwords are limited to printable ASCII. That way the SCRAM verifier matches
 * the one PostgreSQL computes without applying SASLprep.
 */
const PRINTABLE_ASCII: RegExp = /^[\x20-\x7E]+$/;
const EMAIL: RegExp = /^[^@\s]+@[^@\s]+$/;

export function isPrintableAscii(text: string): boolean {
    return PRINTABLE_ASCII.test(text);
}

/**
 * Verifies username and password. When the user does not exist (or is not printable ASCII)
 * it still computes a throwaway verifier, so the response time does not reveal which users
 * are registered.
 */
export async function verifyCredentials(store: UserStore, username: string, password: string, parameters: ScramParameters): Promise<boolean> {
    var verifier: string | undefined = isPrintableAscii(username) ? await store.findVerifier(username) : undefined;
    if (verifier == null || !isPrintableAscii(password)) {
        await generateVerifier(password, parameters);
        return false;
    }
    return verifyPassword(password, verifier);
}

export async function addUser(store: UserStore, username: string, password: string, profile: UserProfile, parameters: ScramParameters): Promise<void> {
    if (!isPrintableAscii(username) || !isPrintableAscii(password)) {
        throw new Error(messages.nonAsciiCredentials);
    }
    if (profile.givenName.trim() === '' || profile.familyName.trim() === '') {
        throw new Error(messages.nameRequired);
    }
    if (profile.email != null && !EMAIL.test(profile.email)) {
        throw new Error(formatMessage(messages.invalidEmail, profile.email));
    }
    var verifier: string = await generateVerifier(password, parameters);
    if (!await store.add(username, verifier, profile)) {
        throw new Error(formatMessage(messages.userAlreadyExists, username));
    }
}
