import type { JWK } from 'oidc-provider';

/**
 * Storage interfaces. The logic in users.ts and keys.ts only depends on these; the PostgreSQL
 * implementation is in pg-stores.ts and can be replaced by another one.
 * oidc-provider's own data goes through its Adapter interface (also implemented in pg-stores.ts).
 */

export interface UserProfile {
    readonly givenName: string;
    readonly familyName: string;
    readonly email: string | null;
    readonly emailVerified: boolean;
}

export interface UserStore {
    findVerifier(username: string): Promise<string | undefined>;
    findProfile(username: string): Promise<UserProfile | undefined>;
    /** Returns false when the user already exists. */
    add(username: string, verifier: string, profile: UserProfile): Promise<boolean>;
}

export interface SigningKeyStore {
    list(): Promise<JWK[]>;
    add(key: JWK): Promise<void>;
}
