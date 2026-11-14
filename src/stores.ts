import type { JWK } from 'oidc-provider';

/**
 * Storage interfaces. The logic in users.ts and keys.ts only depends on these; the PostgreSQL
 * implementations can be replaced by others. Each service has its own: the authentication service
 * in pg-auth-stores.ts (oidc-provider's own data goes through its Adapter interface, also there),
 * the user administration in pg-user-admin-store.ts and the installation in pg-signing-key-admin-store.ts.
 */

export interface UserProfile {
    readonly givenName: string;
    readonly familyName: string;
    readonly email: string | null;
    readonly emailVerified: boolean;
}

/** What the authentication service reads, and the only thing it writes, about users. */
export interface AuthUserStore {
    /** The verifier of an active user; undefined when the user does not exist or is not active. */
    findVerifier(username: string): Promise<string | undefined>;
    /** The profile of an active user; undefined when the user does not exist or is not active. */
    findActiveProfile(username: string): Promise<UserProfile | undefined>;
    /** The encrypted TOTP secret, or undefined when the user does not exist or has no second factor. */
    findTotpSecret(username: string): Promise<string | undefined>;
    /** Records the step of a code; false when it is not after the last one used (the code was already used). */
    useTotpStep(username: string, step: number): Promise<boolean>;
}

/** What the user administration does. */
export interface UserAdminStore {
    findProfile(username: string): Promise<UserProfile | undefined>;
    /** Returns false when the user already exists. */
    add(username: string, verifier: string, profile: UserProfile): Promise<boolean>;
    /** The encrypted TOTP secret, or undefined when the user does not exist or has no second factor. */
    findTotpSecret(username: string): Promise<string | undefined>;
    /** Sets the encrypted TOTP secret and forgets the last step used. False when the user does not exist. */
    setTotpSecret(username: string, encryptedSecret: string): Promise<boolean>;
    /** Removes the second factor and the remembered devices. False when the user does not exist. */
    resetTotp(username: string): Promise<boolean>;
}

/** Devices where the user chose not to enter the second factor for a while. */
export interface TrustedDeviceStore {
    add(tokenHash: string, username: string, days: number): Promise<void>;
    isTrusted(tokenHash: string, username: string): Promise<boolean>;
}

/** Failed attempts by key, within a time window (see rate-limit.ts). */
export interface FailureStore {
    isBlocked(key: string, limit: number, windowSeconds: number): Promise<boolean>;
    recordFailure(key: string, limit: number, windowSeconds: number): Promise<void>;
    reset(key: string): Promise<void>;
}

export interface SigningKeyStore {
    list(): Promise<JWK[]>;
}

/** Signing keys are created at installation time, not by the authentication service. */
export interface SigningKeyAdminStore {
    add(key: JWK): Promise<void>;
}

export interface ClientRecord {
    readonly clientId: string;
    readonly clientSecret: string;
    readonly redirectUris: readonly string[];
    readonly postLogoutRedirectUris: readonly string[];
    readonly backchannelLogoutUri: string | null;
}

/** An API a client may call, with the scopes the client receives for it. */
export interface ClientResource {
    readonly resource: string;
    readonly scopes: readonly string[];
    readonly accessTokenTtl: number;
}

export interface ClientStore {
    findClient(clientId: string): Promise<ClientRecord | undefined>;
    /** Only the scopes that are both granted to the client and defined by the resource server. */
    findResources(clientId: string): Promise<ClientResource[]>;
    /** Compares the URLs normalized (as oidc-provider does before calling them). */
    isBackchannelLogoutUri(uri: string): Promise<boolean>;
}
