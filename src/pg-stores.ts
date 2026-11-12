import { Pool } from 'pg';
import type { Adapter, AdapterFactory, AdapterPayload, JWK } from 'oidc-provider';
import { formatMessage, messages } from './messages.ts';
import type { ClientRecord, ClientResource, ClientStore, FailureStore, SigningKeyStore, TrustedDeviceStore, UserProfile, UserStore } from './stores.ts';

/**
 * The connection is configured with the standard PostgreSQL environment variables
 * (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD, ...), which pg reads by itself.
 */
export function createPool(): Pool {
    var pool: Pool = new Pool();
    pool.on('error', function (error: Error): void {
        console.error(messages.databasePoolError, error);
    });
    return pool;
}

export function createPgUserStore(pool: Pool): UserStore {
    return {
        findVerifier: async function (username: string): Promise<string | undefined> {
            var result = await pool.query<{ verifier: string }>(
                'select verifier from gate_one.users where username = $1',
                [username]
            );
            return result.rows.length === 0 ? undefined : result.rows[0].verifier;
        },
        findProfile: async function (username: string): Promise<UserProfile | undefined> {
            var result = await pool.query<UserProfile>(
                'select given_name as "givenName", family_name as "familyName", email, email_verified as "emailVerified"'
                + ' from gate_one.users where username = $1',
                [username]
            );
            return result.rows.length === 0 ? undefined : result.rows[0];
        },
        add: async function (username: string, verifier: string, profile: UserProfile): Promise<boolean> {
            var result = await pool.query(
                'insert into gate_one.users (username, verifier, given_name, family_name, email, email_verified)'
                + ' values ($1, $2, $3, $4, $5, $6) on conflict (username) do nothing',
                [username, verifier, profile.givenName, profile.familyName, profile.email, profile.emailVerified]
            );
            return result.rowCount === 1;
        },
        findTotpSecret: async function (username: string): Promise<string | undefined> {
            var result = await pool.query<{ secret: string | null }>(
                'select totp_secret as secret from gate_one.users where username = $1',
                [username]
            );
            return result.rows.length === 0 || result.rows[0].secret == null ? undefined : result.rows[0].secret;
        },
        setTotpSecret: async function (username: string, encryptedSecret: string | null): Promise<boolean> {
            var result = await pool.query(
                'update gate_one.users set totp_secret = $2, totp_last_step = null where username = $1',
                [username, encryptedSecret]
            );
            return result.rowCount === 1;
        },
        useTotpStep: async function (username: string, step: number): Promise<boolean> {
            // A single statement, so two requests with the same code cannot both succeed.
            var result = await pool.query(
                'update gate_one.users set totp_last_step = $2'
                + ' where username = $1 and (totp_last_step is null or totp_last_step < $2)',
                [username, step]
            );
            return result.rowCount === 1;
        },
    };
}

export function createPgTrustedDeviceStore(pool: Pool): TrustedDeviceStore {
    return {
        add: async function (tokenHash: string, username: string, days: number): Promise<void> {
            await pool.query(
                'insert into gate_one.trusted_devices (token_hash, username, expires_at)'
                + ' values ($1, $2, current_timestamp + make_interval(days => $3))',
                [tokenHash, username, days]
            );
        },
        isTrusted: async function (tokenHash: string, username: string): Promise<boolean> {
            var result = await pool.query(
                'select 1 from gate_one.trusted_devices where token_hash = $1 and username = $2 and expires_at > current_timestamp',
                [tokenHash, username]
            );
            return result.rows.length > 0;
        },
        removeForUser: async function (username: string): Promise<void> {
            await pool.query('delete from gate_one.trusted_devices where username = $1', [username]);
        },
    };
}

export function createPgFailureStore(pool: Pool): FailureStore {
    return {
        isBlocked: async function (key: string, limit: number, windowSeconds: number): Promise<boolean> {
            var result = await pool.query(
                'select 1 from gate_one.auth_failures where key = $1 and failures >= $2'
                + ' and window_start > current_timestamp - make_interval(secs => $3)',
                [key, limit, windowSeconds]
            );
            return result.rows.length > 0;
        },
        /**
         * A window starts with the first failure; reaching the limit restarts it, so the block lasts
         * windowSeconds from the last failure. Failures after an expired window start a new one.
         */
        recordFailure: async function (key: string, limit: number, windowSeconds: number): Promise<void> {
            await pool.query(
                'insert into gate_one.auth_failures as f (key, window_start, failures) values ($1, current_timestamp, 1)'
                + ' on conflict (key) do update set'
                + ' failures = case when f.window_start <= current_timestamp - make_interval(secs => $3) then 1 else f.failures + 1 end,'
                + ' window_start = case when f.window_start <= current_timestamp - make_interval(secs => $3) then current_timestamp'
                + ' when f.failures + 1 >= $2 then current_timestamp else f.window_start end',
                [key, limit, windowSeconds]
            );
        },
        reset: async function (key: string): Promise<void> {
            await pool.query('delete from gate_one.auth_failures where key = $1', [key]);
        },
    };
}

function isJwk(value: unknown): value is JWK {
    return typeof value === 'object' && value !== null
        && typeof Reflect.get(value, 'kty') === 'string'
        && typeof Reflect.get(value, 'kid') === 'string';
}

export function createPgSigningKeyStore(pool: Pool): SigningKeyStore {
    return {
        list: async function (): Promise<JWK[]> {
            var result = await pool.query<{ kid: string, jwk: unknown }>(
                'select kid, jwk from gate_one.signing_keys order by created_at desc, kid'
            );
            return result.rows.map(function (row: { kid: string, jwk: unknown }): JWK {
                if (!isJwk(row.jwk) || row.jwk.kid !== row.kid) {
                    throw new Error(formatMessage(messages.signingKeyInvalid, row.kid));
                }
                return row.jwk;
            });
        },
        add: async function (key: JWK): Promise<void> {
            await pool.query('insert into gate_one.signing_keys (kid, jwk) values ($1, $2)', [key.kid, JSON.stringify(key)]);
        },
    };
}

export function createPgClientStore(pool: Pool): ClientStore {
    return {
        findClient: async function (clientId: string): Promise<ClientRecord | undefined> {
            var result = await pool.query<ClientRecord>(
                'select client_id as "clientId", client_secret as "clientSecret", redirect_uris as "redirectUris",'
                + ' post_logout_redirect_uris as "postLogoutRedirectUris", backchannel_logout_uri as "backchannelLogoutUri"'
                + ' from gate_one.clients where client_id = $1',
                [clientId]
            );
            return result.rows.length === 0 ? undefined : result.rows[0];
        },
        findResources: async function (clientId: string): Promise<ClientResource[]> {
            var result = await pool.query<ClientResource>(
                'select r.resource, array(select unnest(cr.scopes) intersect select unnest(r.scopes) order by 1) as scopes,'
                + ' r.access_token_ttl as "accessTokenTtl"'
                + ' from gate_one.client_resources cr join gate_one.resource_servers r using (resource)'
                + ' where cr.client_id = $1 order by r.resource',
                [clientId]
            );
            return result.rows.filter(function (row: ClientResource): boolean {
                return row.scopes.length > 0;
            });
        },
        isBackchannelLogoutUri: async function (uri: string): Promise<boolean> {
            var result = await pool.query<{ uri: string }>(
                'select backchannel_logout_uri as uri from gate_one.clients where backchannel_logout_uri is not null'
            );
            var normalized: string = new URL(uri).href;
            return result.rows.some(function (row: { uri: string }): boolean {
                return new URL(row.uri).href === normalized;
            });
        },
    };
}

/** Models whose records belong to a grant and are removed by revokeByGrantId (as in oidc-provider's memory adapter). */
const GRANTABLE_MODELS: ReadonlySet<string> = new Set<string>([
    'AccessToken',
    'AuthorizationCode',
    'RefreshToken',
    'DeviceCode',
    'BackchannelAuthenticationRequest',
    'PreAuthorizedCode',
]);

function isPayload(value: unknown): value is AdapterPayload {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function firstPayload(rows: readonly { payload: unknown }[]): AdapterPayload | undefined {
    if (rows.length === 0) {
        return undefined;
    }
    var payload: unknown = rows[0].payload;
    if (!isPayload(payload)) {
        throw new Error(messages.oidcPayloadInvalid);
    }
    return payload;
}

const NOT_EXPIRED: string = '(expires_at is null or expires_at > current_timestamp)';

/**
 * oidc-provider adapter over the gate_one.oidc_models table. Expired records are never returned;
 * deleteExpiredModels removes them from the table.
 */
export function createPgAdapterFactory(pool: Pool): AdapterFactory {
    return function (model: string): Adapter {
        return {
            upsert: async function (id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
                var grantId: string | null = GRANTABLE_MODELS.has(model) && payload.grantId != null ? payload.grantId : null;
                var uid: string | null = model === 'Session' && payload.uid != null ? payload.uid : null;
                var userCode: string | null = payload.userCode != null ? payload.userCode : null;
                await pool.query(
                    'insert into gate_one.oidc_models (model, id, payload, grant_id, user_code, uid, expires_at)'
                    + ' values ($1, $2, $3, $4, $5, $6, current_timestamp + make_interval(secs => $7::double precision))'
                    + ' on conflict (model, id) do update set payload = excluded.payload, grant_id = excluded.grant_id,'
                    + ' user_code = excluded.user_code, uid = excluded.uid, expires_at = excluded.expires_at',
                    [model, id, JSON.stringify(payload), grantId, userCode, uid, expiresIn == null ? null : expiresIn]
                );
            },
            find: async function (id: string): Promise<AdapterPayload | undefined> {
                var result = await pool.query<{ payload: unknown }>(
                    'select payload from gate_one.oidc_models where model = $1 and id = $2 and ' + NOT_EXPIRED,
                    [model, id]
                );
                return firstPayload(result.rows);
            },
            findByUserCode: async function (userCode: string): Promise<AdapterPayload | undefined> {
                var result = await pool.query<{ payload: unknown }>(
                    'select payload from gate_one.oidc_models where model = $1 and user_code = $2 and ' + NOT_EXPIRED,
                    [model, userCode]
                );
                return firstPayload(result.rows);
            },
            findByUid: async function (uid: string): Promise<AdapterPayload | undefined> {
                var result = await pool.query<{ payload: unknown }>(
                    'select payload from gate_one.oidc_models where model = $1 and uid = $2 and ' + NOT_EXPIRED,
                    [model, uid]
                );
                return firstPayload(result.rows);
            },
            consume: async function (id: string): Promise<void> {
                await pool.query(
                    'update gate_one.oidc_models'
                    + ' set payload = jsonb_set(payload, \'{consumed}\', to_jsonb(floor(extract(epoch from current_timestamp))::bigint))'
                    + ' where model = $1 and id = $2',
                    [model, id]
                );
            },
            destroy: async function (id: string): Promise<void> {
                await pool.query('delete from gate_one.oidc_models where model = $1 and id = $2', [model, id]);
            },
            revokeByGrantId: async function (grantId: string): Promise<void> {
                await pool.query('delete from gate_one.oidc_models where grant_id = $1', [grantId]);
            },
        };
    };
}

/** Removes the expired trusted devices and the failure counts whose window ended. */
export async function deleteExpiredSecurityRecords(pool: Pool, failureWindowSeconds: number): Promise<void> {
    await pool.query('delete from gate_one.trusted_devices where expires_at <= current_timestamp');
    await pool.query(
        'delete from gate_one.auth_failures where window_start <= current_timestamp - make_interval(secs => $1)',
        [failureWindowSeconds]
    );
}

/** Removes the expired records. Returns how many were removed. */
export async function deleteExpiredModels(pool: Pool): Promise<number> {
    var result = await pool.query('delete from gate_one.oidc_models where expires_at <= current_timestamp');
    return result.rowCount ?? 0;
}
