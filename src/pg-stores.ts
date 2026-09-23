import { Pool } from 'pg';
import type { Adapter, AdapterFactory, AdapterPayload, JWK } from 'oidc-provider';
import { formatMessage, messages } from './messages.ts';
import type { SigningKeyStore, UserProfile, UserStore } from './stores.ts';

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

/** Removes the expired records. Returns how many were removed. */
export async function deleteExpiredModels(pool: Pool): Promise<number> {
    var result = await pool.query('delete from gate_one.oidc_models where expires_at <= current_timestamp');
    return result.rowCount ?? 0;
}
