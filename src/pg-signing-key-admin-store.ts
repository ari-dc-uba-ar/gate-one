import type { Pool } from 'pg';
import type { JWK } from 'oidc-provider';
import type { SigningKeyAdminStore } from './stores.ts';

/** Creation of signing keys, done at installation time with an administrator's connection. */
export function createPgSigningKeyAdminStore(pool: Pool): SigningKeyAdminStore {
    return {
        add: async function (key: JWK): Promise<void> {
            await pool.query('insert into gate_one.signing_keys (kid, jwk) values ($1, $2)', [key.kid, JSON.stringify(key)]);
        },
    };
}
