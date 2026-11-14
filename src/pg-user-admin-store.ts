import type { Pool } from 'pg';
import type { UserAdminStore, UserProfile } from './stores.ts';

/** Data access of the user administration, connected with its own database role (see install/grants.sql). */
export function createPgUserAdminStore(pool: Pool): UserAdminStore {
    return {
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
        setTotpSecret: async function (username: string, encryptedSecret: string): Promise<boolean> {
            var result = await pool.query(
                'update gate_one.users set totp_secret = $2, totp_last_step = null where username = $1',
                [username, encryptedSecret]
            );
            return result.rowCount === 1;
        },
        resetTotp: async function (username: string): Promise<boolean> {
            var client = await pool.connect();
            try {
                await client.query('begin');
                var result = await client.query(
                    'update gate_one.users set totp_secret = null, totp_last_step = null where username = $1',
                    [username]
                );
                await client.query('delete from gate_one.trusted_devices where username = $1', [username]);
                await client.query('commit');
                return result.rowCount === 1;
            } catch (error: unknown) {
                await client.query('rollback');
                throw error;
            } finally {
                client.release();
            }
        },
    };
}
