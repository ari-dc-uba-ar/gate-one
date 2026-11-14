# gate-one
Auth0 for one-back

OpenID Connect server to centralize user identification and passwords.
Built on [oidc-provider](https://github.com/panva/node-oidc-provider) and PostgreSQL,
modeled after Entra ID: services connect to it the same way they would connect to Entra ID or Google.

Passwords are stored as SCRAM-SHA-256 verifiers with the same format and default parameters as PostgreSQL
(the strings are interchangeable with the ones in `pg_authid`). Usernames and passwords are limited to printable ASCII.

## Installation

### Requirements

- Node.js 22 or later
- PostgreSQL 14 or later

### 1. Get and build the code

```sh
git clone https://github.com/ari-dc-uba-ar/gate-one.git
cd gate-one
npm ci
npm run build
```

### 2. Create the database

gate-one is split by what each part needs to know and to do. Each part connects with its own role:

| Role | Used by | Can |
|---|---|---|
| `gate_one_auth` | the gate-one server (authentication) | read users, clients and signing keys; write only its own records (sessions, codes, failed attempts, remembered devices) |
| `gate_one_apps` | systems administration | register clients, APIs and their permissions |
| `gate_one_users` | users administration (`create-user`, `enable-totp`, `reset-totp`) | create users and change their data, passwords, second factor and active flag |

None of them can create or alter objects. Run as a PostgreSQL administrator:

```sh
psql -U postgres -c "create role gate_one_auth login" -c "create role gate_one_apps login" -c "create role gate_one_users login"
psql -U postgres -c "\password gate_one_auth"     # and the same for the other two
psql -U postgres -c "create database gate_one"
psql -U postgres -d gate_one -v ON_ERROR_STOP=1 -f install/schema.sql
psql -U postgres -d gate_one -v ON_ERROR_STOP=1 -v auth_role=gate_one_auth -v apps_role=gate_one_apps -v users_role=gate_one_users -f install/grants.sql
```

`install/schema.sql` creates the `gate_one` schema; `install/grants.sql` gives each role its permissions.
Use a database (or cluster) of its own: it holds the password verifiers and the client secrets.

Then create the signing key (with the administrator's connection: the server can only read the keys):

```sh
PGUSER=postgres PGDATABASE=gate_one npm run create-signing-key
```

### 3. Configure

The server and the users administration commands have separate configuration files, each one with the connection
of its own role.

```sh
cp .env.example .env
cp .env.users.example .env.users
```

Edit `.env` (the server):

- `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`: the connection with the `gate_one_auth` role (standard PostgreSQL variables).
- `AUTH_ISSUER`: the public URL of gate-one. It is part of every token, so it must not change once services use it.
- `AUTH_PORT`: the port it listens on.
- `AUTH_COOKIE_KEYS`: cookie signing keys, comma separated. Generate each one with `openssl rand -base64 32`.
- `AUTH_TOTP_KEY`: key that encrypts the second factor secrets, generated with `openssl rand -base64 32`.
  Keep it out of the database (and of its backups): if it is lost or changed, every user must enable the second factor again.
- `AUTH_LANG`: language of the pages and messages, `en` (default) or `es`.
- Optional: `AUTH_SESSION_TTL` (seconds, 8 hours by default), `AUTH_SCRAM_ITERATIONS` and `AUTH_SCRAM_SALT_LENGTH`
  (4096 and 16 by default, as in PostgreSQL).

Edit `.env.users` (the users administration commands): the connection with the `gate_one_users` role,
`AUTH_LANG`, the same `AUTH_TOTP_KEY` as the server and, optionally, the SCRAM parameters.

### 4. Register the services

Each service is a client, and each API that accepts gate-one access tokens is a resource server.
They are registered with the `gate_one_apps` role: copy `install/example-client.sql`, replace the values
and run it with `psql -U gate_one_apps -d gate_one -v ON_ERROR_STOP=1 -f <file>`.

- `gate_one.clients`: the service, its secret and its URLs (callback, after logout, back-channel logout).
- `gate_one.resource_servers`: the API (its URL is the audience of the tokens), its scopes and the lifetime of its access tokens.
- `gate_one.client_resources`: which scopes of which API each service receives.

The service needs the discovery URL (`<AUTH_ISSUER>/.well-known/openid-configuration`), its `client_id` and its secret.

### 5. Create users

```sh
npm run create-user -- <username>
```

It asks for the given name, the family name, the email (optional) and the password.

Users are deactivated, not deleted (`update gate_one.users set active = false where username = ...`, with the
`gate_one_users` role). An inactive user cannot sign in, and a session already open gets no more tokens; the tokens
already issued remain valid until they expire.

### 6. Start

```sh
npm start
```

Without a signing key the server does not start. Expired sessions and codes are deleted every 10 minutes.

## Second factor

Users can have a second factor: a 6 digit code from an authenticator app (Microsoft Authenticator,
Google Authenticator, FreeOTP, ...), the standard TOTP (RFC 6238). An administrator enables it:

```sh
npm run enable-totp -- <username>
```

It shows a QR code; the user scans it with the app ("Add account" → "Other account") and types the first code,
which confirms it. From then on gate-one asks for the code after the password. When the user loses the phone,
an administrator removes it (with the remembered devices) and it can be enabled again:

```sh
npm run reset-totp -- <username>
```

- **Remembered devices.** After the code, the user can choose not to be asked again on that device for 30 days.
- **Services that require it.** A service asks for it with `acr_values=mfa`: a user without second factor is
  rejected (`access_denied`), and a session opened without it goes through the sign-in again.
  To require the code itself, not a remembered device, the service also sends `max_age` or `prompt=login`.
- **Tokens.** Like in Entra ID, the ID token says how the user signed in: `acr` is `pwd` or `mfa`, and `amr` is
  `["pwd"]`, `["pwd", "otp", "mfa"]` (code entered) or `["pwd", "mfa"]` (remembered device).

### Formats, for other tools that write users

A tool that writes `gate_one.users` directly (for example, an administration application) must use these formats:

- `verifier`: SCRAM-SHA-256 in the format of PostgreSQL's `pg_authid`
  (`SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, base64), computed from a printable ASCII password.
- `totp_secret`: the base32 TOTP secret encrypted with AES-256-GCM and `AUTH_TOTP_KEY`, stored as `v1:` followed by the
  base64 of the 12 byte IV, the 16 byte authentication tag and the ciphertext; the username (UTF-8) is the
  additional authenticated data. See `src/totp.ts`.

## Failed attempts

Wrong passwords and wrong codes count as failures. A username is locked for 15 minutes after 5 failures in a row
(a successful sign-in resets the count), and an IP address after 50 failures within 15 minutes.

## Not ready yet

- Running behind a reverse proxy with HTTPS: gate-one does not yet trust the `X-Forwarded-*` headers.
  Until then, behind a proxy every request comes from the proxy's address, so the limit by IP address counts
  all users together.
- Signing key rotation.
- User management other than `create-user` (which, for now, shows the password while it is typed).

## Tests

The tests need a PostgreSQL database whose name contains `test`, given by the `PG*` variables, because they drop and
recreate the `gate_one` schema. The connection must be a superuser's: the tests create the roles `gate_one_test_auth`,
`gate_one_test_apps` and `gate_one_test_users` (if they do not exist), check their permissions and read `pg_authid`.

```sh
PGDATABASE=gate_one_test npm test
```
