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

Run as a PostgreSQL administrator (not as the role gate-one will use):

```sh
psql -U postgres -c "create role gate_one_app login"
psql -U postgres -c "\password gate_one_app"
psql -U postgres -c "create database gate_one"
psql -U postgres -d gate_one -v ON_ERROR_STOP=1 -f install/schema.sql
psql -U postgres -d gate_one -v ON_ERROR_STOP=1 -v app_role=gate_one_app -f install/grants.sql
```

`install/schema.sql` creates the `gate_one` schema. `install/grants.sql` gives the role only the permissions it needs:
it cannot create or alter objects. Use a database (or cluster) of its own: it holds the password verifiers and the client secrets.

### 3. Configure

```sh
cp .env.example .env
```

Edit `.env`:

- `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`: the connection (standard PostgreSQL variables).
- `AUTH_ISSUER`: the public URL of gate-one. It is part of every token, so it must not change once services use it.
- `AUTH_PORT`: the port it listens on.
- `AUTH_COOKIE_KEYS`: cookie signing keys, comma separated. Generate each one with `openssl rand -base64 32`.
- `AUTH_TOTP_KEY`: key that encrypts the second factor secrets, generated with `openssl rand -base64 32`.
  Keep it out of the database (and of its backups): if it is lost or changed, every user must enable the second factor again.
- `AUTH_LANG`: language of the pages and messages, `en` (default) or `es`.
- Optional: `AUTH_SESSION_TTL` (seconds, 8 hours by default), `AUTH_SCRAM_ITERATIONS` and `AUTH_SCRAM_SALT_LENGTH`
  (4096 and 16 by default, as in PostgreSQL).

### 4. Register the services

Each service is a client, and each API that accepts gate-one access tokens is a resource server.
They are registered in the database by an administrator: copy `install/example-client.sql`, replace the values
and run it with `psql -U postgres -d gate_one -v ON_ERROR_STOP=1 -f <file>`.

- `gate_one.clients`: the service, its secret and its URLs (callback, after logout, back-channel logout).
- `gate_one.resource_servers`: the API (its URL is the audience of the tokens), its scopes and the lifetime of its access tokens.
- `gate_one.client_resources`: which scopes of which API each service receives.

The service needs the discovery URL (`<AUTH_ISSUER>/.well-known/openid-configuration`), its `client_id` and its secret.

### 5. Create users

```sh
npm run create-user -- <username>
```

It asks for the given name, the family name, the email (optional) and the password.

### 6. Start

```sh
npm start
```

The signing key is generated and stored in the database the first time. Expired sessions and codes are deleted every 10 minutes.

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
recreate the `gate_one` schema. One test reads `pg_authid`, so the role must be a superuser.

```sh
PGDATABASE=gate_one_test npm test
```
