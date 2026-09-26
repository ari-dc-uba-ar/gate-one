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

## Not ready yet

- Running behind a reverse proxy with HTTPS: gate-one does not yet trust the `X-Forwarded-*` headers.
- Limiting repeated login attempts.
- Signing key rotation.
- User management other than `create-user` (which, for now, shows the password while it is typed).

## Tests

The tests need a PostgreSQL database whose name contains `test`, given by the `PG*` variables, because they drop and
recreate the `gate_one` schema. One test reads `pg_authid`, so the role must be a superuser.

```sh
PGDATABASE=gate_one_test npm test
```
