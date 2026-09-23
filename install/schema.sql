-- gate-one schema. Run by an administrator (not by the gate-one role), for example:
--     psql -v ON_ERROR_STOP=1 -f install/schema.sql
-- Then give the gate-one role its permissions with install/grants.sql.

create schema gate_one;

-- Usernames are limited to printable ASCII (see src/users.ts).
-- The profile columns are the minimum for the standard claims of the profile and email scopes
-- (username is preferred_username; name is given_name followed by family_name).
create table gate_one.users (
    username text primary key check (username ~ '^[ -~]+$'),
    verifier text not null check (verifier like 'SCRAM-SHA-256$%'),
    given_name text not null check (btrim(given_name) <> ''),
    family_name text not null check (btrim(family_name) <> ''),
    email text check (email ~ '^[^@\s]+@[^@\s]+$'),
    email_verified boolean not null default false,
    created_at timestamptz not null default current_timestamp
);

-- Registered applications (OIDC clients), like Entra ID's app registrations.
-- client_secret is kept readable because client_secret_basic authentication compares it.
create table gate_one.clients (
    client_id text primary key,
    client_secret text not null,
    redirect_uris text[] not null check (cardinality(redirect_uris) > 0),
    post_logout_redirect_uris text[] not null default '{}',
    backchannel_logout_uri text,
    created_at timestamptz not null default current_timestamp
);

-- APIs that accept gate-one access tokens. resource is the audience of the tokens (RFC 8707).
create table gate_one.resource_servers (
    resource text primary key,
    scopes text[] not null check (cardinality(scopes) > 0),
    access_token_ttl integer not null default 600 check (access_token_ttl > 0),
    created_at timestamptz not null default current_timestamp
);

-- Which scopes of which API each client receives, already consented (like Entra ID's admin consent).
-- Only the scopes that the resource server defines are granted.
create table gate_one.client_resources (
    client_id text not null references gate_one.clients,
    resource text not null references gate_one.resource_servers,
    scopes text[] not null check (cardinality(scopes) > 0),
    primary key (client_id, resource)
);

-- Signing keys published in the JWKS. The jwk column holds the private key.
create table gate_one.signing_keys (
    kid text primary key,
    jwk jsonb not null,
    created_at timestamptz not null default current_timestamp
);

-- Everything oidc-provider stores: sessions, interactions, grants, codes, tokens.
-- One row per model and id; grant_id, user_code and uid are the indexes the adapter looks up by.
create table gate_one.oidc_models (
    model text not null,
    id text not null,
    payload jsonb not null,
    grant_id text,
    user_code text,
    uid text,
    expires_at timestamptz,
    primary key (model, id)
);

create index oidc_models_grant_id on gate_one.oidc_models (grant_id) where grant_id is not null;
create index oidc_models_user_code on gate_one.oidc_models (user_code) where user_code is not null;
create index oidc_models_uid on gate_one.oidc_models (uid) where uid is not null;
create index oidc_models_expires_at on gate_one.oidc_models (expires_at) where expires_at is not null;
