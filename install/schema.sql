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
