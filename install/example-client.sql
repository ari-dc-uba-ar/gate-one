-- Registers one-entrance (the example service) as a client and as an API, for development.
-- Replace the secret (generate one with: openssl rand -base64 32) and the URLs. Run by an administrator:
--     psql -v ON_ERROR_STOP=1 -f install/example-client.sql

insert into gate_one.clients (client_id, client_secret, redirect_uris, post_logout_redirect_uris, backchannel_logout_uri)
    values ('one-entrance', 'replace-with-a-random-secret',
        array['http://localhost:3004/callback'],
        array['http://localhost:3004/'],
        'http://localhost:3004/backchannel-logout');

insert into gate_one.resource_servers (resource, scopes, access_token_ttl)
    values ('http://localhost:3004/api', array['perfil:leer'], 600);

insert into gate_one.client_resources (client_id, resource, scopes)
    values ('one-entrance', 'http://localhost:3004/api', array['perfil:leer']);
