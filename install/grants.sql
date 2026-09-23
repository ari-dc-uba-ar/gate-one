-- Minimum permissions for the role gate-one connects with. Run by an administrator, for example:
--     psql -v ON_ERROR_STOP=1 -v app_role=gate_one_app -f install/grants.sql
-- The role does not need permission to create or alter objects.

grant usage on schema gate_one to :"app_role";
grant select, insert on gate_one.users to :"app_role";
grant select, insert on gate_one.signing_keys to :"app_role";
grant select, insert, update, delete on gate_one.oidc_models to :"app_role";
