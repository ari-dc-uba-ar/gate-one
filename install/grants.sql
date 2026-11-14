-- Permissions of the three roles, one per service; none can create or alter objects.
-- Run by an administrator, for example:
--     psql -v ON_ERROR_STOP=1 -v auth_role=gate_one_auth -v apps_role=gate_one_apps -v user_admin_role=gate_one_user_admin -f install/grants.sql
-- The signing keys are created by an administrator (npm run create-signing-key), not by these roles.

grant usage on schema gate_one to :"auth_role", :"apps_role", :"user_admin_role";

-- 1. Authentication (the gate-one server): reads users, clients and signing keys; writes only its own records.
grant select (username, verifier, given_name, family_name, email, email_verified, totp_secret, totp_last_step, active)
    on gate_one.users to :"auth_role";
grant update (totp_last_step) on gate_one.users to :"auth_role";
grant select, insert, delete on gate_one.trusted_devices to :"auth_role";
grant select, insert, update, delete on gate_one.auth_failures to :"auth_role";
grant select, insert, update, delete on gate_one.oidc_models to :"auth_role";
grant select on gate_one.signing_keys to :"auth_role";
grant select on gate_one.clients, gate_one.resource_servers, gate_one.client_resources to :"auth_role";

-- 2. Applications (systems administration): registers clients, APIs and their permissions.
grant select, insert, update, delete on gate_one.clients, gate_one.resource_servers, gate_one.client_resources to :"apps_role";

-- 3. Users (users administration): creates users, changes their data, passwords, second factor and active flag.
-- Users are deactivated, not deleted. Resetting the second factor also forgets the remembered devices.
grant select, insert, update on gate_one.users to :"user_admin_role";
grant select (username), delete on gate_one.trusted_devices to :"user_admin_role";
