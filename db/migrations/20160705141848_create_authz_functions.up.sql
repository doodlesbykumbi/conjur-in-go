-- Authorization functions for RBAC
-- Matches: conjur/db/migrate/20160705141848_create_authz_functions.rb

-- Get all roles that a role is a member of (recursive)
CREATE OR REPLACE FUNCTION all_roles(role_id text) RETURNS TABLE(role_id text, admin_option boolean)
LANGUAGE sql STABLE STRICT ROWS 2376
AS $_$
    WITH RECURSIVE m(role_id, admin_option) AS (
        SELECT $1, 't'::boolean
        UNION
        SELECT ms.role_id, ms.admin_option FROM role_memberships ms, m
        WHERE member_id = m.role_id
    ) SELECT role_id, bool_or(admin_option) FROM m GROUP BY role_id
$_$;

-- Check if a role is allowed to perform a privilege on a resource
CREATE OR REPLACE FUNCTION is_role_allowed_to(role_id text, privilege text, resource_id text) RETURNS boolean
LANGUAGE sql STABLE STRICT
AS $_$
    WITH 
        all_roles AS (SELECT role_id FROM all_roles($1))
    SELECT COUNT(*) > 0 FROM (
        SELECT 1 FROM all_roles, resources 
        WHERE owner_id = role_id
        AND resources.resource_id = $3
    UNION
        SELECT 1 FROM ( all_roles JOIN permissions USING ( role_id ) ) JOIN resources USING ( resource_id )
        WHERE privilege = $2
        AND resources.resource_id = $3
    ) AS _
$_$;

-- Get all roles that can perform a privilege on a resource
CREATE OR REPLACE FUNCTION roles_that_can(permission text, resource_id text) RETURNS SETOF roles
LANGUAGE sql STABLE STRICT ROWS 10
AS $_$
    WITH RECURSIVE allowed_roles(role_id) AS (
        SELECT role_id FROM permissions
        WHERE privilege = $1
            AND resource_id = $2
        UNION SELECT owner_id FROM resources
            WHERE resources.resource_id = $2
        UNION SELECT member_id AS role_id FROM role_memberships ms NATURAL JOIN allowed_roles
    ) SELECT DISTINCT r.* FROM roles r NATURAL JOIN allowed_roles;
$_$;
