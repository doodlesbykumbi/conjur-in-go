-- Policy permission functions for checking permissions on policy hierarchies
-- Matches: conjur/db/migrate/20231026155235_create_policy_permission_functions.rb

-- Returns a list of all resources in the database which have this policy id
-- as a direct or eventual parent. (This includes the policy resource itself)
CREATE OR REPLACE FUNCTION policy_resources(policy_id text) RETURNS TABLE(resource_id text, policy_id text)
  LANGUAGE sql STABLE STRICT
  AS $_$
      SELECT resource_id, policy_id FROM resources
        WHERE position(concat(identifier($1), '/') in identifier(resource_id)) = 1
        OR resource_id = $1;
  $_$;

-- Determines if a given role has update permissions on the given policy
-- and all of the child resources of that policy.
CREATE OR REPLACE FUNCTION policy_permissions(role_id text, permission text, policy_id text) RETURNS boolean
  LANGUAGE sql STABLE STRICT
  AS $_$
    SELECT bool_and(is_role_allowed_to($1, $2, resource_id))
    FROM policy_resources($3);
  $_$;
