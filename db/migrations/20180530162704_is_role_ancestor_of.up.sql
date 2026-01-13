-- Function to check if a role is an ancestor of another role
-- Matches: conjur/db/migrate/20180530162704_is_role_ancestor_of.rb

CREATE FUNCTION is_role_ancestor_of(role_id text, other_id text)
   RETURNS boolean
   LANGUAGE sql
   STABLE STRICT
AS $$
  SELECT COUNT(*) > 0 FROM (
    WITH RECURSIVE m(id) AS (
      SELECT $2
      UNION ALL
      SELECT role_id FROM role_memberships rm, m WHERE member_id = id
    )
    SELECT true FROM m WHERE id = $1 LIMIT 1
  )_
$$;
