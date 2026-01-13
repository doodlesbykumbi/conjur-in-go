-- Policy versions table for tracking policy changes
-- Matches: conjur/db/migrate/20160815131453_create_policy_version.rb

CREATE TABLE IF NOT EXISTS policy_versions (
    resource_id text NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    role_id text NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    version integer NOT NULL,
    created_at timestamp NOT NULL DEFAULT transaction_timestamp(),
    policy_text text NOT NULL,
    policy_sha256 text NOT NULL,
    PRIMARY KEY (resource_id, version)
);

-- Auto-increment version trigger
CREATE OR REPLACE FUNCTION policy_versions_next_version() RETURNS TRIGGER
    LANGUAGE plpgsql STABLE STRICT
AS $$
DECLARE
    next_version integer;
BEGIN
    SELECT coalesce(max(version), 0) + 1 INTO next_version
        FROM policy_versions 
        WHERE resource_id = NEW.resource_id;

    NEW.version = next_version;
    RETURN NEW;
END
$$;

CREATE TRIGGER policy_versions_version
BEFORE INSERT
ON policy_versions
FOR EACH ROW
EXECUTE PROCEDURE policy_versions_next_version();
