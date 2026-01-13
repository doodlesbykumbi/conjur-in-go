-- Secrets table for versioned encrypted secret values
-- Matches: conjur/db/migrate/20160630172059_create_secrets.rb
-- Note: resource_id is NOT an FK because secrets won't be dropped when RBAC is rebuilt

CREATE TABLE IF NOT EXISTS secrets (
    resource_id text NOT NULL,
    version integer NOT NULL,
    value bytea NOT NULL,
    PRIMARY KEY (resource_id, version)
);

-- Auto-increment version trigger (matches Functions.create_version_trigger_sql)
CREATE OR REPLACE FUNCTION secrets_next_version() RETURNS TRIGGER
    LANGUAGE plpgsql STABLE STRICT
AS $$
DECLARE
    next_version integer;
BEGIN
    SELECT coalesce(max(version), 0) + 1 INTO next_version
        FROM secrets 
        WHERE resource_id = NEW.resource_id;

    NEW.version = next_version;
    RETURN NEW;
END
$$;

CREATE TRIGGER secrets_version
BEFORE INSERT
ON secrets
FOR EACH ROW
EXECUTE PROCEDURE secrets_next_version();
