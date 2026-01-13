-- Policy log for tracking changes during policy loading
-- Matches: conjur/db/migrate/20180410092453_policy_log.rb

CREATE TYPE policy_log_op AS ENUM ('INSERT', 'DELETE', 'UPDATE');
CREATE TYPE policy_log_kind AS ENUM ('roles', 'role_memberships', 'resources', 'permissions', 'annotations');
CREATE EXTENSION IF NOT EXISTS hstore;

CREATE TABLE policy_log (
    policy_id text NOT NULL,
    version integer NOT NULL,
    operation policy_log_op NOT NULL,
    kind policy_log_kind NOT NULL,
    subject hstore NOT NULL,
    at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (policy_id, version) REFERENCES policy_versions(resource_id, version) ON DELETE CASCADE
);
CREATE INDEX policy_log_policy_id_version_idx ON policy_log(policy_id, version);

-- Trigger function for roles
CREATE OR REPLACE FUNCTION policy_log_roles() RETURNS TRIGGER AS $$
  DECLARE
    subject roles;
    current policy_versions;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;
    current = current_policy_version();
    IF current.resource_id = subject.policy_id THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        current.resource_id, current.version,
        TG_OP::policy_log_op, 'roles'::policy_log_kind,
        slice(hstore(subject), ARRAY['role_id'])
      ;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER policy_log
  AFTER INSERT OR UPDATE ON roles
  FOR EACH ROW
  WHEN (NEW.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_roles();

CREATE TRIGGER policy_log_d
  AFTER DELETE ON roles
  FOR EACH ROW
  WHEN (OLD.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_roles();

-- Trigger function for role_memberships
CREATE OR REPLACE FUNCTION policy_log_role_memberships() RETURNS TRIGGER AS $$
  DECLARE
    subject role_memberships;
    current policy_versions;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;
    current = current_policy_version();
    IF current.resource_id = subject.policy_id THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        current.resource_id, current.version,
        TG_OP::policy_log_op, 'role_memberships'::policy_log_kind,
        slice(hstore(subject), ARRAY['role_id', 'member_id', 'admin_option'])
      ;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER policy_log
  AFTER INSERT OR UPDATE ON role_memberships
  FOR EACH ROW
  WHEN (NEW.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_role_memberships();

CREATE TRIGGER policy_log_d
  AFTER DELETE ON role_memberships
  FOR EACH ROW
  WHEN (OLD.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_role_memberships();

-- Trigger function for resources
CREATE OR REPLACE FUNCTION policy_log_resources() RETURNS TRIGGER AS $$
  DECLARE
    subject resources;
    current policy_versions;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;
    current = current_policy_version();
    IF current.resource_id = subject.policy_id THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        current.resource_id, current.version,
        TG_OP::policy_log_op, 'resources'::policy_log_kind,
        slice(hstore(subject), ARRAY['resource_id'])
      ;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER policy_log
  AFTER INSERT OR UPDATE ON resources
  FOR EACH ROW
  WHEN (NEW.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_resources();

CREATE TRIGGER policy_log_d
  AFTER DELETE ON resources
  FOR EACH ROW
  WHEN (OLD.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_resources();

-- Trigger function for permissions
CREATE OR REPLACE FUNCTION policy_log_permissions() RETURNS TRIGGER AS $$
  DECLARE
    subject permissions;
    current policy_versions;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;
    current = current_policy_version();
    IF current.resource_id = subject.policy_id THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        current.resource_id, current.version,
        TG_OP::policy_log_op, 'permissions'::policy_log_kind,
        slice(hstore(subject), ARRAY['privilege', 'resource_id', 'role_id'])
      ;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER policy_log
  AFTER INSERT OR UPDATE ON permissions
  FOR EACH ROW
  WHEN (NEW.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_permissions();

CREATE TRIGGER policy_log_d
  AFTER DELETE ON permissions
  FOR EACH ROW
  WHEN (OLD.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_permissions();

-- Trigger function for annotations
CREATE OR REPLACE FUNCTION policy_log_annotations() RETURNS TRIGGER AS $$
  DECLARE
    subject annotations;
    current policy_versions;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;
    current = current_policy_version();
    IF current.resource_id = subject.policy_id THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        current.resource_id, current.version,
        TG_OP::policy_log_op, 'annotations'::policy_log_kind,
        slice(hstore(subject), ARRAY['resource_id', 'name'])
      ;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE TRIGGER policy_log
  AFTER INSERT OR UPDATE ON annotations
  FOR EACH ROW
  WHEN (NEW.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_annotations();

CREATE TRIGGER policy_log_d
  AFTER DELETE ON annotations
  FOR EACH ROW
  WHEN (OLD.policy_id IS NOT NULL)
  EXECUTE PROCEDURE policy_log_annotations();
