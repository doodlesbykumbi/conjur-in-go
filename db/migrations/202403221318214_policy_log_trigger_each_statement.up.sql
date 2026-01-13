-- Update policy log triggers to use statement-level triggers for better performance
-- Matches: conjur/db/migrate/202403221318214_policy_log_trigger_each_statement.rb

-- Drop existing row-level triggers first
DROP TRIGGER IF EXISTS policy_log ON roles;
DROP TRIGGER IF EXISTS policy_log_d ON roles;
DROP TRIGGER IF EXISTS policy_log ON role_memberships;
DROP TRIGGER IF EXISTS policy_log_d ON role_memberships;
DROP TRIGGER IF EXISTS policy_log ON resources;
DROP TRIGGER IF EXISTS policy_log_d ON resources;
DROP TRIGGER IF EXISTS policy_log ON permissions;
DROP TRIGGER IF EXISTS policy_log_d ON permissions;
DROP TRIGGER IF EXISTS policy_log ON annotations;
DROP TRIGGER IF EXISTS policy_log_d ON annotations;

-- Roles
CREATE OR REPLACE FUNCTION policy_log_roles() RETURNS TRIGGER AS $$
  DECLARE
    current policy_versions;
  BEGIN
    current = current_policy_version_no_policy_text();
    IF TG_OP = 'DELETE' THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'roles',
            ARRAY['role_id'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM old_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    ELSE
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'roles',
            ARRAY['role_id'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM new_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE TRIGGER policy_log
  AFTER INSERT ON roles
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_roles();

CREATE OR REPLACE TRIGGER policy_log_u
  AFTER UPDATE ON roles
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_roles();

CREATE OR REPLACE TRIGGER policy_log_d
  AFTER DELETE ON roles
  REFERENCING OLD TABLE AS old_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_roles();

-- Role memberships
CREATE OR REPLACE FUNCTION policy_log_role_memberships() RETURNS TRIGGER AS $$
  DECLARE
    current policy_versions;
  BEGIN
    current = current_policy_version_no_policy_text();
    IF TG_OP = 'DELETE' THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'role_memberships',
            ARRAY['role_id', 'member_id', 'admin_option'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM old_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    ELSE
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'role_memberships',
            ARRAY['role_id', 'member_id', 'admin_option'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM new_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE TRIGGER policy_log
  AFTER INSERT ON role_memberships
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_role_memberships();

CREATE OR REPLACE TRIGGER policy_log_u
  AFTER UPDATE ON role_memberships
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_role_memberships();

CREATE OR REPLACE TRIGGER policy_log_d
  AFTER DELETE ON role_memberships
  REFERENCING OLD TABLE AS old_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_role_memberships();

-- Resources
CREATE OR REPLACE FUNCTION policy_log_resources() RETURNS TRIGGER AS $$
  DECLARE
    current policy_versions;
  BEGIN
    current = current_policy_version_no_policy_text();
    IF TG_OP = 'DELETE' THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'resources',
            ARRAY['resource_id'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM old_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    ELSE
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'resources',
            ARRAY['resource_id'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM new_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE TRIGGER policy_log
  AFTER INSERT ON resources
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_resources();

CREATE OR REPLACE TRIGGER policy_log_u
  AFTER UPDATE ON resources
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_resources();

CREATE OR REPLACE TRIGGER policy_log_d
  AFTER DELETE ON resources
  REFERENCING OLD TABLE AS old_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_resources();

-- Permissions
CREATE OR REPLACE FUNCTION policy_log_permissions() RETURNS TRIGGER AS $$
  DECLARE
    current policy_versions;
  BEGIN
    current = current_policy_version_no_policy_text();
    IF TG_OP = 'DELETE' THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'permissions',
            ARRAY['resource_id', 'role_id', 'privilege'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM old_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    ELSE
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'permissions',
            ARRAY['resource_id', 'role_id', 'privilege'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM new_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE TRIGGER policy_log
  AFTER INSERT ON permissions
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_permissions();

CREATE OR REPLACE TRIGGER policy_log_u
  AFTER UPDATE ON permissions
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_permissions();

CREATE OR REPLACE TRIGGER policy_log_d
  AFTER DELETE ON permissions
  REFERENCING OLD TABLE AS old_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_permissions();

-- Annotations
CREATE OR REPLACE FUNCTION policy_log_annotations() RETURNS TRIGGER AS $$
  DECLARE
    current policy_versions;
  BEGIN
    current = current_policy_version_no_policy_text();
    IF TG_OP = 'DELETE' THEN
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'annotations',
            ARRAY['resource_id', 'name'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM old_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    ELSE
      INSERT INTO policy_log(
        policy_id, version,
        operation, kind,
        subject)
      SELECT
        (policy_log_record(
            'annotations',
            ARRAY['resource_id', 'name'],
            hstore(subject),
            current.resource_id,
            current.version,
            TG_OP
          )).*
      FROM new_table AS subject
      WHERE current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%';
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;

CREATE OR REPLACE TRIGGER policy_log
  AFTER INSERT ON annotations
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_annotations();

CREATE OR REPLACE TRIGGER policy_log_u
  AFTER UPDATE ON annotations
  REFERENCING NEW TABLE AS new_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_annotations();

CREATE OR REPLACE TRIGGER policy_log_d
  AFTER DELETE ON annotations
  REFERENCING OLD TABLE AS old_table
  FOR EACH STATEMENT
  EXECUTE PROCEDURE policy_log_annotations();
