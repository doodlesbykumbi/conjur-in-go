-- Revert policy log trigger bypass
-- Matches: conjur/db/migrate/201808131137612_policy_log_trigger_bypass.rb

-- Revert trigger functions to original versions (without bypass)
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

DROP FUNCTION IF EXISTS policy_log_record(text, text[], hstore, text, int, text);
DROP TYPE policy_log_record;
