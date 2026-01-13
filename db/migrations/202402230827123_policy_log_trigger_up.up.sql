-- Update policy log triggers to handle nested policies
-- Matches: conjur/db/migrate/202402230827123_policy_log_trigger_up.rb

CREATE OR REPLACE FUNCTION current_policy_version_no_policy_text()
RETURNS SETOF policy_versions
SET search_path FROM CURRENT
LANGUAGE sql STABLE AS $$
  SELECT resource_id, role_id, "version", created_at, NULL as policy_text, policy_sha256, finished_at, client_ip 
  FROM policy_versions WHERE finished_at IS NULL
$$;

CREATE OR REPLACE FUNCTION policy_log_roles() RETURNS TRIGGER AS $$
  DECLARE
    subject roles;
    current policy_versions;
    skip boolean;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;

    BEGIN
        skip := current_setting('conjur.skip_insert_policy_log_trigger');
    EXCEPTION WHEN OTHERS THEN
        skip := false;
    END;

    IF skip THEN
      RETURN subject;
    END IF;

    current = current_policy_version_no_policy_text();
    IF current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%' THEN
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
          )).*;
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
    skip boolean;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;

    BEGIN
        skip := current_setting('conjur.skip_insert_policy_log_trigger');
    EXCEPTION WHEN OTHERS THEN
        skip := false;
    END;

    IF skip THEN
      RETURN subject;
    END IF;

    current = current_policy_version_no_policy_text();
    IF current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%' THEN
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
          )).*;
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
    skip boolean;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;

    BEGIN
        skip := current_setting('conjur.skip_insert_policy_log_trigger');
    EXCEPTION WHEN OTHERS THEN
        skip := false;
    END;

    IF skip THEN
      RETURN subject;
    END IF;

    current = current_policy_version_no_policy_text();
    IF current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%' THEN
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
          )).*;
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
    skip boolean;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;

    BEGIN
        skip := current_setting('conjur.skip_insert_policy_log_trigger');
    EXCEPTION WHEN OTHERS THEN
        skip := false;
    END;

    IF skip THEN
      RETURN subject;
    END IF;

    current = current_policy_version_no_policy_text();
    IF current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%' THEN
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
          )).*;
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
    skip boolean;
  BEGIN
    IF (TG_OP = 'DELETE') THEN
      subject := OLD;
    ELSE
      subject := NEW;
    END IF;

    BEGIN
        skip := current_setting('conjur.skip_insert_policy_log_trigger');
    EXCEPTION WHEN OTHERS THEN
        skip := false;
    END;

    IF skip THEN
      RETURN subject;
    END IF;

    current = current_policy_version_no_policy_text();
    IF current.resource_id = subject.policy_id OR subject.policy_id LIKE current.resource_id || '/%' THEN
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
          )).*;
    ELSE
      RAISE WARNING 'modifying data outside of policy load: %', subject.policy_id;
    END IF;
    RETURN subject;
  END;
$$ LANGUAGE plpgsql
SET search_path FROM CURRENT;
