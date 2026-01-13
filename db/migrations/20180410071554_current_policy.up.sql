-- Current policy tracking for policy versions
-- Matches: conjur/db/migrate/20180410071554_current_policy.rb

ALTER TABLE policy_versions ALTER COLUMN created_at TYPE timestamptz;

ALTER TABLE policy_versions ADD COLUMN finished_at timestamptz;
CREATE INDEX policy_versions_finished_at_idx ON policy_versions(finished_at);
ALTER TABLE policy_versions ADD CONSTRAINT created_before_finish CHECK (created_at <= finished_at);

CREATE OR REPLACE FUNCTION policy_versions_finish()
  RETURNS trigger
LANGUAGE plpgsql AS $$
  BEGIN
    UPDATE policy_versions pv
      SET finished_at = clock_timestamp()
      WHERE finished_at IS NULL;
    RETURN new;
  END;
$$;

-- Deferred constraint trigger will run on transaction commit.
-- This enforces that loading policy version has to happen inside the 
-- same transaction that created it, and that finished_at is never NULL
-- once the transaction is committed.
CREATE CONSTRAINT TRIGGER finish_current
  AFTER INSERT ON policy_versions
  INITIALLY DEFERRED
  FOR EACH ROW
  WHEN (NEW.finished_at IS NULL)
  EXECUTE PROCEDURE policy_versions_finish();

-- If any version is current while creating new one, finalize it, so only
-- a single policy is current at any given time.
CREATE TRIGGER only_one_current
  BEFORE INSERT ON policy_versions
  FOR EACH ROW
  EXECUTE PROCEDURE policy_versions_finish();

CREATE FUNCTION current_policy_version()
  RETURNS SETOF policy_versions
  SET search_path FROM CURRENT
  LANGUAGE sql STABLE AS $$
    SELECT * FROM policy_versions WHERE finished_at IS NULL $$;
