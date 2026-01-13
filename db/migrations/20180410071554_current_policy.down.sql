-- Remove current policy tracking
-- Matches: conjur/db/migrate/20180410071554_current_policy.rb

DROP FUNCTION current_policy_version();
DROP TRIGGER finish_current ON policy_versions;
DROP TRIGGER only_one_current ON policy_versions;
DROP FUNCTION policy_versions_finish();

ALTER TABLE policy_versions DROP CONSTRAINT created_before_finish;
DROP INDEX policy_versions_finished_at_idx;
ALTER TABLE policy_versions DROP COLUMN finished_at;
ALTER TABLE policy_versions ALTER COLUMN created_at TYPE timestamp;
