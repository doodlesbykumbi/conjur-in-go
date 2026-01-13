-- Remove policy_id column from tables
-- Matches: conjur/db/migrate/20160815131521_add_policy_column.rb

ALTER TABLE annotations DROP CONSTRAINT verify_policy_kind;
ALTER TABLE annotations DROP COLUMN policy_id;

ALTER TABLE permissions DROP CONSTRAINT verify_policy_kind;
ALTER TABLE permissions DROP COLUMN policy_id;

ALTER TABLE role_memberships DROP CONSTRAINT verify_policy_kind;
ALTER TABLE role_memberships DROP COLUMN policy_id;

ALTER TABLE resources DROP CONSTRAINT verify_policy_kind;
ALTER TABLE resources DROP COLUMN policy_id;

ALTER TABLE roles DROP CONSTRAINT verify_policy_kind;
ALTER TABLE roles DROP COLUMN policy_id;
