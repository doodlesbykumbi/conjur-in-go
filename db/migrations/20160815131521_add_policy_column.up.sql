-- Add policy_id column to track which policy created each record
-- Matches: conjur/db/migrate/20160815131521_add_policy_column.rb

ALTER TABLE roles ADD COLUMN policy_id text REFERENCES resources(resource_id) ON DELETE CASCADE;
ALTER TABLE roles ADD CONSTRAINT verify_policy_kind CHECK (kind(policy_id) = 'policy');

ALTER TABLE resources ADD COLUMN policy_id text REFERENCES resources(resource_id) ON DELETE CASCADE;
ALTER TABLE resources ADD CONSTRAINT verify_policy_kind CHECK (kind(policy_id) = 'policy');

ALTER TABLE role_memberships ADD COLUMN policy_id text REFERENCES resources(resource_id) ON DELETE CASCADE;
ALTER TABLE role_memberships ADD CONSTRAINT verify_policy_kind CHECK (kind(policy_id) = 'policy');

ALTER TABLE permissions ADD COLUMN policy_id text REFERENCES resources(resource_id) ON DELETE CASCADE;
ALTER TABLE permissions ADD CONSTRAINT verify_policy_kind CHECK (kind(policy_id) = 'policy');

ALTER TABLE annotations ADD COLUMN policy_id text REFERENCES resources(resource_id) ON DELETE CASCADE;
ALTER TABLE annotations ADD CONSTRAINT verify_policy_kind CHECK (kind(policy_id) = 'policy');
