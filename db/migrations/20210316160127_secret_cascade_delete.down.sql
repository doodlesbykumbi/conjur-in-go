-- Remove cascade delete for secrets
-- Matches: conjur/db/migrate/20210316160127_secret_cascade_delete.rb

DROP INDEX secrets_resource_id_idx;
ALTER TABLE secrets DROP CONSTRAINT secrets_resource_id_fkey;
