-- Remove cascade delete for credentials
-- Matches: conjur/db/migrate/20210514185315_role_cascade_delete.rb

ALTER TABLE credentials DROP CONSTRAINT credentials_role_id_fkey;
