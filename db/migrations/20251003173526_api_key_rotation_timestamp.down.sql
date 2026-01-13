-- Remove updated_at column from credentials
-- Matches: conjur/db/migrate/20251003173526_api_key_rotation_timestamp.rb

ALTER TABLE credentials DROP COLUMN updated_at;
