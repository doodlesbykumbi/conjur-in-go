-- Add expiration column to secrets
-- Matches: conjur/db/migrate/20180508164825_add_expiration.rb

ALTER TABLE secrets ADD COLUMN expires_at timestamp;
