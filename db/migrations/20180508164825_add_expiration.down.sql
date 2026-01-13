-- Remove expiration column from secrets
-- Matches: conjur/db/migrate/20180508164825_add_expiration.rb

ALTER TABLE secrets DROP COLUMN expires_at;
