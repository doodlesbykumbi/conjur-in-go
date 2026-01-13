-- Remove CIDR restriction column from credentials
-- Matches: conjur/db/migrate/20180705192211_credentials_restricted_to_cidr.rb

ALTER TABLE credentials DROP COLUMN restricted_to;
