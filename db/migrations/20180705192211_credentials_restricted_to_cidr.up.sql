-- Add CIDR restriction column to credentials
-- Matches: conjur/db/migrate/20180705192211_credentials_restricted_to_cidr.rb

ALTER TABLE credentials ADD COLUMN restricted_to cidr[] NOT NULL DEFAULT '{}';
