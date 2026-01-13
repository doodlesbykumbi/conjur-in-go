-- Remove client IP column from policy versions
-- Matches: conjur/db/migrate/20200605203735_add_policy_version_client_ip.rb

ALTER TABLE policy_versions DROP COLUMN client_ip;
