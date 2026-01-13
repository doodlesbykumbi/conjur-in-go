-- Remove API keys for non-users and non-hosts
-- Matches: conjur/db/migrate/20211114091827_remove_unused_api_keys.rb

DELETE FROM credentials
WHERE kind(role_id) NOT IN ('user', 'host');
