-- Drop slosilo cache clear notification trigger
-- Matches: conjur/db/migrate/20251212000000_clear_slosilo_cache_trigger.rb

DROP TRIGGER IF EXISTS slosilo_cache_clear_notify ON slosilo_keystore;
DROP FUNCTION IF EXISTS slosilo_cache_notify();
