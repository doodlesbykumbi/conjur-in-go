-- Slosilo cache clear notification trigger
-- Matches: conjur/db/migrate/20251212000000_clear_slosilo_cache_trigger.rb

CREATE OR REPLACE FUNCTION slosilo_cache_notify()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_notify('clear_slosilo_cache', '');
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS slosilo_cache_clear_notify ON slosilo_keystore;
CREATE TRIGGER slosilo_cache_clear_notify
AFTER UPDATE OR DELETE ON slosilo_keystore
FOR EACH STATEMENT
EXECUTE FUNCTION slosilo_cache_notify();
