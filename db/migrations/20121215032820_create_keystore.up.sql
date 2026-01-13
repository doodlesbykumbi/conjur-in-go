-- Slosilo keystore for encrypted key storage
-- Matches: conjur/db/migrate/20121215032820_create_keystore.rb (via slosilo gem)

CREATE TABLE IF NOT EXISTS slosilo_keystore (
    id text PRIMARY KEY,
    key bytea NOT NULL,
    fingerprint text NOT NULL UNIQUE
);
