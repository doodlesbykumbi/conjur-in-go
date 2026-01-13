-- Credentials table for API keys and encrypted hashes
-- Matches: conjur/db/migrate/20160628222441_create_credentials.rb
-- Note: role_id is NOT an FK because credentials won't be dropped when RBAC is rebuilt

CREATE TABLE IF NOT EXISTS credentials (
    role_id text PRIMARY KEY,
    client_id text REFERENCES roles(role_id) ON DELETE CASCADE,
    api_key bytea,
    encrypted_hash bytea,
    expiration timestamp
);
