-- Host factory tokens for automated host enrollment
-- Matches: conjur/db/migrate/20170404125612_create_host_factories.rb

CREATE TABLE IF NOT EXISTS host_factory_tokens (
    token_sha256 varchar(64) PRIMARY KEY,
    token bytea NOT NULL,
    resource_id text NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    cidr cidr[] NOT NULL DEFAULT '{}',
    expiration timestamp
);
