-- Resources table for protected resources (variables, webservices, etc.)
-- Matches: conjur/db/migrate/20160628212349_create_resources.rb

CREATE TABLE IF NOT EXISTS resources (
    resource_id text PRIMARY KEY,
    owner_id text NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    created_at timestamp NOT NULL DEFAULT transaction_timestamp()
);
