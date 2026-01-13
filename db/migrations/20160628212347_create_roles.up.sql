-- Roles table for identity/principal storage
-- Matches: conjur/db/migrate/20160628212347_create_roles.rb

CREATE TABLE IF NOT EXISTS roles (
    role_id text PRIMARY KEY,
    created_at timestamp NOT NULL DEFAULT transaction_timestamp()
);
