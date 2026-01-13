-- Authenticator configuration table
-- Matches: conjur/db/migrate/20191112025200_create_authenticator_config.rb

CREATE TABLE authenticator_configs (
    id SERIAL PRIMARY KEY,
    resource_id text NOT NULL UNIQUE REFERENCES resources(resource_id) ON DELETE CASCADE,
    enabled boolean NOT NULL DEFAULT false
);
