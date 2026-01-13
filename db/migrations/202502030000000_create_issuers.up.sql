-- Issuers table for JWT/OIDC token issuers
-- Matches: conjur/db/migrate/202502030000000_create_issuers.rb

CREATE TABLE issuers (
    issuer_id text,
    account text,
    issuer_type text NOT NULL,
    max_ttl integer NOT NULL,
    data bytea,
    created_at timestamp NOT NULL DEFAULT transaction_timestamp(),
    modified_at timestamp NOT NULL,
    policy_id text NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    PRIMARY KEY (account, issuer_id)
);
