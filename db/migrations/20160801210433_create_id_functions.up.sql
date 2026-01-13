-- ID parsing functions for extracting account, kind, identifier from resource/role IDs
-- Matches: conjur/db/migrate/20160801210433_create_id_functions.rb
-- ID format: account:kind:identifier (e.g., "myaccount:variable:secrets/db-password")

-- Extract account from ID
CREATE OR REPLACE FUNCTION account(id text) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT CASE 
    WHEN split_part($1, ':', 1) = '' THEN NULL 
    ELSE split_part($1, ':', 1)
END
$$;

-- Extract kind from ID
CREATE OR REPLACE FUNCTION kind(id text) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT CASE 
    WHEN split_part($1, ':', 2) = '' THEN NULL 
    ELSE split_part($1, ':', 2)
END
$$;

-- Extract identifier from ID (everything after account:kind:)
CREATE OR REPLACE FUNCTION identifier(id text) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT SUBSTRING($1 from '[^:]+:[^:]+:(.*)');
$$;

-- Overloaded functions for roles table
CREATE OR REPLACE FUNCTION account(record roles) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT account(record.role_id)
$$;

CREATE OR REPLACE FUNCTION kind(record roles) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT kind(record.role_id)
$$;

CREATE OR REPLACE FUNCTION identifier(record roles) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT identifier(record.role_id)
$$;

-- Overloaded functions for resources table
CREATE OR REPLACE FUNCTION account(record resources) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT account(record.resource_id)
$$;

CREATE OR REPLACE FUNCTION kind(record resources) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT kind(record.resource_id)
$$;

CREATE OR REPLACE FUNCTION identifier(record resources) RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
SELECT identifier(record.resource_id)
$$;

-- Indexes on roles table
CREATE INDEX roles_account_idx ON roles(account(role_id));
CREATE INDEX roles_kind_idx ON roles(kind(role_id));
CREATE INDEX roles_account_kind_idx ON roles(account(role_id), kind(role_id));

-- Indexes on resources table
CREATE INDEX resources_account_idx ON resources(account(resource_id));
CREATE INDEX resources_kind_idx ON resources(kind(resource_id));
CREATE INDEX resources_account_kind_idx ON resources(account(resource_id), kind(resource_id));

-- Index on secrets for efficient lookups
CREATE INDEX secrets_account_kind_identifier_idx ON secrets(account(resource_id), kind(resource_id), identifier(resource_id) text_pattern_ops);

-- Constraints to ensure account and kind are not null
ALTER TABLE roles ADD CONSTRAINT has_account CHECK (account(role_id) IS NOT NULL);
ALTER TABLE roles ADD CONSTRAINT has_kind CHECK (kind(role_id) IS NOT NULL);
ALTER TABLE resources ADD CONSTRAINT has_account CHECK (account(resource_id) IS NOT NULL);
ALTER TABLE resources ADD CONSTRAINT has_kind CHECK (kind(resource_id) IS NOT NULL);
