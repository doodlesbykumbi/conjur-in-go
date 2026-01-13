-- Remove constraints
ALTER TABLE resources DROP CONSTRAINT IF EXISTS has_kind;
ALTER TABLE resources DROP CONSTRAINT IF EXISTS has_account;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS has_kind;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS has_account;

-- Remove indexes
DROP INDEX IF EXISTS secrets_account_kind_identifier_idx;
DROP INDEX IF EXISTS resources_account_kind_idx;
DROP INDEX IF EXISTS resources_kind_idx;
DROP INDEX IF EXISTS resources_account_idx;
DROP INDEX IF EXISTS roles_account_kind_idx;
DROP INDEX IF EXISTS roles_kind_idx;
DROP INDEX IF EXISTS roles_account_idx;

-- Remove overloaded functions
DROP FUNCTION IF EXISTS identifier(resources);
DROP FUNCTION IF EXISTS kind(resources);
DROP FUNCTION IF EXISTS account(resources);
DROP FUNCTION IF EXISTS identifier(roles);
DROP FUNCTION IF EXISTS kind(roles);
DROP FUNCTION IF EXISTS account(roles);

-- Remove base functions
DROP FUNCTION IF EXISTS identifier(text);
DROP FUNCTION IF EXISTS kind(text);
DROP FUNCTION IF EXISTS account(text);
