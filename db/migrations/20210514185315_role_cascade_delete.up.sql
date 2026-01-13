-- Add cascade delete for credentials when role is deleted
-- Matches: conjur/db/migrate/20210514185315_role_cascade_delete.rb

-- Remove orphan credentials first
DELETE FROM credentials
WHERE NOT EXISTS (
  SELECT 1 FROM roles
  WHERE credentials.role_id = role_id
);

-- Add foreign key with cascade delete (note: credentials already has role_id FK via client_id)
-- This adds an additional FK on role_id column for cascade delete
ALTER TABLE credentials ADD CONSTRAINT credentials_role_id_fkey 
  FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE;
