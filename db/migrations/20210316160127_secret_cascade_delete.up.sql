-- Add cascade delete for secrets when resource is deleted
-- Matches: conjur/db/migrate/20210316160127_secret_cascade_delete.rb

-- Remove orphan secrets first
DELETE FROM secrets
WHERE NOT EXISTS (
  SELECT 1 FROM resources
  WHERE secrets.resource_id = resource_id
);

-- Add foreign key with cascade delete
ALTER TABLE secrets ADD CONSTRAINT secrets_resource_id_fkey 
  FOREIGN KEY (resource_id) REFERENCES resources(resource_id) ON DELETE CASCADE;
CREATE INDEX secrets_resource_id_idx ON secrets(resource_id);
