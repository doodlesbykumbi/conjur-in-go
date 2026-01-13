-- Add updated_at column to credentials for API key rotation tracking
-- Matches: conjur/db/migrate/20251003173526_api_key_rotation_timestamp.rb

ALTER TABLE credentials ADD COLUMN updated_at timestamp without time zone;

UPDATE credentials c
SET updated_at = COALESCE(
  ( 
    SELECT r.created_at 
    FROM roles r
    WHERE c.role_id = r.role_id
  ),
  NOW()
);
