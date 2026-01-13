-- Change permissions primary key order for better query performance
-- Matches: conjur/db/migrate/20190307154241_change_permissions_primary_key.rb

ALTER TABLE permissions DROP CONSTRAINT permissions_pkey;
ALTER TABLE permissions ADD PRIMARY KEY (resource_id, role_id, privilege);
