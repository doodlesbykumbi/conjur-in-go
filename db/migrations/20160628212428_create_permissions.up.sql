-- Permissions table for RBAC permission grants
-- Matches: conjur/db/migrate/20160628212428_create_permissions.rb

CREATE TABLE IF NOT EXISTS permissions (
    privilege text NOT NULL,
    resource_id text NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    role_id text NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (privilege, resource_id, role_id)
);
