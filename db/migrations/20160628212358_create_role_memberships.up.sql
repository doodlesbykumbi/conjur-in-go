-- Role memberships for role hierarchy
-- Matches: conjur/db/migrate/20160628212358_create_role_memberships.rb

CREATE TABLE IF NOT EXISTS role_memberships (
    role_id text NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    member_id text NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    admin_option boolean NOT NULL DEFAULT false,
    ownership boolean NOT NULL DEFAULT false,
    PRIMARY KEY (role_id, member_id, ownership)
);

CREATE INDEX role_memberships_member ON role_memberships(member_id);
