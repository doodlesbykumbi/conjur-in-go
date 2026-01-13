-- Ownership trigger functions
-- Matches: conjur/db/migrate/20160906135444_create_owner_functions.rb
-- These functions automatically manage role_memberships when resources are created/updated/deleted

-- Deletes the role_memberships record with the indicated role and grantee (owner)
CREATE OR REPLACE FUNCTION delete_role_membership_of_owner(role_id text, owner_id text) RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
    row_count int;
BEGIN
    DELETE FROM role_memberships rm
        WHERE rm.role_id = $1 AND
        member_id = $2 AND
        ownership = true;
    GET DIAGNOSTICS row_count = ROW_COUNT;
    RETURN row_count;
END
$$;

-- Inserts a role_memberships record with the indicated role and grantee (owner)
CREATE OR REPLACE FUNCTION grant_role_membership_to_owner(role_id text, owner_id text) RETURNS int
LANGUAGE plpgsql
AS $$
DECLARE
    rolsource_role roles%rowtype;
    existing_grant role_memberships%rowtype;
BEGIN
    SELECT * INTO rolsource_role FROM roles WHERE roles.role_id = $1;
    IF FOUND THEN
        SELECT * INTO existing_grant FROM role_memberships rm WHERE rm.role_id = $1 AND rm.member_id = $2 AND rm.admin_option = true AND rm.ownership = true;
        IF NOT FOUND THEN
            INSERT INTO role_memberships ( role_id, member_id, admin_option, ownership )
                VALUES ( $1, $2, true, true );
            RETURN 1;
        END IF;
    END IF;
    RETURN 0;
END
$$;

-- Updates role membership when owner changes
CREATE OR REPLACE FUNCTION update_role_membership_of_owner(role_id text, old_owner_id text, new_owner_id text) RETURNS int
LANGUAGE plpgsql
AS $$
BEGIN
    IF old_owner_id != new_owner_id THEN
        PERFORM public.delete_role_membership_of_owner(role_id, old_owner_id);
        PERFORM public.grant_role_membership_to_owner(role_id, new_owner_id);
    END IF;
    RETURN 1;
END
$$;

-- Trigger function for INSERT on resources
CREATE OR REPLACE FUNCTION grant_role_membership_to_owner_trigger() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM public.grant_role_membership_to_owner(NEW.resource_id, NEW.owner_id);
    RETURN NEW;
END
$$;

-- Trigger function for UPDATE on resources
CREATE OR REPLACE FUNCTION update_role_membership_of_owner_trigger() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.owner_id != NEW.owner_id THEN
        PERFORM public.delete_role_membership_of_owner(OLD.resource_id, OLD.owner_id);
        PERFORM public.grant_role_membership_to_owner(OLD.resource_id, NEW.owner_id);
    END IF;
    RETURN NEW;
END
$$;

-- Trigger function for DELETE on resources
CREATE OR REPLACE FUNCTION delete_role_membership_of_owner_trigger() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM public.delete_role_membership_of_owner(OLD.resource_id, OLD.owner_id);
    RETURN OLD;
END
$$;

-- Create triggers on resources table
CREATE TRIGGER grant_role_membership_to_owner
BEFORE INSERT ON resources
FOR EACH ROW
EXECUTE PROCEDURE public.grant_role_membership_to_owner_trigger();

CREATE TRIGGER update_role_membership_of_owner
BEFORE UPDATE ON resources
FOR EACH ROW
EXECUTE PROCEDURE public.update_role_membership_of_owner_trigger();

CREATE TRIGGER delete_role_membership_of_owner
BEFORE DELETE ON resources
FOR EACH ROW
EXECUTE PROCEDURE public.delete_role_membership_of_owner_trigger();
