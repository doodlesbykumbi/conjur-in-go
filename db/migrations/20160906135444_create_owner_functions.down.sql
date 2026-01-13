DROP TRIGGER IF EXISTS delete_role_membership_of_owner ON resources;
DROP TRIGGER IF EXISTS update_role_membership_of_owner ON resources;
DROP TRIGGER IF EXISTS grant_role_membership_to_owner ON resources;

DROP FUNCTION IF EXISTS delete_role_membership_of_owner_trigger();
DROP FUNCTION IF EXISTS update_role_membership_of_owner_trigger();
DROP FUNCTION IF EXISTS grant_role_membership_to_owner_trigger();
DROP FUNCTION IF EXISTS update_role_membership_of_owner(text, text, text);
DROP FUNCTION IF EXISTS grant_role_membership_to_owner(text, text);
DROP FUNCTION IF EXISTS delete_role_membership_of_owner(text, text);
