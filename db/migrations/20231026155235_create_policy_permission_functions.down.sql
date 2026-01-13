-- Drop policy permission functions
-- Matches: conjur/db/migrate/20231026155235_create_policy_permission_functions.rb

DROP FUNCTION policy_permissions(text, text, text);
DROP FUNCTION policy_resources(text);
