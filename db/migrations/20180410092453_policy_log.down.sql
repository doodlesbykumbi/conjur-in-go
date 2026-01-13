-- Remove policy log
-- Matches: conjur/db/migrate/20180410092453_policy_log.rb

DROP TRIGGER policy_log ON annotations;
DROP TRIGGER policy_log_d ON annotations;
DROP FUNCTION policy_log_annotations();

DROP TRIGGER policy_log ON permissions;
DROP TRIGGER policy_log_d ON permissions;
DROP FUNCTION policy_log_permissions();

DROP TRIGGER policy_log ON resources;
DROP TRIGGER policy_log_d ON resources;
DROP FUNCTION policy_log_resources();

DROP TRIGGER policy_log ON role_memberships;
DROP TRIGGER policy_log_d ON role_memberships;
DROP FUNCTION policy_log_role_memberships();

DROP TRIGGER policy_log ON roles;
DROP TRIGGER policy_log_d ON roles;
DROP FUNCTION policy_log_roles();

DROP TABLE policy_log;

DROP TYPE policy_log_kind;
DROP TYPE policy_log_op;
