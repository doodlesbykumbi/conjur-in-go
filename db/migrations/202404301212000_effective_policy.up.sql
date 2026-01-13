-- Resource depth function for policy hierarchy calculations
-- Matches: conjur/db/migrate/202404301212000_effective_policy.rb

CREATE OR REPLACE FUNCTION res_depth(resource_id text) RETURNS integer AS
$$
  BEGIN
      RETURN length(resource_id)-length(replace(resource_id, '/', ''));
  END;
$$ LANGUAGE plpgsql;
