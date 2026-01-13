-- Revert annotation_update_textsearch to original version
-- Matches: conjur/db/migrate/20201119122834_update_annotation_update_textsearch.rb

CREATE OR REPLACE FUNCTION annotation_update_textsearch() RETURNS trigger
    SET search_path FROM CURRENT
    LANGUAGE plpgsql
    AS $annotation_update_textsearch$
    BEGIN
      IF TG_OP IN ('INSERT', 'UPDATE') THEN
        UPDATE resources_textsearch rts
        SET textsearch = (
          SELECT r.tsvector FROM resources r
          WHERE r.resource_id = rts.resource_id
        ) WHERE resource_id = NEW.resource_id;
      END IF;
      
      IF TG_OP IN ('UPDATE', 'DELETE') THEN
        UPDATE resources_textsearch rts
        SET textsearch = (
          SELECT r.tsvector FROM resources r
          WHERE r.resource_id = rts.resource_id
        ) WHERE resource_id = OLD.resource_id;
      END IF;

      RETURN NULL;
    END
    $annotation_update_textsearch$;
