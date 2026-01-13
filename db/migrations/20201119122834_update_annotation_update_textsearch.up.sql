-- Update annotation_update_textsearch to handle foreign key violations
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
          BEGIN
            UPDATE resources_textsearch rts
            SET textsearch = (
              SELECT r.tsvector FROM resources r
              WHERE r.resource_id = rts.resource_id
            ) WHERE resource_id = OLD.resource_id;
          EXCEPTION WHEN foreign_key_violation THEN
            /*
            It's possible when an annotation is deleted that the entire resource
            has been deleted. When this is the case, attempting to update the
            search text will raise a foreign key violation on the missing
            resource_id. 
            */
            RAISE WARNING 'Cannot update search text for % because it no longer exists', OLD.resource_id;
            RETURN NULL;
          END;
        END IF;

        RETURN NULL;
      END
      $annotation_update_textsearch$;
