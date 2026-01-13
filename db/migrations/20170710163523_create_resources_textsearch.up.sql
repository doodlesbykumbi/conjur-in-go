-- Resources text search for full-text search capabilities
-- Matches: conjur/db/migrate/20170710163523_create_resources_textsearch.rb

CREATE TABLE resources_textsearch (
    resource_id text PRIMARY KEY REFERENCES resources(resource_id) ON DELETE CASCADE
);

ALTER TABLE resources_textsearch ADD COLUMN textsearch tsvector;
CREATE INDEX resources_ts_index ON resources_textsearch USING gist (textsearch);

CREATE FUNCTION tsvector(resource resources) RETURNS tsvector
    LANGUAGE sql
    AS $$
    WITH annotations AS (
      SELECT name, value FROM annotations
      WHERE resource_id = resource.resource_id
    )
    SELECT
    -- id and name are A
    -- Translate chars that are not considered word separators by parser.
    -- Note: although ids are not english, use english dict so that searching is simpler, if less strict
    setweight(to_tsvector('pg_catalog.english', translate(identifier(resource.resource_id), './-', '   ')), 'A') ||

    setweight(to_tsvector('pg_catalog.english',
      coalesce((SELECT value FROM annotations WHERE name = 'name'), '')
    ), 'A') ||

    -- other annotations are B
    setweight(to_tsvector('pg_catalog.english',
      (SELECT coalesce(string_agg(value, ' :: '), '') FROM annotations WHERE name <> 'name')
    ), 'B') ||

    -- kind is C
    setweight(to_tsvector('pg_catalog.english', kind(resource.resource_id)), 'C')
    $$;

CREATE FUNCTION resource_update_textsearch() RETURNS trigger
    SET search_path FROM CURRENT
    LANGUAGE plpgsql
    AS $resource_update_textsearch$
    BEGIN
      IF TG_OP = 'INSERT' THEN
        INSERT INTO resources_textsearch
        VALUES (NEW.resource_id, tsvector(NEW));
      ELSE
        UPDATE resources_textsearch
        SET textsearch = tsvector(NEW)
        WHERE resource_id = NEW.resource_id;
      END IF;

      RETURN NULL;
    END
    $resource_update_textsearch$;

CREATE TRIGGER resource_update_textsearch
     AFTER INSERT OR UPDATE ON resources
     FOR EACH ROW EXECUTE PROCEDURE resource_update_textsearch();

CREATE FUNCTION annotation_update_textsearch() RETURNS trigger
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

CREATE TRIGGER annotation_update_textsearch
     AFTER INSERT OR UPDATE OR DELETE ON annotations
     FOR EACH ROW EXECUTE PROCEDURE annotation_update_textsearch();

-- Populate existing resources
INSERT INTO resources_textsearch
    SELECT resource_id, resources.tsvector
    FROM resources;
