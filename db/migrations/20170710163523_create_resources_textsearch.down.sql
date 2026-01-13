-- Drop resources text search
-- Matches: conjur/db/migrate/20170710163523_create_resources_textsearch.rb

DROP TRIGGER annotation_update_textsearch ON annotations;
DROP FUNCTION annotation_update_textsearch();

DROP TRIGGER resource_update_textsearch ON resources;
DROP FUNCTION resource_update_textsearch();

DROP FUNCTION tsvector(resource resources);

DROP INDEX resources_ts_index;

DROP TABLE resources_textsearch;
