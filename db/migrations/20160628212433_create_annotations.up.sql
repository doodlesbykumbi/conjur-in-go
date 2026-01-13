-- Annotations table for metadata on resources
-- Matches: conjur/db/migrate/20160628212433_create_annotations.rb

CREATE TABLE IF NOT EXISTS annotations (
    resource_id text NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    name text NOT NULL,
    value text NOT NULL,
    PRIMARY KEY (resource_id, name)
);

CREATE INDEX annotations_name_index ON annotations(name);
