-- Drop role graph function and type
-- Matches: conjur/db/migrate/20180618161021_role_graph.rb

DROP FUNCTION role_graph(start_role text);
DROP TYPE role_graph_edge;
