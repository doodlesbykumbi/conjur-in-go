package endpoints

import "conjur-in-go/pkg/server"

// RegisterAll registers all API endpoints on the server
func RegisterAll(srv *server.Server) {
	RegisterAuthenticateEndpoint(srv)
	RegisterSecretsEndpoints(srv)
	RegisterPoliciesEndpoints(srv)
	RegisterResourcesEndpoints(srv)
	RegisterRolesEndpoints(srv)
	RegisterStatusEndpoints(srv)
	RegisterWhoamiEndpoint(srv)
	RegisterPublicKeysEndpoints(srv)
	RegisterHostFactoryEndpoints(srv)
	RegisterAnnotationsEndpoints(srv)
}
