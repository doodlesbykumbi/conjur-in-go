package endpoints

import (
	"net/http"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/openapi"
)

// RegisterAll registers all API endpoints on the server
func RegisterAll(srv *server.Server) {
	RegisterAccountsEndpoints(srv)
	RegisterAuthenticateEndpoint(srv)
	RegisterJWTAuthenticateEndpoint(srv)
	RegisterSecretsEndpoints(srv)
	RegisterPoliciesEndpoints(srv)
	RegisterResourcesEndpoints(srv)
	RegisterRolesEndpoints(srv)
	RegisterStatusEndpoints(srv)
	RegisterWhoamiEndpoint(srv)
	RegisterPublicKeysEndpoints(srv)
	RegisterHostFactoryEndpoints(srv)
	RegisterAnnotationsEndpoints(srv)

	// Static files
	RegisterStaticFiles(srv)
}

// RegisterOpenAPI registers the OpenAPI-generated handlers on the server.
// This uses the generated API types and covers all core endpoints.
func RegisterOpenAPI(srv *server.Server) {
	apiServer := openapi.NewAPIServer(
		srv.AuthenticateStore,
		srv.AuthzStore,
		srv.SecretsStore,
		srv.ResourcesStore,
		srv.PolicyStore,
		srv.HealthStore,
		srv.RolesStore,
		srv.AccountsStore,
		srv.PolicyLoaderStore,
		srv.Keystore,
		srv.Config,
	)

	// Public paths that don't require authentication
	publicPaths := map[string]bool{
		"/":               true,
		"/authenticators": true,
		"/accounts":       true,
	}

	// Public path prefixes
	publicPrefixes := []string{
		"/authn/",
		"/authn-jwt/",
		"/accounts/",
	}

	// Check if path matches status endpoint pattern (authenticator status)
	isStatusPath := func(path string) bool {
		// Matches /{authenticator}/{account}/status or /{authenticator}/{service_id}/{account}/status
		if len(path) > 1 && path[len(path)-7:] == "/status" {
			return true
		}
		return false
	}

	// Create JWT middleware that skips public endpoints
	jwtMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path

			// Check exact public paths
			if publicPaths[path] {
				next.ServeHTTP(w, r)
				return
			}

			// Check public prefixes
			for _, prefix := range publicPrefixes {
				if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check status paths
			if isStatusPath(path) {
				next.ServeHTTP(w, r)
				return
			}

			// Apply JWT middleware for protected routes
			srv.JWTMiddleware.Middleware(next).ServeHTTP(w, r)
		})
	}

	// Register routes that need {identifier:.+} pattern FIRST (before OpenAPI routes)
	// This is because gorilla mux matches routes in registration order
	registerIdentifierRoutes(srv, apiServer, jwtMiddleware)

	// Register OpenAPI handlers with JWT middleware for protected routes
	api.HandlerWithOptions(apiServer, api.GorillaServerOptions{
		BaseRouter:  srv.Router,
		Middlewares: []api.MiddlewareFunc{jwtMiddleware},
	})

	// Register endpoints not yet covered by OpenAPI spec
	RegisterPublicKeysEndpoints(srv)
	RegisterHostFactoryEndpoints(srv)
	RegisterAnnotationsEndpoints(srv)
	RegisterStaticFiles(srv)
}

// registerIdentifierRoutes registers routes that need {identifier:.+} pattern
func registerIdentifierRoutes(srv *server.Server, apiServer *openapi.APIServer, jwtMiddleware func(http.Handler) http.Handler) {
	r := srv.Router

	// Secrets routes with .+ pattern for identifier
	r.HandleFunc("/secrets/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleGetSecret(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("GET")

	r.HandleFunc("/secrets/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleCreateSecret(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("POST")

	// Resources routes with .+ pattern for identifier
	r.HandleFunc("/resources/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleGetResource(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("GET")

	// Roles routes with .+ pattern for identifier
	r.HandleFunc("/roles/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleGetRole(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("GET")

	r.HandleFunc("/roles/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleAddRoleMember(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("POST")

	r.HandleFunc("/roles/{account}/{kind}/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleDeleteRoleMember(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("DELETE")

	// Policies routes with .+ pattern for identifier
	r.HandleFunc("/policies/{account}/policy/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleGetPolicy(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("GET")

	r.HandleFunc("/policies/{account}/policy/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleLoadPolicy(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("POST")

	r.HandleFunc("/policies/{account}/policy/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleReplacePolicy(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("PUT")

	r.HandleFunc("/policies/{account}/policy/{identifier:.+}", func(w http.ResponseWriter, r *http.Request) {
		jwtMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			openapi.HandleUpdatePolicy(apiServer, w, r)
		})).ServeHTTP(w, r)
	}).Methods("PATCH")
}
