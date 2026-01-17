// Package server provides the HTTP server for the Conjur API.
//
// This package implements the core HTTP server that handles all Conjur REST API
// requests. It uses gorilla/mux for routing and provides middleware for
// authentication and request handling.
//
// # Server Setup
//
//	srv := server.NewServer(keystore, cipher, router, db, jwtMiddleware)
//	if err := srv.ListenAndServe(":80"); err != nil {
//	    log.Fatal(err)
//	}
//
// # Components
//
// The Server struct holds:
//
//   - Keystore: RSA key storage for token signing
//   - Cipher: Symmetric cipher for secret encryption
//   - Router: HTTP request router
//   - DB: Database connection
//   - JWTMiddleware: JWT token validation
//
// # Endpoints
//
// API endpoints are registered via the endpoints subpackage:
//
//	endpoints.RegisterAll(srv)
//
// This registers all standard Conjur API endpoints including:
//
//   - /authn/{account}/{login}/authenticate - API key authentication
//   - /authn-jwt/{service-id}/{account}/authenticate - JWT authentication
//   - /secrets/{account}/{kind}/{identifier} - Secret management
//   - /policies/{account}/policy/{identifier} - Policy loading
//   - /resources/{account} - Resource listing
//   - /roles/{account}/{kind}/{identifier} - Role management
//   - /whoami - Token introspection
package server
