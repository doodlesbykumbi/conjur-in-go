// Package store provides storage abstractions for the Conjur server.
//
// This package defines interfaces for database operations, allowing the
// server endpoints to be decoupled from the specific database implementation.
// This enables easier testing with mocks and potential support for different
// storage backends.
//
// # Available Stores
//
//   - SecretsStore: Secret value operations (fetch, create, expire)
//   - ResourcesStore: Resource listing and metadata (TODO)
//   - RolesStore: Role and membership operations (TODO)
//
// # Usage
//
//	store := store.NewGormSecretsStore(db)
//	secret, err := store.FetchSecret("myorg:variable:password", "")
//	if err != nil {
//	    if errors.Is(err, store.ErrSecretNotFound) {
//	        // Handle not found
//	    }
//	}
package store
