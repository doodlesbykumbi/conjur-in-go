// Package conjur provides a Go implementation of the CyberArk Conjur secrets management server.
//
// Conjur is a secrets management solution that provides secure storage and access control
// for secrets, credentials, and other sensitive data. This Go implementation aims to be
// compatible with the Ruby Conjur OSS server.
//
// # Architecture
//
// The server is organized into several packages:
//
//   - pkg/server: HTTP server and routing
//   - pkg/server/endpoints: REST API endpoint handlers
//   - pkg/policy: Policy parsing and loading
//   - pkg/slosilo: Cryptographic operations (encryption, signing, token generation)
//   - pkg/authenticator: Authentication mechanisms (API key, JWT)
//   - pkg/model: Database models
//   - pkg/db: Database connection utilities
//   - pkg/audit: Audit logging
//   - pkg/config: Configuration management
//
// # Quick Start
//
// The server is run via the conjurctl CLI:
//
//	# Generate a data key for encryption
//	conjurctl data-key generate > data_key
//	export CONJUR_DATA_KEY=$(cat data_key)
//
//	# Run database migrations
//	conjurctl db migrate
//
//	# Create an account
//	conjurctl account create myorg
//
//	# Start the server
//	conjurctl server
//
// # Environment Variables
//
//   - DATABASE_URL: PostgreSQL connection string
//   - CONJUR_DATA_KEY: Base64-encoded 256-bit key for data encryption
//   - CONJUR_AUTHENTICATORS: Comma-separated list of enabled authenticators
//   - CONJUR_LOG_LEVEL: Log level (debug, info, warn, error)
//   - PORT: Server port (default: 80)
//
// For more information, see https://github.com/doodlesbykumbi/conjur-in-go
package main
