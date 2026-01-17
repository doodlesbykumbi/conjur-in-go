// Package config provides configuration management for Conjur.
//
// This package handles loading and validating Conjur server configuration
// from environment variables and configuration files.
//
// # Configuration Sources
//
// Configuration is loaded from:
//
//   - Environment variables (primary)
//   - Configuration files (optional)
//
// # Key Configuration Options
//
//   - CONJUR_AUTHENTICATORS: Enabled authenticators
//   - CONJUR_DATA_KEY: Encryption key
//   - CONJUR_LOG_LEVEL: Logging verbosity
//   - DATABASE_URL: Database connection
//   - PORT: Server listen port
package config
