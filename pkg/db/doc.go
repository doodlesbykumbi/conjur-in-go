// Package db provides database connection utilities for Conjur.
//
// This package handles PostgreSQL database connections using GORM.
// It provides a centralized way to configure and establish database
// connections with proper encryption support.
//
// # Connection
//
//	cfg := db.Config{
//	    Cipher: cipher, // for credential encryption
//	}
//	database, err := db.Connect(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Environment Variables
//
//   - DATABASE_URL: PostgreSQL connection string (required)
//   - CONJUR_LOG_LEVEL: Set to "debug" for SQL query logging
//
// # Connection String Format
//
// The DATABASE_URL should be a standard PostgreSQL connection string:
//
//	postgres://user:password@host:port/database?sslmode=disable
package db
