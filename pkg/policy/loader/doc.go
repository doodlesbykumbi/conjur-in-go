// Package loader provides database loading for parsed Conjur policies.
//
// This package handles loading parsed policy statements into a database.
// For parsing policy YAML, see the parser package.
//
// # Basic Usage
//
//	store := loader.NewGormStore(db, cipher)
//	l := loader.NewLoader(store, "myorg")
//	result, err := l.LoadFromString(policyYAML)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Created %d roles\n", len(result.CreatedRoles))
//
// # Configuration Options
//
// The loader supports several configuration options via method chaining:
//
//	store := loader.NewGormStore(db, cipher)
//	l := loader.NewLoader(store, "myorg").
//	    WithPolicyID("myorg:policy:app").
//	    WithRoleID("myorg:user:admin").
//	    WithClientIP("192.168.1.1").
//	    WithDeletePermitted(true).
//	    WithDryRun(false)
//
// # Dry Run Mode
//
// Use WithDryRun(true) to validate a policy without applying changes:
//
//	store := loader.NewGormStore(db, cipher)
//	result, err := loader.NewLoader(store, "myorg").
//	    WithDryRun(true).
//	    LoadFromString(policyYAML)
//
// # Store Interface
//
// The loader uses a Store interface for database operations, allowing for
// different backends or mocking in tests. The GormStore implementation
// provides the default database backend using GORM.
package loader
