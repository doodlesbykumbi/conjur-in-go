package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"conjur-in-go/pkg/policy"
)

// policyLoadCmd represents the policy load command
var policyLoadCmd = &cobra.Command{
	Use:   "load <account> <file>",
	Short: "Load a policy file",
	Long: `Load a MAML policy file into Conjur.

This command parses the policy YAML and creates the corresponding roles,
resources, permissions, and grants in the database.

Example:
  conjurctl policy load myorg policy.yml
  conjurctl policy load default /path/to/policy.yml`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		account := args[0]
		filename := args[1]

		result, err := loadPolicyFile(account, filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
			os.Exit(1)
		}

		// Output result as JSON
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
	},
}

func init() {
	policyCmd.AddCommand(policyLoadCmd)
}

func loadPolicyFile(account, filename string) (*policy.LoadResult, error) {
	// Connect to database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required")
	}

	db, err := gorm.Open(
		postgres.New(postgres.Config{
			DSN:                  dbURL,
			PreferSimpleProtocol: true,
		}),
		&gorm.Config{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Open policy file
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Load policy
	loader := policy.NewLoader(db, account)
	result, err := loader.LoadFromReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	fmt.Printf("Policy loaded successfully for account '%s'\n", account)
	if len(result.CreatedRoles) > 0 {
		fmt.Printf("Created %d role(s) with credentials\n", len(result.CreatedRoles))
	}

	return result, nil
}
