package store

// AccountsStore abstracts account storage operations
type AccountsStore interface {
	// ListAccounts returns all account names
	ListAccounts() ([]string, error)

	// AccountExists checks if an account exists
	AccountExists(accountName string) bool

	// CreateAccount creates a new account with signing key and admin user
	CreateAccount(accountName string) (string, error)

	// DeleteAccount deletes an account and all its associated data
	DeleteAccount(accountName string) error
}
