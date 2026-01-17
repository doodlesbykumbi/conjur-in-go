package endpoints

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
)

// AccountResponse represents an account in API responses
type AccountResponse struct {
	ID string `json:"id"`
}

// AccountCreateResponse represents the response from creating an account
type AccountCreateResponse struct {
	ID     string `json:"id"`
	APIKey string `json:"api_key"`
}

// RegisterAccountsEndpoints registers the account management endpoints
func RegisterAccountsEndpoints(s *server.Server) {
	db := s.DB
	keystore := s.Keystore
	cipher := s.Cipher

	// GET /accounts - List all accounts
	s.Router.HandleFunc("/accounts", handleListAccounts(db, keystore)).Methods("GET")

	// POST /accounts - Create a new account
	s.Router.HandleFunc("/accounts", handleCreateAccount(db, keystore, cipher)).Methods("POST")

	// DELETE /accounts/{id} - Delete an account
	s.Router.HandleFunc("/accounts/{id}", handleDeleteAccount(db, keystore)).Methods("DELETE")
}

// handleListAccounts returns all accounts by listing keys in the slosilo keystore
func handleListAccounts(db *gorm.DB, keystore *store.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// List all keys from the keystore
		keys, err := keystore.List()
		if err != nil {
			http.Error(w, "Failed to list accounts", http.StatusInternalServerError)
			return
		}

		// Extract account names from key IDs (format: "authn:<account>")
		accounts := make([]string, 0)
		for _, keyID := range keys {
			if strings.HasPrefix(keyID, "authn:") {
				accountName := strings.TrimPrefix(keyID, "authn:")
				// Skip the special "!" account used for the accounts resource
				if accountName != "!" {
					accounts = append(accounts, accountName)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(accounts)
	}
}

// handleCreateAccount creates a new account with a signing key and admin user
func handleCreateAccount(db *gorm.DB, keystore *store.KeyStore, cipher slosilo.SymmetricCipher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse account name from request body or query parameter
		var accountName string

		// Try to get from query parameter first
		accountName = r.URL.Query().Get("id")

		// If not in query, try request body
		if accountName == "" {
			var body struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				accountName = body.ID
			}
		}

		if accountName == "" {
			http.Error(w, "Account name is required", http.StatusBadRequest)
			return
		}

		// Validate account name - no spaces or colons
		if strings.ContainsAny(accountName, " :") {
			http.Error(w, "Account name contains invalid characters (space or colon)", http.StatusBadRequest)
			return
		}

		// Check if account already exists
		keyID := "authn:" + accountName
		if _, err := keystore.Get(keyID); err == nil {
			http.Error(w, "Account already exists", http.StatusConflict)
			return
		}

		// Create the account in a transaction
		apiKey, err := createAccountInDB(db, keystore, cipher, accountName)
		if err != nil {
			http.Error(w, "Failed to create account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		response := AccountCreateResponse{
			ID:     accountName,
			APIKey: apiKey,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	}
}

// handleDeleteAccount deletes an account and all its associated data
func handleDeleteAccount(db *gorm.DB, keystore *store.KeyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		accountName := vars["id"]

		if accountName == "" {
			http.Error(w, "Account name is required", http.StatusBadRequest)
			return
		}

		// Check if account exists
		keyID := "authn:" + accountName
		if _, err := keystore.Get(keyID); err != nil {
			http.Error(w, "Account not found", http.StatusNotFound)
			return
		}

		// Delete the account
		if err := deleteAccountFromDB(db, keystore, accountName); err != nil {
			http.Error(w, "Failed to delete account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// createAccountInDB creates an account with signing key and admin user
func createAccountInDB(db *gorm.DB, keystore *store.KeyStore, cipher slosilo.SymmetricCipher, accountName string) (string, error) {
	// Generate a new RSA key for token signing
	key, err := slosilo.GenerateKey()
	if err != nil {
		return "", err
	}

	// Store the key in the keystore
	keyID := "authn:" + accountName
	if err := keystore.Put(keyID, key); err != nil {
		return "", err
	}

	// Create the admin user role
	adminRoleID := accountName + ":user:admin"
	if err := db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, adminRoleID).Error; err != nil {
		return "", err
	}

	// Create the root policy role
	policyRoleID := accountName + ":policy:root"
	if err := db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, policyRoleID).Error; err != nil {
		return "", err
	}

	// Create the admin user resource (owned by admin role)
	if err := db.Exec(`INSERT INTO resources (resource_id, owner_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, adminRoleID, adminRoleID).Error; err != nil {
		return "", err
	}

	// Create the root policy resource (owned by admin role)
	if err := db.Exec(`INSERT INTO resources (resource_id, owner_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, policyRoleID, adminRoleID).Error; err != nil {
		return "", err
	}

	// Generate API key for admin user
	apiKey, err := model.GenerateAPIKey()
	if err != nil {
		return "", err
	}

	// Encrypt and store the API key
	encryptedAPIKey, err := cipher.Encrypt([]byte(adminRoleID), apiKey)
	if err != nil {
		return "", err
	}

	if err := db.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, adminRoleID, encryptedAPIKey).Error; err != nil {
		return "", err
	}

	return string(apiKey), nil
}

// deleteAccountFromDB deletes an account and all its associated data
func deleteAccountFromDB(db *gorm.DB, keystore *store.KeyStore, accountName string) error {
	// Delete in order to respect foreign key constraints
	// 1. Delete credentials for this account
	if err := db.Exec(`DELETE FROM credentials WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	// 2. Delete secrets for this account
	if err := db.Exec(`DELETE FROM secrets WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	// 3. Delete permissions for this account
	if err := db.Exec(`DELETE FROM permissions WHERE role_id LIKE ? OR resource_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return err
	}

	// 4. Delete role memberships for this account
	if err := db.Exec(`DELETE FROM role_memberships WHERE role_id LIKE ? OR member_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return err
	}

	// 5. Delete annotations for this account
	if err := db.Exec(`DELETE FROM annotations WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	// 6. Delete resources for this account
	if err := db.Exec(`DELETE FROM resources WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	// 7. Delete roles for this account
	if err := db.Exec(`DELETE FROM roles WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	// 8. Delete the signing key from the keystore
	keyID := "authn:" + accountName
	if err := keystore.Delete(keyID); err != nil {
		return err
	}

	return nil
}
