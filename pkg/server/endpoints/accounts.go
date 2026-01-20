package endpoints

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
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
	accountsStore := s.AccountsStore

	// GET /accounts - List all accounts
	s.Router.HandleFunc("/accounts", handleListAccounts(accountsStore)).Methods("GET")

	// POST /accounts - Create a new account
	s.Router.HandleFunc("/accounts", handleCreateAccount(accountsStore)).Methods("POST")

	// DELETE /accounts/{id} - Delete an account
	s.Router.HandleFunc("/accounts/{id}", handleDeleteAccount(accountsStore)).Methods("DELETE")
}

func handleListAccounts(accountsStore store.AccountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accounts, err := accountsStore.ListAccounts()
		if err != nil {
			http.Error(w, "Failed to list accounts", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(accounts)
	}
}

func handleCreateAccount(accountsStore store.AccountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var accountName string

		accountName = r.URL.Query().Get("id")

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

		if strings.ContainsAny(accountName, " :") {
			http.Error(w, "Account name contains invalid characters (space or colon)", http.StatusBadRequest)
			return
		}

		if accountsStore.AccountExists(accountName) {
			http.Error(w, "Account already exists", http.StatusConflict)
			return
		}

		apiKey, err := accountsStore.CreateAccount(accountName)
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

func handleDeleteAccount(accountsStore store.AccountsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		accountName := vars["id"]

		if accountName == "" {
			http.Error(w, "Account name is required", http.StatusBadRequest)
			return
		}

		if !accountsStore.AccountExists(accountName) {
			http.Error(w, "Account not found", http.StatusNotFound)
			return
		}

		if err := accountsStore.DeleteAccount(accountName); err != nil {
			http.Error(w, "Failed to delete account: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
