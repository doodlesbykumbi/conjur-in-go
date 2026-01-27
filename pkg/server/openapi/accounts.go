package openapi

import (
	"encoding/json"
	"net/http"

	"github.com/doodlesbykumbi/conjur-in-go/api"
)

// ListAccounts implements api.ServerInterface
func (s *APIServer) ListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.accountsStore.ListAccounts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accounts)
}

// CreateAccount implements api.ServerInterface
func (s *APIServer) CreateAccount(w http.ResponseWriter, r *http.Request, params api.CreateAccountParams) {
	var accountName string

	// Try query param first
	if params.Id != nil && *params.Id != "" {
		accountName = *params.Id
	} else {
		// Try JSON body
		var body struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.ID != "" {
			accountName = body.ID
		}
	}

	if accountName == "" {
		http.Error(w, "Account name is required", http.StatusBadRequest)
		return
	}

	// Check if account already exists
	if s.accountsStore.AccountExists(accountName) {
		http.Error(w, "Account already exists", http.StatusConflict)
		return
	}

	apiKey, err := s.accountsStore.CreateAccount(accountName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := api.AccountCreateResponse{
		Id:     &accountName,
		ApiKey: &apiKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// DeleteAccount implements api.ServerInterface
func (s *APIServer) DeleteAccount(w http.ResponseWriter, r *http.Request, id api.AccountId) {
	// Check if account exists
	if !s.accountsStore.AccountExists(id) {
		http.Error(w, "Account not found", http.StatusNotFound)
		return
	}

	if err := s.accountsStore.DeleteAccount(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
