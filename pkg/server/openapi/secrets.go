package openapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/doodlesbykumbi/conjur-in-go/api"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/audit"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// GetSecret implements api.ServerInterface
func (s *APIServer) GetSecret(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.GetSecretParams) {
	resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

	id, _ := identity.Get(r.Context())
	roleId := id.RoleID
	clientIP := getClientIP(r)

	secretVersion := ""
	if params.Version != nil {
		secretVersion = strconv.Itoa(*params.Version)
	}

	if !s.authzStore.IsRoleAllowedTo(roleId, "execute", resourceId) {
		audit.Log(audit.FetchEvent{
			UserID:       roleId,
			ClientIP:     clientIP,
			ResourceID:   resourceId,
			Version:      secretVersion,
			Success:      false,
			ErrorMessage: "permission denied",
		})
		http.Error(w, "role does not have execute permissions on secret", http.StatusForbidden)
		return
	}

	secret, err := s.secretsStore.FetchSecret(resourceId, secretVersion)
	if err != nil {
		if errors.Is(err, store.ErrSecretNotFound) {
			audit.Log(audit.FetchEvent{
				UserID:       roleId,
				ClientIP:     clientIP,
				ResourceID:   resourceId,
				Version:      secretVersion,
				Success:      false,
				ErrorMessage: "secret not found",
			})
			respondWithError(w, http.StatusNotFound, map[string]string{"message": "secret is empty or not found."})
			return
		}
		if errors.Is(err, store.ErrSecretExpired) {
			audit.Log(audit.FetchEvent{
				UserID:       roleId,
				ClientIP:     clientIP,
				ResourceID:   resourceId,
				Version:      secretVersion,
				Success:      false,
				ErrorMessage: "secret has expired",
			})
			respondWithError(w, http.StatusNotFound, map[string]string{"message": "secret has expired"})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	audit.Log(audit.FetchEvent{
		UserID:     roleId,
		ClientIP:   clientIP,
		ResourceID: resourceId,
		Version:    secretVersion,
		Success:    true,
	})
	_, _ = w.Write(secret.Value)
}

// CreateSecret implements api.ServerInterface
func (s *APIServer) CreateSecret(w http.ResponseWriter, r *http.Request, account api.Account, kind api.Kind, identifier api.Identifier, params api.CreateSecretParams) {
	resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

	id, _ := identity.Get(r.Context())
	roleId := id.RoleID
	clientIP := getClientIP(r)

	// Check if this is an expiration request
	if params.Expirations != nil {
		// Handle expiration
		if kind != "variable" {
			respondWithError(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "Only variables can be expired",
			})
			return
		}

		if !s.authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if err := s.secretsStore.ExpireSecret(resourceId); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		return
	}

	// Regular secret creation
	newSecretValue, err := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !s.authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
		audit.Log(audit.UpdateEvent{
			UserID:       roleId,
			ClientIP:     clientIP,
			ResourceID:   resourceId,
			Success:      false,
			ErrorMessage: "permission denied",
		})
		http.Error(w, "role does not have update permissions on secret", http.StatusForbidden)
		return
	}

	if err := s.secretsStore.CreateSecret(resourceId, newSecretValue); err != nil {
		audit.Log(audit.UpdateEvent{
			UserID:       roleId,
			ClientIP:     clientIP,
			ResourceID:   resourceId,
			Success:      false,
			ErrorMessage: err.Error(),
		})
		respondWithError(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}

	audit.Log(audit.UpdateEvent{
		UserID:     roleId,
		ClientIP:   clientIP,
		ResourceID: resourceId,
		Success:    true,
	})
	w.WriteHeader(http.StatusCreated)
}

// BatchGetSecrets implements api.ServerInterface
func (s *APIServer) BatchGetSecrets(w http.ResponseWriter, r *http.Request, params api.BatchGetSecretsParams) {
	variableIds := strings.Split(params.VariableIds, ",")

	id, _ := identity.Get(r.Context())
	roleId := id.RoleID

	useBase64 := strings.EqualFold(r.Header.Get("Accept-Encoding"), "base64")

	results := make(map[string]string)
	for _, varId := range variableIds {
		varId = strings.TrimSpace(varId)
		if varId == "" {
			continue
		}

		if !s.authzStore.IsRoleAllowedTo(roleId, "execute", varId) {
			respondWithError(w, http.StatusForbidden, map[string]string{
				"error": fmt.Sprintf("Forbidden: role does not have execute permission on %s", varId),
			})
			return
		}

		secret, err := s.secretsStore.FetchSecret(varId, "")
		if err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				respondWithError(w, http.StatusNotFound, map[string]string{
					"error": fmt.Sprintf("Variable %s has no secret value", varId),
				})
				return
			}
			if errors.Is(err, store.ErrSecretExpired) {
				respondWithError(w, http.StatusNotFound, map[string]string{
					"error": fmt.Sprintf("Variable %s has expired", varId),
				})
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		value := string(secret.Value)
		if useBase64 {
			value = base64.StdEncoding.EncodeToString(secret.Value)
		}
		results[varId] = value
	}

	if useBase64 {
		w.Header().Set("Content-Encoding", "base64")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(results)
}

// BatchUpdateSecrets implements api.ServerInterface
func (s *APIServer) BatchUpdateSecrets(w http.ResponseWriter, r *http.Request, account api.Account) {
	id, _ := identity.Get(r.Context())
	roleId := id.RoleID

	var body struct {
		Secrets map[string]string `json:"secrets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	updated := make([]string, 0)
	errs := make(map[string]string)

	for varId, value := range body.Secrets {
		// Ensure variable ID includes account
		if !strings.HasPrefix(varId, account+":") {
			varId = account + ":variable:" + varId
		}

		if !s.authzStore.IsRoleAllowedTo(roleId, "update", varId) {
			errs[varId] = "permission denied"
			continue
		}

		if err := s.secretsStore.CreateSecret(varId, []byte(value)); err != nil {
			errs[varId] = err.Error()
			continue
		}

		updated = append(updated, varId)
	}

	response := map[string]interface{}{
		"updated": updated,
	}
	if len(errs) > 0 {
		response["errors"] = errs
	}

	w.Header().Set("Content-Type", "application/json")
	if len(errs) > 0 && len(updated) > 0 {
		w.WriteHeader(http.StatusMultiStatus)
	} else if len(errs) > 0 {
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(response)
}
