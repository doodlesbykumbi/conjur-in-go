package endpoints

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

func TestHandleGetPolicy(t *testing.T) {
	t.Run("returns policy versions list", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:admin"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(true)

		now := time.Now()
		policyStore.On("ListPolicyVersions", policyID).Return([]store.PolicyVersion{
			{Version: 1, CreatedAt: now, PolicySHA256: "abc123", RoleID: roleID},
			{Version: 2, CreatedAt: now.Add(time.Hour), PolicySHA256: "def456", RoleID: roleID},
		})

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var versions []PolicyVersionResponse
		err := json.Unmarshal(w.Body.Bytes(), &versions)
		require.NoError(t, err)

		assert.Len(t, versions, 2)
		assert.Equal(t, 1, versions[0].Version)
		assert.Equal(t, 2, versions[1].Version)
	})

	t.Run("returns specific policy version text", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:admin"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(true)

		policyText := "- !user\n  id: alice\n"
		policyStore.On("GetPolicyVersion", policyID, 1).Return(&store.PolicyVersion{
			Version:      1,
			CreatedAt:    time.Now(),
			PolicySHA256: "abc123",
			PolicyText:   policyText,
		}, nil)

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root?version=1", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/x-yaml", w.Header().Get("Content-Type"))
		assert.Equal(t, policyText, w.Body.String())
	})

	t.Run("returns 403 when policy not visible", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:bob"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(false)

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 404 for non-existent version", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:admin"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(true)
		policyStore.On("GetPolicyVersion", policyID, 99).Return(nil, errors.New("not found"))

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root?version=99", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 400 for invalid version", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:admin"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(true)

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root?version=invalid", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns empty list for policy with no versions", func(t *testing.T) {
		resourcesStore := NewMockResourcesStore()
		policyStore := NewMockPolicyStore()

		policyID := "myorg:policy:root"
		roleID := "myorg:user:admin"

		resourcesStore.On("IsResourceVisible", policyID, roleID).Return(true)
		policyStore.On("ListPolicyVersions", policyID).Return([]store.PolicyVersion{})

		handler := handleGetPolicy(resourcesStore, policyStore)

		req := requestWithIdentity("GET", "/policies/myorg/policy/root", "", "myorg", roleID)
		req = withMuxVars(req, map[string]string{
			"account":    "myorg",
			"identifier": "root",
		})

		w := httptest.NewRecorder()
		handler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var versions []PolicyVersionResponse
		err := json.Unmarshal(w.Body.Bytes(), &versions)
		require.NoError(t, err)

		assert.Len(t, versions, 0)
	})
}
