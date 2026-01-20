package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/identity"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// RegisterAnnotationsEndpoints registers the annotations API endpoints
func RegisterAnnotationsEndpoints(s *server.Server) {
	annotationsStore := s.AnnotationsStore
	authzStore := s.AuthzStore

	annotationsRouter := s.Router.PathPrefix("/resources").Subrouter()
	annotationsRouter.Use(s.JWTMiddleware.Middleware)

	// GET /resources/{account}/{kind}/{id}/annotations - List all annotations
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations", handleListAnnotations(annotationsStore, authzStore)).Methods("GET")

	// GET /resources/{account}/{kind}/{id}/annotations/{name} - Get single annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleGetAnnotation(annotationsStore, authzStore)).Methods("GET")

	// PUT /resources/{account}/{kind}/{id}/annotations/{name} - Set annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleSetAnnotation(annotationsStore, authzStore)).Methods("PUT")

	// DELETE /resources/{account}/{kind}/{id}/annotations/{name} - Delete annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleDeleteAnnotation(annotationsStore, authzStore)).Methods("DELETE")
}

func handleListAnnotations(annotationsStore store.AnnotationsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		resourceId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsResourceVisible(resourceId, roleId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		annotations := annotationsStore.GetAnnotations(resourceId)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(annotations)
	}
}

func handleGetAnnotation(annotationsStore store.AnnotationsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsResourceVisible(resourceId, roleId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		value, found := annotationsStore.GetAnnotation(resourceId, name)
		if !found {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Annotation not found"})
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(value))
	}
}

func handleSetAnnotation(annotationsStore store.AnnotationsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		var value string
		contentType := r.Header.Get("Content-Type")
		if contentType == "application/json" {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				respondWithError(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
				return
			}
			value = body["value"]
		} else {
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			value = string(buf[:n])
		}

		if err := annotationsStore.SetAnnotation(resourceId, name, value); err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleDeleteAnnotation(annotationsStore store.AnnotationsStore, authzStore store.AuthzStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		id, _ := identity.Get(r.Context())
		roleId := id.RoleID

		if !authzStore.IsRoleAllowedTo(roleId, "update", resourceId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		deleted, err := annotationsStore.DeleteAnnotation(resourceId, name)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		if !deleted {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Annotation not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
