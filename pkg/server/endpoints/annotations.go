package endpoints

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/middleware"
)

// RegisterAnnotationsEndpoints registers the annotations API endpoints
func RegisterAnnotationsEndpoints(s *server.Server) {
	db := s.DB

	// Annotations are accessed via /resources/{account}/{kind}/{id}/annotations
	annotationsRouter := s.Router.PathPrefix("/resources").Subrouter()
	annotationsRouter.Use(s.JWTMiddleware.Middleware)

	// GET /resources/{account}/{kind}/{id}/annotations - List all annotations
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations", handleListAnnotations(db)).Methods("GET")

	// GET /resources/{account}/{kind}/{id}/annotations/{name} - Get single annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleGetAnnotation(db)).Methods("GET")

	// PUT /resources/{account}/{kind}/{id}/annotations/{name} - Set annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleSetAnnotation(db)).Methods("PUT")

	// DELETE /resources/{account}/{kind}/{id}/annotations/{name} - Delete annotation
	annotationsRouter.HandleFunc("/{account}/{kind}/{identifier:.+}/annotations/{name}", handleDeleteAnnotation(db)).Methods("DELETE")
}

func handleListAnnotations(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])

		resourceId := account + ":" + kind + ":" + identifier

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID

		// Check if user can see this resource
		if !canSeeResource(db, resourceId, roleId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Fetch annotations
		annotations := getAnnotationsMap(db, resourceId)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(annotations)
	}
}

func handleGetAnnotation(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID

		// Check if user can see this resource
		if !canSeeResource(db, resourceId, roleId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Fetch annotation
		var value string
		result := db.Raw(`SELECT value FROM annotations WHERE resource_id = ? AND name = ?`, resourceId, name).Scan(&value)
		if result.Error != nil || result.RowsAffected == 0 {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Annotation not found"})
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(value))
	}
}

func handleSetAnnotation(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID

		// Check if user has update permission on the resource
		if !isRoleAllowedTo(db, roleId, "update", resourceId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Read value from body
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
			// Plain text
			buf := make([]byte, 1024)
			n, _ := r.Body.Read(buf)
			value = string(buf[:n])
		}

		// Upsert annotation
		err := db.Exec(`
			INSERT INTO annotations (resource_id, name, value)
			VALUES (?, ?, ?)
			ON CONFLICT (resource_id, name) DO UPDATE SET value = EXCLUDED.value
		`, resourceId, name, value).Error

		if err != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func handleDeleteAnnotation(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		account := vars["account"]
		kind := vars["kind"]
		identifier, _ := url.PathUnescape(vars["identifier"])
		name := vars["name"]

		resourceId := account + ":" + kind + ":" + identifier

		// Get role from auth context
		tokenInfo, _ := middleware.GetTokenInfo(r.Context())
		roleId := tokenInfo.RoleID

		// Check if user has update permission on the resource
		if !isRoleAllowedTo(db, roleId, "update", resourceId) {
			respondWithError(w, http.StatusForbidden, map[string]string{"error": "Forbidden"})
			return
		}

		// Delete annotation
		result := db.Exec(`DELETE FROM annotations WHERE resource_id = ? AND name = ?`, resourceId, name)
		if result.Error != nil {
			respondWithError(w, http.StatusInternalServerError, map[string]string{"error": result.Error.Error()})
			return
		}

		if result.RowsAffected == 0 {
			respondWithError(w, http.StatusNotFound, map[string]string{"error": "Annotation not found"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func canSeeResource(db *gorm.DB, resourceId, roleId string) bool {
	var canSee bool
	db.Raw(`SELECT is_resource_visible(?, ?)`, resourceId, roleId).Scan(&canSee)
	return canSee
}

func getAnnotationsMap(db *gorm.DB, resourceId string) map[string]string {
	type annotationRow struct {
		Name  string
		Value string
	}
	var rows []annotationRow
	db.Raw(`SELECT name, value FROM annotations WHERE resource_id = ?`, resourceId).Scan(&rows)

	annotations := make(map[string]string)
	for _, row := range rows {
		annotations[row.Name] = row.Value
	}
	return annotations
}
