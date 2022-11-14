package endpoints

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/server"
)

func fetchSecret(db *gorm.DB, resourceId string, secretVersion string) (*model.Secret, error) {
	var secret model.Secret
	query := map[string]interface{}{"resource_id": resourceId}
	if secretVersion != "" {
		query["version"] = secretVersion
	}

	tx := db.Order("version desc").Where(query).First(&secret)
	err := tx.Error
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

func isRoleAllowedTo(db *gorm.DB, roleId, privilege, resourceId string) bool {
	var permitted bool
	db.Raw(`SELECT is_role_allowed_to(?, ?, ?)`, roleId, privilege, resourceId).Scan(&permitted)
	return permitted
}

func RegisterSecretsEndpoints(server *server.Server) {
	keystore := server.Keystore
	router := server.Router
	db := server.DB

	// TODO: this isn't right. The middleware should be available everywhere for consumption by multiple routes
	jwtMiddleware := &JWTAuthenticator{
		keystore: keystore,
	}

	secretsRouter := router.PathPrefix("/secrets").Subrouter()
	secretsRouter.Use(jwtMiddleware.Instrument)
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}", // For 'identifier' we grab the rest of the URL including slashes
		func(writer http.ResponseWriter, request *http.Request) {
			secretVersion := request.URL.Query().Get("version")

			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// TODO: use a "service" object to serve the endpoint
			//  getSecret(roleId, resourceId) ?

			resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			roleId := request.Context().Value("roleId").(string)

			allowed := isRoleAllowedTo(
				db,
				roleId,
				"execute",
				resourceId,
			)
			if !allowed {
				http.Error(writer, "role does not have execute permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			secret, err := fetchSecret(db, resourceId, secretVersion)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					respondWithError(writer, http.StatusNotFound, map[string]string{"message": "secret is empty or not found."})
					return
				}

				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}

			writer.Write(secret.Value)
		},
	).Methods("GET")

	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier:.+}", // For 'identifier' we grab the rest of the URL including slashes
		func(writer http.ResponseWriter, request *http.Request) {
			newSecretValue, err := ioutil.ReadAll(request.Body)
			defer request.Body.Close()
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			resourceId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			roleId := request.Context().Value("roleId").(string)

			// TODO: turn this into "#authorize(action)" utility function
			allowed := isRoleAllowedTo(
				db,
				roleId,
				"update",
				resourceId,
			)
			if !allowed {
				http.Error(writer, "role does not have update permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			tx := db.Create(&model.Secret{
				ResourceId: resourceId,
				Value:      newSecretValue,
			})
			err = tx.Error
			if err != nil {
				respondWithError(writer, http.StatusInternalServerError, map[string]string{"message": err.Error()})
				return
			}

			writer.WriteHeader(http.StatusCreated)
		},
	).Methods("POST")
}
