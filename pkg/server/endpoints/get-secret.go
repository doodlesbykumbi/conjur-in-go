package endpoints

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/server"
)

func fetchSecret(db *gorm.DB, secretId string) (*model.Secret, error) {
	var secret model.Secret
	tx := db.Where(&model.Secret{ResourceId: secretId}).First(&secret)
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

func RegisterSecretReadEndpoint(server *server.Server) {
	keystore := server.Keystore
	router := server.Router
	db := server.DB

	jwtMiddleware := &JWTAuthenticator{
		keystore: keystore,
	}

	secretsRouter := router.PathPrefix("/secrets").Subrouter()
	secretsRouter.Use(jwtMiddleware.Instrument)
	secretsRouter.HandleFunc(
		"/{account}/{kind}/{identifier}",
		func(writer http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			account := vars["account"]
			kind := vars["kind"]
			identifier, err := url.PathUnescape(vars["identifier"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// TODO: use a "service" object to serve the endpoint
			//  getSecret(roleId, secretId) ?

			secretId := fmt.Sprintf("%s:%s:%s", account, kind, identifier)

			// Comes from auth
			roleId := request.Context().Value("roleId").(string)

			allowed := isRoleAllowedTo(
				db,
				roleId,
				"execute",
				secretId,
			)
			if !allowed {
				http.Error(writer, "Role does not have execute permissions on secret", http.StatusForbidden)
				return
			}

			// TODO: There's definitely a better model abstraction here
			secret, err := fetchSecret(db, secretId)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					http.Error(writer, err.Error(), http.StatusNotFound)
				}

				http.Error(writer, err.Error(), http.StatusInternalServerError)
				return
			}

			writer.Write([]byte(secret.Value))
		},
	).Methods("GET")
}
