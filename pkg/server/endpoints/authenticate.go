package endpoints

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/utils"
)

const acceptEncoding string = "Accept-Encoding"

func roleIdFromLogin(account string, login string) string {
	tokens := strings.SplitN(login, "/", 2)
	if len(tokens) == 1 {
		tokens = []string{"user", tokens[0]}
	}
	tokens = append([]string{account}, tokens...)
	return strings.Join(tokens, ":")
}

func RegisterAuthenticateEndpoint(server *server.Server) {
	keystore := server.Keystore
	router := server.Router
	db := server.DB

	router.HandleFunc(
		"/authn/{account}/{login}/authenticate",
		func(writer http.ResponseWriter, request *http.Request) {
			requestApiKey, err := ioutil.ReadAll(request.Body)
			defer request.Body.Close()
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			vars := mux.Vars(request)
			account := vars["account"]
			login, err := url.PathUnescape(vars["login"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// Detect the encoding to use
			var base64Encoding bool
			for _, curEnc := range strings.Split(request.Header.Get(acceptEncoding), ",") {
				curEnc = strings.TrimSpace(curEnc)
				if curEnc == "base64" {
					base64Encoding = true
					break
				}
			}

			roleId := roleIdFromLogin(account, login)
			// Validate API key
			credential := model.Credential{}
			tx := db.Where(&struct{ RoleId string }{RoleId: roleId}).First(&credential)
			err = tx.Error
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			if ok := subtle.ConstantTimeCompare(credential.ApiKey, requestApiKey); ok != 1 {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}

			newclaimsMap := map[string]interface{}{
				"iat": time.Now().Unix(),
				"sub": login,
			}
			key, err := keystore.ByAccount(account)
			if err != nil {
				// TODO: Generally this needs to be hidden from the response and should probably be logged
				//
				// Errors like: Error on key by account: cipher: message authentication failed
				http.Error(writer, fmt.Sprintf("Error on key by account: %s", err.Error()), http.StatusBadRequest)
				return
			}

			newheaderMap := map[string]interface{}{
				"alg": "conjur.org/slosilo/v2",
				"kid": key.Fingerprint(),
			}

			newheader := utils.ToJson(newheaderMap)
			newclaims := utils.ToJson(newclaimsMap)

			newsalt, _ := slosilo.RandomBytes(32)
			stringToSign := strings.Join(
				[]string{
					base64.URLEncoding.EncodeToString([]byte(newheader)),
					base64.URLEncoding.EncodeToString([]byte(newclaims)),
				},
				".",
			)

			// Conjur in ruby forces the thing being signed to be encoded in ASCII-8BIT
			// https://github.com/cyberark/slosilo/blob/master/lib/slosilo/key.rb#L198-L202
			//
			// Go uses UTF-8 as the standard encoding.
			// TODO: confirm if these are altogether compatible, and there are no edge cases where a token signed by Ruby
			// can't be verified by Go and vice-versa
			newsignature, err := key.Sign(
				[]byte(
					stringToSign,
				),
				newsalt,
			)
			newjwt := map[string]string{
				"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
				"payload":   base64.URLEncoding.EncodeToString([]byte(newclaims)),
				"signature": base64.URLEncoding.EncodeToString(newsignature),
			}

			newjwtJSON := []byte(utils.ToJson(newjwt))

			if base64Encoding {
				writer.Header().Add("Content-Encoding", "base64")
				base64.NewEncoder(base64.StdEncoding.Strict(), writer).Write(newjwtJSON)
				return
			}

			writer.Header().Add("Content-Type", "application/json")
			writer.Write(newjwtJSON)
		},
	).Methods("POST")
}
