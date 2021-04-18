package endpoints

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/utils"
)

const acceptEncoding string = "Accept-Encoding"

func RegisterAuthenticateEndpoint(server *server.Server) {
	keystore := server.Keystore
	router := server.Router

	router.HandleFunc(
		"/authn/{account}/{login}/authenticate",
		func(writer http.ResponseWriter, request *http.Request) {
			// TODO: check if api key matches against DB

			vars := mux.Vars(request)
			account := vars["account"]
			login, err := url.PathUnescape(vars["login"])
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			// Detect what encoding to use
			var base64Encoding bool
			for _, curEnc := range strings.Split(request.Header.Get(acceptEncoding), ",") {
				curEnc = strings.TrimSpace(curEnc)
				if curEnc == "base64" {
					base64Encoding = true
					break
				}
			}

			newclaimsMap := map[string]interface{}{
				"iat": time.Now().Unix(),
				"sub": login,
			}
			key, err := keystore.ByAccount(account)
			if err != nil {
				http.Error(writer, fmt.Sprintf("Error on key by account: %s", err.Error()), http.StatusBadRequest)
				return
			}

			newheaderMap := map[string]interface{}{
				"alg": "conjur.org/slosilo/v2",
				"kid": key.StoredKey.Fingerprint,
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

			// TODO: this needs to be more sophisticated
			//  Conjur in ruby forces the thing being signed to be encoded in ASCII-8BIT
			//  https://github.com/cyberark/slosilo/blob/master/lib/slosilo/key.rb#L198-L202
			newsignature, err := key.Sign(
				[]byte(
					stringToSign,
				),
				newsalt,
			)
			newjwt := map[string]string{
				"protected": base64.URLEncoding.EncodeToString([]byte(newheader)),
				"payload": base64.URLEncoding.EncodeToString([]byte(newclaims)),
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
