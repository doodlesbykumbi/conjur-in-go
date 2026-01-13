package endpoints

import (
	"encoding/json"
	"net/http"
)

func respondWithError(w http.ResponseWriter, code int, payload interface{}) {
	respondWithJSON(w, code, map[string]interface{}{"error": payload})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}
