package server

import (
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

type Server struct {
	Keystore *store.KeyStore
	Cipher   slosilo.SymmetricCipher
	Router   *mux.Router
	DB       *gorm.DB
	srv      *http.Server
}

func NewServer(
	keystore *store.KeyStore,
	cipher slosilo.SymmetricCipher,
	db *gorm.DB,
	host string,
	port string,
) *Server {

	router := mux.NewRouter().UseEncodedPath()
	srv := &http.Server{
		Handler: handlers.LoggingHandler(os.Stdout, router),
		Addr:    host + ":" + port,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return &Server{
		Keystore: keystore,
		Cipher:   cipher,
		Router:   router,
		DB:       db,
		srv:      srv,
	}
}

func (s Server) Start() error {
	return s.srv.ListenAndServe()
}
