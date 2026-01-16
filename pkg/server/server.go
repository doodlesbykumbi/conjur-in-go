package server

import (
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"gorm.io/gorm"

	"conjur-in-go/pkg/server/middleware"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

type Server struct {
	Keystore      *store.KeyStore
	Cipher        slosilo.SymmetricCipher
	Router        *mux.Router
	DB            *gorm.DB
	JWTMiddleware *middleware.JWTAuthenticator
	srv           *http.Server
	listener      net.Listener
}

func NewServer(
	keystore *store.KeyStore,
	cipher slosilo.SymmetricCipher,
	db *gorm.DB,
	host string,
	port string,
) *Server {

	router := mux.NewRouter().UseEncodedPath().StrictSlash(true)
	srv := &http.Server{
		Handler: handlers.LoggingHandler(os.Stdout, router),
		Addr:    host + ":" + port,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return &Server{
		Keystore:      keystore,
		Cipher:        cipher,
		Router:        router,
		DB:            db,
		JWTMiddleware: middleware.NewJWTAuthenticator(keystore),
		srv:           srv,
	}
}

func (s *Server) Start() error {
	return s.srv.ListenAndServe()
}

// StartWithListener starts the server with a pre-created listener.
// This is useful for tests where you need to know the actual port.
func (s *Server) StartWithListener(ln net.Listener) error {
	s.listener = ln
	return s.srv.Serve(ln)
}

// Addr returns the server's address. Only valid after StartWithListener is called.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.srv.Addr
}
