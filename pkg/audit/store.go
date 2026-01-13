package audit

import (
	"database/sql"
	"encoding/json"
	"os"
	"time"
)

// Store handles audit message persistence to database
type Store struct {
	db *sql.DB
}

// Message represents an audit message for database persistence
type Message struct {
	Facility  int            `json:"facility"`
	Severity  int            `json:"severity"`
	Timestamp time.Time      `json:"timestamp"`
	Hostname  string         `json:"hostname"`
	Appname   string         `json:"appname"`
	Procid    string         `json:"procid"`
	Msgid     string         `json:"msgid"`
	Sdata     map[string]any `json:"sdata"`
	Message   string         `json:"message"`
}

// NewStore creates a new audit store from AUDIT_DATABASE_URL
// Returns nil if AUDIT_DATABASE_URL is not set (audit DB disabled)
func NewStore() (*Store, error) {
	dbURL := os.Getenv("AUDIT_DATABASE_URL")
	if dbURL == "" {
		return nil, nil
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// NewStoreWithDB creates a store with an existing database connection
// Useful for testing with sqlmock
func NewStoreWithDB(db *sql.DB) *Store {
	return &Store{db: db}
}

// Close closes the database connection
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Save persists an audit event to the database
func (s *Store) Save(event Event) error {
	if s.db == nil {
		return nil
	}

	hostname, _ := os.Hostname()
	sdata := event.StructuredData()

	sdataJSON, err := json.Marshal(sdata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT INTO messages (facility, severity, timestamp, hostname, appname, procid, msgid, sdata, message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`,
		event.Facility(),
		int(event.Severity()),
		time.Now().UTC(),
		hostname,
		"conjur",
		os.Getpid(),
		event.MessageID(),
		sdataJSON,
		event.Message(),
	)

	return err
}

// DB returns the underlying database connection (for testing)
func (s *Store) DB() *sql.DB {
	return s.db
}
