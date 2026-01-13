package audit

import (
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStoreSave(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := NewStoreWithDB(db)

	event := FetchEvent{
		UserID:     "myorg:user:admin",
		ClientIP:   "10.0.0.1",
		ResourceID: "myorg:variable:db/password",
		Success:    true,
	}

	mock.ExpectExec(`INSERT INTO messages`).
		WithArgs(
			FacilityAuthPriv,  // facility
			int(SeverityInfo), // severity
			sqlmock.AnyArg(),  // timestamp
			sqlmock.AnyArg(),  // hostname
			"conjur",          // appname
			sqlmock.AnyArg(),  // procid
			"fetch",           // msgid
			sqlmock.AnyArg(),  // sdata (JSON)
			sqlmock.AnyArg(),  // message
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Save(event)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSaveAuthenticateEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := NewStoreWithDB(db)

	event := AuthenticateEvent{
		RoleID:            "myorg:user:admin",
		ClientIP:          "192.168.1.1",
		AuthenticatorName: "authn",
		Success:           true,
	}

	mock.ExpectExec(`INSERT INTO messages`).
		WithArgs(
			FacilityAuthPriv,
			int(SeverityInfo),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"conjur",
			sqlmock.AnyArg(),
			"authn",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Save(event)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSaveFailedEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := NewStoreWithDB(db)

	event := FetchEvent{
		UserID:       "myorg:user:admin",
		ClientIP:     "10.0.0.1",
		ResourceID:   "myorg:variable:db/password",
		Success:      false,
		ErrorMessage: "permission denied",
	}

	mock.ExpectExec(`INSERT INTO messages`).
		WithArgs(
			FacilityAuthPriv,
			int(SeverityWarning), // Failed events have warning severity
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"conjur",
			sqlmock.AnyArg(),
			"fetch",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Save(event)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreNilDB(t *testing.T) {
	store := &Store{db: nil}

	event := FetchEvent{
		UserID:     "myorg:user:admin",
		ClientIP:   "10.0.0.1",
		ResourceID: "myorg:variable:db/password",
		Success:    true,
	}

	// Should not error when db is nil
	err := store.Save(event)
	if err != nil {
		t.Errorf("Save() with nil db should not error, got: %v", err)
	}
}

func TestStoreClose(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	store := NewStoreWithDB(db)

	mock.ExpectClose()

	err = store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreCloseNilDB(t *testing.T) {
	store := &Store{db: nil}

	err := store.Close()
	if err != nil {
		t.Errorf("Close() with nil db should not error, got: %v", err)
	}
}

func TestStoreSavePolicyEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := NewStoreWithDB(db)

	event := PolicyEvent{
		UserID:        "myorg:user:admin",
		ClientIP:      "10.0.0.1",
		ResourceID:    "myorg:policy:root",
		PolicyVersion: 5,
		Operation:     "update",
		Success:       true,
	}

	mock.ExpectExec(`INSERT INTO messages`).
		WithArgs(
			FacilityAuthPriv,
			int(SeverityInfo),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"conjur",
			sqlmock.AnyArg(),
			"policy",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Save(event)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestStoreSaveHostFactoryEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	store := NewStoreWithDB(db)

	event := HostFactoryEvent{
		UserID:        "myorg:user:admin",
		ClientIP:      "10.0.0.1",
		HostFactoryID: "myorg:host_factory:servers",
		Operation:     "create-host",
		HostID:        "myorg:host:server-01",
		Success:       true,
	}

	mock.ExpectExec(`INSERT INTO messages`).
		WithArgs(
			FacilityAuthPriv,
			int(SeverityInfo),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"conjur",
			sqlmock.AnyArg(),
			"host-factory",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = store.Save(event)
	if err != nil {
		t.Errorf("Save() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestMessage(t *testing.T) {
	msg := Message{
		Facility:  FacilityAuthPriv,
		Severity:  int(SeverityInfo),
		Timestamp: time.Now(),
		Hostname:  "localhost",
		Appname:   "conjur",
		Procid:    "12345",
		Msgid:     "fetch",
		Sdata:     map[string]any{"auth@43868": map[string]any{"user": "admin"}},
		Message:   "admin fetched secret",
	}

	if msg.Facility != FacilityAuthPriv {
		t.Errorf("Message.Facility = %v, want %v", msg.Facility, FacilityAuthPriv)
	}
	if msg.Msgid != "fetch" {
		t.Errorf("Message.Msgid = %v, want 'fetch'", msg.Msgid)
	}
}
