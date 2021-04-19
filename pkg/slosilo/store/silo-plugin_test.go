package store

import (
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Suite struct {
	suite.Suite
	DB   *gorm.DB
	mock sqlmock.Sqlmock
}

func (s *Suite) SetupSuite() {
	var (
		db  *sql.DB
		err error
	)

	db, s.mock, err = sqlmock.New()
	require.NoError(s.T(), err)

	s.DB, err = gorm.Open(postgres.New(postgres.Config{Conn: db}), &gorm.Config{})
	require.NoError(s.T(), err)
	dataKey, err := base64.StdEncoding.DecodeString("6QrDHLBWYXieY5FM5DlRWRXX/wA8hefCuwMciHQ5ms0=")
	require.NoError(s.T(), err)
	_, err = NewKeyStore(s.DB, []byte(dataKey))
	require.NoError(s.T(), err)
}

// AfterTest comment
func (s *Suite) AfterTest(_, _ string) {
	require.NoError(s.T(), s.mock.ExpectationsWereMet())
}

func TestSiloDBPlugin(t *testing.T) {
	suite.Run(t, new(Suite))
}

type TestEncryption struct {
	ID           uint64 `json:"id" gorm:"primary_key"`
	Content      string `silo:"encrypted"`
	AnotherField string `silo:"aad"`
}

type TestNoEncryption struct {
	ID           uint64 `json:"id" gorm:"primary_key"`
	Content      string
	AnotherField string
}

// Used to verify that the database query does not contain the content
// that should be encrypted
// There isn't really a good way to verify that the field is indeed encrypted,
// though
type negativeMatchArgument struct{}

func (n negativeMatchArgument) Match(s driver.Value) bool {
	return !strings.HasPrefix(s.(string), "encrypted Content")
}

func (s *Suite) TestReadUnencryptedData() {
	unencryptedRecord := TestNoEncryption{}
	var readRecords []TestNoEncryption
	unencryptedResult := TestNoEncryption{
		ID:           1,
		Content:      "unencrypted Content",
		AnotherField: "unencrypted AnotherField",
	}
	// First unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_no_encryptions" ORDER BY "test_no_encryptions"."id" LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(1, "unencrypted Content", "unencrypted AnotherField"))
	// Last unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_no_encryptions" ORDER BY "test_no_encryptions"."id" DESC LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(2, "unencrypted Content", "unencrypted AnotherField"))
	// Take unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_no_encryptions" LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(3, "unencrypted Content", "unencrypted AnotherField"))
	// Find unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_no_encryptions"`)).
		WillReturnRows(
			sqlmock.NewRows([]string{"id", "content", "another_field"}).
				AddRow(4, "unencrypted Content", "unencrypted AnotherField"))
	s.DB.First(&unencryptedRecord)
	assert.Equal(s.T(), unencryptedRecord, unencryptedResult)
	unencryptedRecord = TestNoEncryption{}
	unencryptedResult.ID = 2
	s.DB.Last(&unencryptedRecord)
	assert.Equal(s.T(), unencryptedRecord, unencryptedResult)
	unencryptedRecord = TestNoEncryption{}
	unencryptedResult.ID = 3
	s.DB.Take(&unencryptedRecord)
	assert.Equal(s.T(), unencryptedRecord, unencryptedResult)
	unencryptedResult.ID = 4
	s.DB.Find(&readRecords)
	assert.Equal(s.T(), len(readRecords), 1)
	assert.Equal(s.T(), readRecords[0], unencryptedResult)
}

func (s *Suite) TestReadEncryptedData() {
	encryptedContent := s.DB.Plugins["silo"].(siloPlugin).encrypt("encrypted Content", "unencrypted AnotherField")

	encryptedRecord := TestEncryption{}
	var readRecords []TestEncryption
	encryptedResult := TestEncryption{
		ID:           1,
		Content:      "encrypted Content",
		AnotherField: "unencrypted AnotherField",
	}

	// Find encrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_encryptions" ORDER BY "test_encryptions"."id" LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(1, encryptedContent, "unencrypted AnotherField"))
	// Last unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_encryptions" ORDER BY "test_encryptions"."id" DESC LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(2, encryptedContent, "unencrypted AnotherField"))
	// Take unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_encryptions" LIMIT 1`)).
		WithArgs().
		WillReturnRows(sqlmock.NewRows([]string{"id", "content", "another_field"}).
			AddRow(3, encryptedContent, "unencrypted AnotherField"))
	// Find unencrypted
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_encryptions"`)).
		WillReturnRows(
			sqlmock.NewRows([]string{"id", "content", "another_field"}).
				AddRow(4, encryptedContent, "unencrypted AnotherField"))

	s.DB.First(&encryptedRecord)
	assert.Equal(s.T(), encryptedRecord, encryptedResult)
	encryptedRecord = TestEncryption{}
	encryptedResult.ID = 2
	s.DB.Last(&encryptedRecord)
	assert.Equal(s.T(), encryptedRecord, encryptedResult)
	encryptedRecord = TestEncryption{}
	encryptedResult.ID = 3
	s.DB.Take(&encryptedRecord)
	assert.Equal(s.T(), encryptedRecord, encryptedResult)
	encryptedRecord = TestEncryption{}
	encryptedResult.ID = 4
	s.DB.Find(&readRecords)
	assert.Equal(s.T(), len(readRecords), 1)
	assert.Equal(s.T(), readRecords[0], encryptedResult)
}

func (s *Suite) TestWriteUnencryptedData() {
	record := TestNoEncryption{
		Content:      "non-encrypted Content",
		AnotherField: "non-encrypted AnotherField",
	}

	resultRecord := TestNoEncryption{
		ID:           1,
		Content:      "non-encrypted Content",
		AnotherField: "non-encrypted AnotherField",
	}

	batchRecords := []TestNoEncryption{
		{Content: "batch Content 2", AnotherField: "batch AnotherField 2"},
		{Content: "batch Content 3", AnotherField: "batch AnotherField 3"},
	}

	resultBatchRecords := []TestNoEncryption{
		{ID: 2, Content: "batch Content 2", AnotherField: "batch AnotherField 2"},
		{ID: 3, Content: "batch Content 3", AnotherField: "batch AnotherField 3"},
	}

	s.mock.ExpectBegin()
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`INSERT INTO "test_no_encryptions" ("content","another_field") VALUES ($1,$2) RETURNING "id"`)).
		WithArgs("non-encrypted Content", "non-encrypted AnotherField").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	s.mock.ExpectCommit()

	s.mock.ExpectBegin()
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`INSERT INTO "test_no_encryptions" ("content","another_field") VALUES ($1,$2),($3,$4) RETURNING "id"`)).
		WithArgs("batch Content 2", "batch AnotherField 2", "batch Content 3", "batch AnotherField 3").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2).AddRow(3))
	s.mock.ExpectCommit()

	s.DB.Create(&record)
	assert.Equal(s.T(), record, resultRecord)

	s.DB.Create(&batchRecords)
	assert.Equal(s.T(), batchRecords, resultBatchRecords)
}

func (s *Suite) TestWriteEncryptedData() {
	record := TestEncryption{
		Content:      "encrypted Content",
		AnotherField: "non-encrypted AnotherField",
	}

	// TODO: Update to expected decrypted (original) value
	resultRecord := TestEncryption{
		ID:           1,
		Content:      "encrypted Content",
		AnotherField: "non-encrypted AnotherField",
	}

	batchRecords := []TestEncryption{
		{Content: "encrypted Content 2", AnotherField: "non-encrypted AnotherField 2"},
		{Content: "encrypted Content 3", AnotherField: "non-encrypted AnotherField 3"},
	}

	// TODO: Update to expected decrypted (original) values
	resultBatchRecords := []TestEncryption{
		{ID: 2, Content: "encrypted Content 2", AnotherField: "non-encrypted AnotherField 2"},
		{ID: 3, Content: "encrypted Content 3", AnotherField: "non-encrypted AnotherField 3"},
	}

	// TODO: Update to expected encrypted value
	s.mock.ExpectBegin()
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`INSERT INTO "test_encryptions" ("content","another_field") VALUES ($1,$2) RETURNING "id"`)).
		WithArgs(negativeMatchArgument{}, "non-encrypted AnotherField").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
	s.mock.ExpectCommit()

	// TODO: Update to expected encrypted values
	s.mock.ExpectBegin()
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`INSERT INTO "test_encryptions" ("content","another_field") VALUES ($1,$2),($3,$4) RETURNING "id"`)).
		WithArgs(negativeMatchArgument{}, "non-encrypted AnotherField 2", negativeMatchArgument{}, "non-encrypted AnotherField 3").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(2).AddRow(3))
	s.mock.ExpectCommit()

	s.DB.Create(&record)
	assert.Equal(s.T(), record, resultRecord)

	s.DB.Create(&batchRecords)
	assert.Equal(s.T(), batchRecords, resultBatchRecords)
}

func (s *Suite) TestUpdateUnencrypted() {
	var record TestNoEncryption

	// Base Record
	s.mock.ExpectQuery(regexp.QuoteMeta(
		`SELECT * FROM "test_no_encryptions" ORDER BY "test_no_encryptions"."id" LIMIT 1`)).
		WillReturnRows(
			sqlmock.NewRows([]string{"id", "content", "another_field"}).
				AddRow(1, "non-encrypted Content", "non-encrypted AnotherField"))
	// Save
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_no_encryptions" SET "content"=$1,"another_field"=$2 WHERE "id" = $3`)).
		WithArgs("second non-encrypted Content", "non-encrypted AnotherField", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()
	// Update single column
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_no_encryptions" SET "another_field"=$1 WHERE "id" = $2`)).
		WithArgs("second non-encrypted AnotherField", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()
	// Update multiple columns
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_no_encryptions" SET "content"=$1,"another_field"=$2 WHERE "id" = $3`)).
		WithArgs("content", "anotherField", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()

	s.DB.First(&record)
	record.Content = "second non-encrypted Content"
	result := s.DB.Save(&record)
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
	result = s.DB.Model(&record).Update("another_field", "second non-encrypted AnotherField")
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
	result = s.DB.Model(&record).Updates(TestNoEncryption{Content: "content", AnotherField: "anotherField"})
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
}

func (s *Suite) TestUpdateEncrypted() {
	record := TestEncryption{
		ID:           1,
		Content:      "encrypted Content",
		AnotherField: "non-encrypted AnotherField",
	}

	// Save
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_encryptions" SET "content"=$1,"another_field"=$2 WHERE "id" = $3`)).
		WithArgs(negativeMatchArgument{}, "non-encrypted AnotherField", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()
	// Update single column
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_encryptions" SET "content"=$1 WHERE "id" = $2`)).
		WithArgs(negativeMatchArgument{}, 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()
	// Update multiple columns
	s.mock.ExpectBegin()
	s.mock.ExpectExec(regexp.QuoteMeta(
		`UPDATE "test_encryptions" SET "content"=$1,"another_field"=$2 WHERE "id" = $3`)).
		WithArgs(negativeMatchArgument{}, "anotherField", 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	s.mock.ExpectCommit()

	record.Content = "encrypted Content 2"
	result := s.DB.Save(&record)
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
	result = s.DB.Model(&record).Update("Content", "encrypted Content 3")
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
	result = s.DB.Model(&record).Updates(TestEncryption{Content: "content 4", AnotherField: "anotherField"})
	assert.Equal(s.T(), result.RowsAffected, int64(1))
	assert.Nil(s.T(), result.Error)
}

// assert.Panics(s.T(), func() {functionThatPanics(arg)}, "The code did not panic")
