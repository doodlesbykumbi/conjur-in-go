package main

import (
	"conjur-in-go/pkg/slosilo"
	"database/sql"
	"encoding/base64"
	"fmt"

	_ "github.com/lib/pq"
)

func main() {
	const data_key = "FWxDdCYVP9XM+vHfn+YUGvIMJ/6XBsA3qaHZ+x3tC/0="

	data_key_decoded, _ := base64.StdEncoding.DecodeString(data_key)
	cipher, _ := slosilo.NewSymmetric(data_key_decoded)

	query_str := "INSERT INTO secrets (resource_id, value) VALUES \n"

	for i := 0; i < 150000; i++ {
		res_id := fmt.Sprintf("myConjurAccount:variable:BenchmarkSecrets/secret_%d", i)
		secret_bytes, _ := cipher.Encrypt([]byte(res_id), []byte("Hello, World!"))
		secret_b64 := base64.StdEncoding.EncodeToString(secret_bytes)

		query_str += fmt.Sprintf("('%s', decode('%s', 'base64')::bytea), ", res_id, secret_b64)
	}

	query_str = query_str[:len(query_str)-2]

	// fmt.Println(query_str)

	connStr := "user=postgres dbname=postgres sslmode=disable host=localhost port=8432"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	_, err = db.Query(query_str)
	if err != nil {
		panic(err)
	}
}
