package benchmark

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const api_key = "1n2tgbz2q2p9rb3rjtjfafsha3g185z8hk3ctnms2yed6932pzy3sv"

var token string
var rand_generator *rand.Rand

type Secret struct {
	ResourceId string
	Value      []byte `slosilo:";encrypted;aad:ResourceId;"`
}

func (s Secret) TableName() string {
	return "secrets"
}

func BenchmarkGetSecretsHandler(b *testing.B) {
	r, _ := http.NewRequest("POST", "http://localhost:8080/authn/myConjurAccount/admin/authenticate", ioutil.NopCloser(strings.NewReader(api_key)))
	r.Header.Add("Accept-Encoding", "base64")
	token_resp, _ := http.DefaultClient.Do(r)
	token_bytes, _ := ioutil.ReadAll(token_resp.Body)
	token = string(token_bytes)

	rand_generator = rand.New(rand.NewSource(time.Now().UnixNano()))

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	defer rdb.Close()

	db, _ := gorm.Open(
		postgres.New(
			postgres.Config{
				DSN:                  "postgres://postgres@localhost:8432/postgres",
				PreferSimpleProtocol: true, // disables implicit prepared statement usage
			},
		),
		&gorm.Config{},
	)
	b.Run("Cache direct: GET /secrets", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			secret_num := rand_generator.Intn(150000)

			resourceId := fmt.Sprintf("myConjurAccount:variable:BenchmarkSecrets/secret_%d", secret_num)
			rdb.Get(context.Background(), resourceId).Result()
		}
	})

	b.Run("DB direct: GET /secrets", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			secret_num := rand_generator.Intn(150000)

			resourceId := fmt.Sprintf("myConjurAccount:variable:BenchmarkSecrets/secret_%d", secret_num)
			var secret Secret
			query := map[string]interface{}{"resource_id": resourceId}

			tx := db.Order("version desc").Where(query).First(&secret)
			err := tx.Error
			if err != nil {
				panic(err)
			}

		}
	})

	b.Run("Golang with cache: GET /secrets", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			doRequest(8000, true)
		}
	})

	b.Run("Golang: GET /secrets", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			doRequest(8000, false)
		}
	})

	b.Run("Ruby: GET /secrets", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			doRequest(8080, false)
		}
	})
}

// func BenchmarkGetPostsHandlerParallel(b *testing.B) {
// 	b.RunParallel(func(pb *testing.PB) {
// 		GetPosts = (&JsonPlaceholderMock{}).GetPosts
// 		r, _ := http.NewRequest("GET", "/posts", nil)
// 		w := httptest.NewRecorder()
// 		handler := http.HandlerFunc(PostsResource{}.List)

// 		b.ReportAllocs()
// 		b.ResetTimer()

// 		for pb.Next() {
// 			handler.ServeHTTP(w, r)
// 		}
// 	})
// }

func doRequest(port int, use_cache bool) {
	secret_num := rand_generator.Intn(150000)
	target_url := fmt.Sprintf("http://localhost:%d/secrets/myConjurAccount/variable/BenchmarkSecrets/secret_%d", port, secret_num)
	if use_cache {
		target_url += "?use_cache"
	}
	r, _ := http.NewRequest("GET", target_url, nil)
	r.Header.Add("Authorization", fmt.Sprintf("Token token=%q", token))
	_, _ = http.DefaultClient.Do(r)
	// resp, _ := http.DefaultClient.Do(r)
	// fmt.Println(resp.StatusCode)
}
