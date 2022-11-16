package benchmark

import (
	"fmt"
	"net/http"
	"testing"
)

const token = "eyJwYXlsb2FkIjoiZXlKcFlYUWlPakUyTmpnMk1EUXlNak1zSW5OMVlpSTZJbUZrYldsdUluMD0iLCJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSmpiMjVxZFhJdWIzSm5MM05zYjNOcGJHOHZkaklpTENKcmFXUWlPaUpqTW1FM01HRTBORE5tWWpVek9UTTFZemd6Wmpnek4yVmxNVFUwWkRReE5qVmlZVFE0TVRaa05URXlZV1U0TkRWaE16RTBZekJqTVRjd056VXdOemN6SW4wPSIsInNpZ25hdHVyZSI6IkVpSGVTVmZGQnk1SWdmN0xud0dJVGE5Ty1jdGpzeG5tUHJaWFhCN0tGcTlhckVxQTlfbVR3SVRSUDNTTkhweFE4R0FKYTdkMWJrTG1Ea1RTNEVXaWdKWW15U2MycXp1em9XMnVqV3ZZX1Q0NGxXR1dxLV9kUHNWVHBoZlY2Z1R6UFhCQzJld1JHMTM1d3pLTnVqTXpZU3liZXlYY0hLVTFWVG9KSmV1b1F0dHhWeV9KWE1ncFZEWExvdzdhR1Y0QmNZX0lISVFhcXBld3E4ai1RMzQwWkljR2NpY0stbHJmTXVkX19jcUQtbG5NeUM0NHNVZ1dYNXVwYXdnLU5BcFNxeFZZczFacFRkUy15d3hFNHBhV2RIUFFSdmh3SWcwS0tIalgtT18zaWlKRmhSVTFHXzdYYjJ1WTJNbVNqV2lLRnpqS05WNTgzbmh5STZnRmU5TTlmaVZnTmpiQ2V4UVgzYVY1OEpWR2c5dlBOX0dRM0VXLWsxN29iMjVLWFdKQSJ9"

func BenchmarkGetPostsHandler(b *testing.B) {
	b.Run("Golang with cache: GET /posts", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			r, _ := http.NewRequest("GET", "http://localhost:8000/secrets/myConjurAccount/variable/BotApp/secretVar?use_cache", nil)
			r.Header.Add("Authorization", fmt.Sprintf("Token token=%q", token))
			_, _ = http.DefaultClient.Do(r)
		}
	})

	b.Run("Golang: GET /posts", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			r, _ := http.NewRequest("GET", "http://localhost:8000/secrets/myConjurAccount/variable/BotApp/secretVar", nil)
			r.Header.Add("Authorization", fmt.Sprintf("Token token=%q", token))
			_, _ = http.DefaultClient.Do(r)
		}
	})

	b.Run("Ruby: GET /posts", func(b *testing.B) {

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			r, _ := http.NewRequest("GET", "http://localhost:8080/secrets/myConjurAccount/variable/BotApp/secretVar", nil)
			r.Header.Add("Authorization", fmt.Sprintf("Token token=%q", token))
			_, _ = http.DefaultClient.Do(r)
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
