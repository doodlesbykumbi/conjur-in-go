Benchmark Results
===

401
---

goos: darwin
goarch: amd64
pkg: conjur-in-go/benchmark
cpu: Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16         	    1785	    692410 ns/op	   20556 B/op	     147 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16                    	    1914	    709939 ns/op	   20363 B/op	     145 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                      	     100	  20211164 ns/op	   19698 B/op	     137 allocs/op

OK with 1 secret
---

goos: darwin
goarch: amd64
pkg: conjur-in-go/benchmark
cpu: Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16         	     346	   3505989 ns/op	   20559 B/op	     148 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16                    	     325	   3745859 ns/op	   20485 B/op	     146 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                      	     100	  20946452 ns/op	   21378 B/op	     156 allocs/op

OK with 150,000 secrets
---

go generate ./...
go test -bench=. ./...
?   	conjur-in-go	[no test files]
goos: darwin
goarch: amd64
pkg: conjur-in-go/benchmark
cpu: Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16         	     370	   3257191 ns/op	   20624 B/op	     149 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16                    	     327	   3817279 ns/op	   20452 B/op	     147 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                      	     100	  21107252 ns/op	   21284 B/op	     156 allocs/op

OK with 150,000 secrets without Authz
---

