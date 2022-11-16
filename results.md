Benchmark Results for fetching a single secret
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

Run 100 times
---

make benchmark
go generate ./...
go test -count=10 -benchtime=100x -bench=. ./...
?   	conjur-in-go	[no test files]
goos: darwin
goarch: amd64
pkg: conjur-in-go/benchmark
cpu: Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    644084 ns/op	     356 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    624305 ns/op	     362 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    626826 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    648527 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    674033 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    639176 ns/op	     356 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    662297 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    677202 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    716497 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/Cache_direct:_GET_/secrets-16         	     100	    646573 ns/op	     359 B/op	       8 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    828685 ns/op	    6889 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    996266 ns/op	    7137 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    835411 ns/op	    6976 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    861124 ns/op	    7058 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    826911 ns/op	    6891 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    849394 ns/op	    7140 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    924631 ns/op	    7140 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    995287 ns/op	    6894 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    842363 ns/op	    7140 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/DB_direct:_GET_/secrets-16            	     100	    843305 ns/op	    6973 B/op	     107 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4117212 ns/op	   19922 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4069482 ns/op	   19994 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   3878123 ns/op	   19960 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   3722230 ns/op	   19776 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   3913172 ns/op	   20006 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4127853 ns/op	   19814 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   3546159 ns/op	   19982 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4630458 ns/op	   19749 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4290392 ns/op	   20436 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang_with_cache:_GET_/secrets-16    	     100	   4441051 ns/op	   19811 B/op	     137 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4712750 ns/op	   19584 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4484905 ns/op	   19692 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4459201 ns/op	   19864 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4046840 ns/op	   19588 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4042410 ns/op	   19729 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   3882679 ns/op	   19630 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4637934 ns/op	   20907 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4245952 ns/op	   19590 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   5088842 ns/op	   19620 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Golang:_GET_/secrets-16               	     100	   4562208 ns/op	   19721 B/op	     135 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20832297 ns/op	   21405 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20838883 ns/op	   21411 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20901289 ns/op	   21425 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20950952 ns/op	   21408 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  21019579 ns/op	   21999 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20822646 ns/op	   21380 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20863719 ns/op	   21487 B/op	     157 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20815994 ns/op	   21320 B/op	     156 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  20857041 ns/op	   21315 B/op	     156 allocs/op
BenchmarkGetSecretsHandler/Ruby:_GET_/secrets-16                 	     100	  21105697 ns/op	   21420 B/op	     157 allocs/op
PASS
ok  	conjur-in-go/benchmark	31.681s
?   	conjur-in-go/cmd/conjurctl	[no test files]
?   	conjur-in-go/gen/encrypted_models	[no test files]
?   	conjur-in-go/pkg/model	[no test files]
?   	conjur-in-go/pkg/server	[no test files]
?   	conjur-in-go/pkg/server/endpoints	[no test files]
?   	conjur-in-go/pkg/slosilo	[no test files]
?   	conjur-in-go/pkg/slosilo/store	[no test files]
?   	conjur-in-go/pkg/utils	[no test files]