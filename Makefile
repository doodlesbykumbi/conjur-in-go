build: generate
	go build -o ./conjurctl ./cmd/conjurctl

generate:
	go generate ./...

benchmark: generate
	go test -count=10 -benchtime=100x -bench=. ./...
test: generate
	go test -count=1 -v ./...

install: generate
	go install ./cmd/conjurctl

# Example usage of run: make run ARGS="variable get -i path/to/var"
run: generate
	go run ./cmd/conjurctl $(ARGS)
