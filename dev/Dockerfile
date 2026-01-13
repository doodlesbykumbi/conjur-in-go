FROM golang:1.22-alpine

# Install reflex for hot reloading
RUN go install github.com/cespare/reflex@latest

# Install golang-migrate for database migrations
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@v4.17.0

# Install useful dev tools
RUN apk add --no-cache git make

WORKDIR /app

# Pre-download dependencies (will be cached in volume)
COPY go.mod go.sum ./
RUN go mod download

EXPOSE 8000

CMD ["reflex", "-c", "/app/dev/reflex.conf"]
