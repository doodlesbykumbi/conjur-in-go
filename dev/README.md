# Development Environment

This folder contains the Docker Compose setup for local development.

## Services

| Service   | Description                  | Port  |
|-----------|------------------------------|-------|
| app       | Go application with reflex   | 8000  |
| postgres  | PostgreSQL 15                | 5432  |
| pgadmin   | pgAdmin 4 web interface      | 5050  |

## Quick Start

1. **Copy the environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Generate a data key:**
   ```bash
   # Option 1: Using openssl
   openssl rand -base64 32
   
   # Option 2: Using the app (after first build)
   docker compose run --rm app go run ./cmd/conjurctl data-key generate
   ```

3. **Add the generated key to `.env`:**
   ```
   CONJUR_DATA_KEY=<your-generated-key>
   ```

4. **Start the development environment:**
   ```bash
   docker compose up
   ```

5. **Access the services:**
   - **App:** http://localhost:8000
   - **pgAdmin:** http://localhost:5050 (login: admin@conjur.local / admin)

## Hot Reloading

The app service uses [reflex](https://github.com/cespare/reflex) for hot reloading. Any changes to `.go` files will automatically trigger a rebuild and restart of the server.

## Volumes

- `go-modules` - Cached Go modules (persists across container restarts)
- `go-build-cache` - Go build cache (speeds up rebuilds)
- `postgres-data` - PostgreSQL data
- `pgadmin-data` - pgAdmin configuration

## Useful Commands

```bash
# Start all services
./cli start

# View logs
./cli logs app

# Rebuild the app container
./cli build

# Run tests
./cli test

# Open a shell in the app container
./cli shell

# Stop all services
./cli stop

# Stop and remove volumes (clean slate)
./cli destroy

# Run happy path demo
./cli demo

# Run Go-Ruby interoperability tests
./cli test-interop
```

## Database Commands

```bash
# Run migrations
./cli migrate

# Check migration status
./cli migrate-status

# Rollback migrations
./cli migrate-down      # Rollback 1
./cli migrate-down 3    # Rollback 3
```

## Account Management

```bash
# Create a new account (generates admin API key)
./cli account-create myorg

# Create default account
./cli account-create
```

## Policy Loading

```bash
# Load a policy file
./cli policy-load myorg /app/examples/policy.yml

# Or via HTTP API (when server is running)
curl -X POST http://localhost:8000/policies/myorg/policy/root \
  -H "Content-Type: application/x-yaml" \
  --data-binary @examples/policy.yml
```

## Using conjurctl Directly

The Go CLI `conjurctl` can be used directly inside the container:

```bash
# Run migrations
./cli exec go run ./cmd/conjurctl db migrate

# Create account
./cli exec go run ./cmd/conjurctl account create myorg

# Load policy
./cli exec go run ./cmd/conjurctl policy load myorg /app/examples/policy.yml

# Start server (migrations run automatically)
./cli exec go run ./cmd/conjurctl server

# Start server without migrations
./cli exec go run ./cmd/conjurctl server --no-migrate
```

## Database Access

### Via psql
```bash
docker compose exec postgres psql -U conjur -d conjur
```

### Via pgAdmin
1. Open http://localhost:5050
2. Login with `admin@example.com` / `admin`
3. The "Conjur Dev" server is pre-configured (password: `conjur`)

---

## Roadmap

See [ROADMAP.md](../ROADMAP.md) for detailed feature status and future plans.
