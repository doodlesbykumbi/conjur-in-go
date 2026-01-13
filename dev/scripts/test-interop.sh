#!/bin/bash
# Interoperability Test Script
# Tests that Go and Ruby Conjur can share the same database seamlessly
#
# Prerequisites:
#   - Docker Compose services running
#   - CONJUR_DATA_KEY environment variable set
#
# Usage:
#   ./test-interop.sh

set -e

ACCOUNT="interop"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "  Conjur Interoperability Test"
echo "=========================================="
echo
echo "This test verifies that:"
echo "  1. Go Conjur can create data that Ruby Conjur can read"
echo "  2. Ruby Conjur can create data that Go Conjur can read"
echo "  3. Both share the same database seamlessly"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

success() { echo -e "${GREEN}✓ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
error() { echo -e "${RED}✗ $1${NC}"; exit 1; }
go_action() { echo -e "${BLUE}[Go]${NC} $1"; }
ruby_action() { echo -e "${RED}[Ruby]${NC} $1"; }

cd "$SCRIPT_DIR"

# Step 1: Start Ruby Conjur if not running
info "Step 1: Ensuring Ruby Conjur is running..."
docker compose --profile ruby up -d conjur-ruby conjur-cli-ruby > /dev/null 2>&1
sleep 2
success "Ruby Conjur containers started"

# Step 2: Reset database
info "Step 2: Resetting database..."
docker compose restart postgres > /dev/null 2>&1
sleep 2
docker compose exec -T postgres psql -U conjur -d postgres -c "DROP DATABASE IF EXISTS conjur;" > /dev/null 2>&1
docker compose exec -T postgres psql -U conjur -d postgres -c "CREATE DATABASE conjur;" > /dev/null 2>&1
success "Database reset"

# Step 3: Restart both servers
info "Step 3: Restarting Go and Ruby servers..."
docker compose restart app > /dev/null 2>&1
docker compose --profile ruby restart conjur-ruby > /dev/null 2>&1
sleep 5
success "Servers restarted"

# Step 4: Run migrations via Go server (creates Sequel-compatible schema_migrations)
go_action "Running migrations..."
docker compose exec -T app go run ./cmd/conjurctl db migrate 2>&1 | grep -v "record not found" || true
success "Migrations complete (via Go)"

# Step 5: Create account via Go
go_action "Creating account '$ACCOUNT'..."
ACCOUNT_OUTPUT=$(docker compose exec -T app go run ./cmd/conjurctl account create "$ACCOUNT" 2>&1)
API_KEY=$(echo "$ACCOUNT_OUTPUT" | grep "API key" | awk '{print $NF}')
if [ -z "$API_KEY" ]; then
    echo "$ACCOUNT_OUTPUT"
    error "Failed to create account"
fi
success "Account created via Go"
echo "   Admin API Key: $API_KEY"
echo

# Step 6: Configure both CLIs
info "Step 6: Configuring CLIs..."
docker compose exec -T conjur-cli sh -c "echo 'account: $ACCOUNT
appliance_url: http://app:8000' > /root/.conjurrc"
docker compose exec -T conjur-cli-ruby sh -c "echo 'account: $ACCOUNT
appliance_url: http://conjur-ruby:80' > /root/.conjurrc"
success "CLIs configured"

# Step 7: Login to both servers
go_action "Logging in via Go server..."
docker compose exec -T conjur-cli conjur login -i admin -p "$API_KEY" > /dev/null 2>&1
success "Logged in to Go server"

ruby_action "Logging in via Ruby server..."
docker compose exec -T conjur-cli-ruby conjur login -i admin -p "$API_KEY" > /dev/null 2>&1
success "Logged in to Ruby server"
echo

# Step 8: Create resources via Go, read via Ruby
echo "--- Test 1: Go creates, Ruby reads ---"
go_action "Creating variable via Go..."
GO_POLICY='- !variable
  id: go-created-secret
'
echo "$GO_POLICY" | docker compose exec -T conjur-cli conjur policy load -b root -f - > /dev/null 2>&1
success "Variable created via Go"

go_action "Setting secret via Go..."
docker compose exec -T conjur-cli conjur variable set -i go-created-secret -v "secret-from-go-server" > /dev/null 2>&1
success "Secret set via Go"

ruby_action "Reading secret via Ruby..."
RUBY_READ=$(docker compose exec -T conjur-cli-ruby conjur variable get -i go-created-secret 2>/dev/null)
if [ "$RUBY_READ" = "secret-from-go-server" ]; then
    success "Ruby successfully read Go-created secret: $RUBY_READ"
else
    error "Ruby failed to read Go-created secret. Got: $RUBY_READ"
fi
echo

# Step 9: Create resources via Ruby, read via Go
echo "--- Test 2: Ruby creates, Go reads ---"
ruby_action "Creating variable via Ruby..."
RUBY_POLICY='- !variable
  id: ruby-created-secret
'
echo "$RUBY_POLICY" | docker compose exec -T conjur-cli-ruby conjur policy load -b root -f - > /dev/null 2>&1
success "Variable created via Ruby"

ruby_action "Setting secret via Ruby..."
docker compose exec -T conjur-cli-ruby conjur variable set -i ruby-created-secret -v "secret-from-ruby-server" > /dev/null 2>&1
success "Secret set via Ruby"

go_action "Reading secret via Go..."
GO_READ=$(docker compose exec -T conjur-cli conjur variable get -i ruby-created-secret 2>/dev/null)
if [ "$GO_READ" = "secret-from-ruby-server" ]; then
    success "Go successfully read Ruby-created secret: $GO_READ"
else
    error "Go failed to read Ruby-created secret. Got: $GO_READ"
fi
echo

# Step 10: List resources from both
echo "--- Test 3: Both see all resources ---"
go_action "Listing resources via Go..."
GO_LIST=$(docker compose exec -T conjur-cli conjur list 2>/dev/null)
echo "$GO_LIST"

ruby_action "Listing resources via Ruby..."
RUBY_LIST=$(docker compose exec -T conjur-cli-ruby conjur list 2>/dev/null)
echo "$RUBY_LIST"

# Verify both lists contain the same resources
if echo "$GO_LIST" | grep -q "go-created-secret" && echo "$GO_LIST" | grep -q "ruby-created-secret"; then
    success "Go sees both secrets"
else
    error "Go doesn't see all secrets"
fi

if echo "$RUBY_LIST" | grep -q "go-created-secret" && echo "$RUBY_LIST" | grep -q "ruby-created-secret"; then
    success "Ruby sees both secrets"
else
    error "Ruby doesn't see all secrets"
fi
echo

echo "=========================================="
echo -e "${GREEN}  Interoperability Test PASSED!${NC}"
echo "=========================================="
echo
echo "Summary:"
echo "  - Go server: http://localhost:8000"
echo "  - Ruby server: http://localhost:3000"
echo "  - Both servers share the same PostgreSQL database"
echo "  - Data created by either server is accessible by both"
echo
echo "Architecture:"
echo "  - Go uses 'go_schema_migrations' table for golang-migrate"
echo "  - Ruby uses 'schema_migrations' table (Sequel format)"
echo "  - Both tables are kept in sync automatically"
echo
echo "Try these commands:"
echo "  # Via Go server"
echo "  docker compose exec conjur-cli conjur list"
echo "  docker compose exec conjur-cli conjur variable get -i go-created-secret"
echo
echo "  # Via Ruby server"
echo "  docker compose exec conjur-cli-ruby conjur list"
echo "  docker compose exec conjur-cli-ruby conjur variable get -i ruby-created-secret"
