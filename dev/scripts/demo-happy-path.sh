#!/bin/bash
# Happy Path Demo Script for Conjur-in-Go
# This script demonstrates the full workflow from scratch

set -e

ACCOUNT="demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "  Conjur-in-Go Happy Path Demo"
echo "=========================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✓ $1${NC}"; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
error() { echo -e "${RED}✗ $1${NC}"; exit 1; }

cd "$SCRIPT_DIR"

# Step 1: Reset database
info "Step 1: Resetting database..."
docker compose restart postgres > /dev/null 2>&1
sleep 2
docker compose exec -T postgres psql -U conjur -d postgres -c "DROP DATABASE IF EXISTS conjur;" > /dev/null 2>&1
docker compose exec -T postgres psql -U conjur -d postgres -c "CREATE DATABASE conjur;" > /dev/null 2>&1
success "Database reset"

# Step 2: Restart app to pick up fresh database
info "Step 2: Restarting application..."
docker compose restart app > /dev/null 2>&1
sleep 3
success "Application restarted"

# Step 3: Run migrations
info "Step 3: Running database migrations..."
docker compose exec -T app go run ./cmd/conjurctl db migrate > /dev/null 2>&1
success "Migrations complete"

# Step 4: Create account
info "Step 4: Creating account '$ACCOUNT'..."
ACCOUNT_OUTPUT=$(docker compose exec -T app go run ./cmd/conjurctl account create "$ACCOUNT" 2>&1)
API_KEY=$(echo "$ACCOUNT_OUTPUT" | grep "API key" | awk '{print $NF}')
if [ -z "$API_KEY" ]; then
    error "Failed to create account"
fi
success "Account created"
echo "   Admin API Key: $API_KEY"
echo

# Step 5: Configure CLI
info "Step 5: Configuring Conjur CLI..."
docker compose exec -T conjur-cli sh -c "echo 'account: $ACCOUNT
appliance_url: http://app:8000' > /root/.conjurrc"
success "CLI configured"

# Step 6: Login with CLI
info "Step 6: Logging in as admin..."
docker compose exec -T conjur-cli conjur login -i admin -p "$API_KEY" > /dev/null 2>&1
success "Logged in as admin"

# Step 7: Verify identity
info "Step 7: Verifying identity..."
WHOAMI=$(docker compose exec -T conjur-cli conjur whoami 2>&1)
echo "$WHOAMI"
success "Identity verified"
echo

# Step 8: Load a policy with nested policy, hosts, groups, and variables
info "Step 8: Loading policy..."
POLICY='- !policy
  id: myapp
  body:
    - !variable
      id: db-password
    - !variable
      id: api-key
    
    - !host
      id: frontend
    - !host
      id: backend
    
    - !group
      id: secrets-users
    
    - !permit
      role: !group secrets-users
      privileges:
        - read
        - execute
      resources:
        - !variable db-password
        - !variable api-key
    
    - !grant
      role: !group secrets-users
      members:
        - !host frontend
        - !host backend
'
echo "$POLICY" | docker compose exec -T conjur-cli conjur policy load -b root -f - > /dev/null 2>&1
success "Policy loaded"

# Step 9: List resources
info "Step 9: Listing resources..."
docker compose exec -T conjur-cli conjur list
echo
success "Resources listed"

# Step 10: Set secret values
info "Step 10: Setting secret values..."
docker compose exec -T conjur-cli conjur variable set -i myapp/db-password -v "postgres://user:pass@db:5432/mydb" > /dev/null 2>&1
docker compose exec -T conjur-cli conjur variable set -i myapp/api-key -v "sk-abc123xyz789" > /dev/null 2>&1
success "Secrets stored"

# Step 11: Retrieve secrets
info "Step 11: Retrieving secrets..."
echo "   db-password: $(docker compose exec -T conjur-cli conjur variable get -i myapp/db-password 2>/dev/null)"
echo "   api-key: $(docker compose exec -T conjur-cli conjur variable get -i myapp/api-key 2>/dev/null)"
success "Secrets retrieved"
echo

# Step 12: Show resource details
info "Step 12: Showing resource details..."
docker compose exec -T conjur-cli conjur resource show "$ACCOUNT:variable:myapp/db-password" 2>&1 || true
success "Resource details shown"

echo
echo "=========================================="
echo -e "${GREEN}  Demo Complete!${NC}"
echo "=========================================="
echo
echo "Summary:"
echo "  - Account: $ACCOUNT"
echo "  - Admin API Key: $API_KEY"
echo "  - Resources created: policy, variables, hosts, groups"
echo "  - Permissions granted via !permit and !grant"
echo "  - Secrets stored and retrieved successfully"
echo
echo "Try these commands:"
echo "  docker compose exec conjur-cli conjur list"
echo "  docker compose exec conjur-cli conjur variable get -i myapp/db-password"
echo "  docker compose exec conjur-cli conjur whoami"
