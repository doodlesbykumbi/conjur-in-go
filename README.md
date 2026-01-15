# Conjur-in-Go

A Go implementation of [CyberArk Conjur](https://github.com/cyberark/conjur), designed to be fully interoperable with Conjur OSS (Ruby). Both servers can share the same PostgreSQL database and serve requests interchangeably.

## Features

### Core Functionality
- **Authentication** - Pluggable authenticator architecture supporting:
  - `authn` - API key authentication with encrypted credentials
  - `authn-jwt` - JWT authentication with inline JWKS or provider URI
- **Authorization** - Full RBAC using PostgreSQL stored procedures
- **Secrets Management** - Store, retrieve, version, and batch update secrets
- **Policy Engine** - YAML policy parser supporting all resource types
- **Host Factories** - Automated host enrollment with tokens
- **Audit Logging** - RFC5424 syslog format matching Ruby Conjur

### API Endpoints

| Category | Endpoints |
|----------|-----------|
| **Authentication** | Login, authenticate, rotate API key, update password |
| **Policies** | Load (POST/PUT/PATCH), get versions, dry-run validation |
| **Secrets** | Get, set, batch fetch, batch update, versioning |
| **Resources** | List, show, permission check, permitted roles, annotations CRUD |
| **Roles** | Show, members, memberships, add/remove members |
| **Host Factory** | Create/revoke tokens, create hosts |
| **Public Keys** | Fetch SSH public keys for users/hosts |

### Slosilo Crypto
Full Go port of [Slosilo](https://github.com/cyberark/slosilo):
- AES-256-GCM symmetric encryption
- RSA-PSS signing for JWT tokens
- Compatible with Ruby Conjur's encrypted data

## Quick Start

### Using Docker (Recommended)

```bash
cd dev
cp .env.example .env
./cli setup      # Generate data key and build containers
./cli start      # Start all services
./cli demo       # Run happy path demo
```

### Manual Build

```bash
go build -o conjurctl ./cmd/conjurctl

DATABASE_URL="postgres://conjur:conjur@localhost:5432/conjur?sslmode=disable" \
CONJUR_DATA_KEY="$(openssl rand -base64 32)" \
./conjurctl server
```

## CLI Commands

```bash
conjurctl server                    # Start HTTP server (auto-migrates)
conjurctl server --no-migrate       # Start without migrations
conjurctl account create <name>     # Create account (generates admin API key)
conjurctl db migrate                # Run database migrations
conjurctl db status                 # Show migration status
conjurctl policy load <acct> <file> # Load policy from file
conjurctl data-key generate         # Generate encryption key
```

## Development

See [dev/README.md](dev/README.md) for the full development environment setup.

```bash
cd dev
./cli start          # Start services
./cli logs app       # View logs
./cli test           # Run tests
./cli test-interop   # Run Go-Ruby interoperability tests
```

## Architecture

```
conjur-in-go/
├── cmd/conjurctl/        # CLI application
├── pkg/
│   ├── audit/            # RFC5424 syslog logging
│   ├── authenticator/    # Pluggable authenticator framework
│   │   ├── authn/        # API key authenticator
│   │   └── authn_jwt/    # JWT authenticator
│   ├── model/            # GORM database models
│   ├── policy/           # YAML parser & loader
│   ├── server/
│   │   ├── endpoints/    # HTTP handlers
│   │   └── middleware/   # JWT token validation
│   └── slosilo/          # Crypto (encryption, signing)
├── db/migrations/        # SQL migrations (40+)
├── test/integration/     # Cucumber/Godog feature tests
└── dev/                  # Docker dev environment
```

## Interoperability

Both Go and Ruby Conjur servers can:
- Share the same PostgreSQL database
- Read each other's encrypted secrets
- Authenticate users created by either server
- Load and enforce the same policies

## Roadmap

See [ROADMAP.md](ROADMAP.md) for detailed feature status and future plans.

## License

Apache 2.0

