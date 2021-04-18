# conjur-in-go

[Conjur](https://github.com/cyberark/conjur) server written in Go. Written to be interoperable with Conjur in Ruby.
This project started off mostly about exploring the crypto side of things, trying to
replicate and better understand [slosilo](https://github.com/cyberark/slosilo). It turns out once you have that working 
you're good to Go :_)

Currently supports
+ authn, authz, secret retrieval

Like Conjur in Ruby, this server uses the datakey to decrypt/encrypt all the things (secrets, tokenSigningPrivateKey etc.) from and to the database.

Authn, though it doesn't verify your api key it allows you to assume the user you pass in.
Like Conjur the account needs an associated tokenSigningPrivateKey in the slosilo keystore. 
The token is used both to sign new access tokens, and to verify access tokens as part of authz.
Also supports base64 encoding of the token.
```shell
curl -X POST \
  -H 'Accept-Encoding: base64' \
  -v \
  "http://localhost:8000/authn/myConjurAccount/Dave@BotApp/authenticate"
```

Secret retrieval + authn + authz. For authn, as with Conjur in Ruby, tokens are verified against the token signing keys (from the slosilo keystore) based on the key id + fingerprint. From authn, we get the identity and use the stored procedure (`is_role_allowed_to`) to check for permissions before
serving secrets to authenticated users. The data key is used to decrypt the secrets from the db.
```shell
token=...
curl \
  -H 'Authorization: Token token="'$token'"' \
  -v \
  "http://localhost:8000/secrets/myConjurAccount/variable/BotApp%2FsecretVar"
```

## Run

Build and run

```shell
go build -o conjurctl ./cmd/conjurctl

DATABASE_URL="postgres://postgres@localhost/postgres" \
CONJUR_DATA_KEY="2AP/N4ajPY3rsjpaIagjjA+JHjDbIw+hI+uI32jnrP4=" \
 ./conjurctl server
```

## Development

A great way to develop this project is to run `cyberark/conjur-quickstart`.
It will bootstrap that database using Conjur in Ruby. This project is meant to be 
interoperable with the Conjur in Ruby.

Replace the database service in the `docker-compose.yml` with the following:

```yaml
  database:
    image: postgres:10.15
    container_name: postgres_database
    environment:
      POSTGRES_HOST_AUTH_METHOD: trust
    ports:
      - 5432:5432
  pgadmin:
#    https://www.pgadmin.org/docs/pgadmin4/latest/container_deployment.html
    image: dpage/pgadmin4
    environment:
      PGADMIN_DEFAULT_EMAIL: user@domain.com
      PGADMIN_DEFAULT_PASSWORD: SuperSecret
    ports:
      - 80:80
```

Visit `http://localhost:80` and use the pgadmin UI to navigate the Conjur database.
This really helps while tinkering. You can see all the tables and explore the Conjur database with such ease. 

## Cool ideas!

1. OpenTelemetry, get some metrics and traces going.
2. This could be used to create a lightweight "Conjur" that has a, say, in-memory backing 
   store for extremely fast reads. In this case the server needs to just do authn, authz and secrets fetching. Who knows the kinds of performance you could squeeze.
3. Refactor + unit tests should be fun.

