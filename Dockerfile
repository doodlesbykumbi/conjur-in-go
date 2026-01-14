# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with version info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" -o conjurctl ./cmd/conjurctl

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 conjur && \
    adduser -u 1000 -G conjur -s /bin/sh -D conjur

ENV CONJUR_HOME=/opt/conjur-server \
    PORT=80 \
    RAILS_ENV=production

WORKDIR ${CONJUR_HOME}

# Create required directories
RUN mkdir -p /opt/conjur/etc/ssl/ca \
             /opt/conjur/etc/ssl/cert \
             /run/authn-local && \
    chown -R conjur:conjur /opt/conjur /run/authn-local

# Copy binary from builder
COPY --from=builder /app/conjurctl /usr/local/bin/conjurctl
COPY --from=builder /app/db/migrations ./db/migrations

# Switch to non-root user
USER conjur

EXPOSE ${PORT}

ENTRYPOINT ["conjurctl"]
CMD ["server"]
