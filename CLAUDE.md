# Better Auth - Go Implementation

## Project Context

This is a **Go server-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth), a multi-repository authentication protocol.

This implementation provides **server-side only** components. For client functionality, use one of the other implementations (TypeScript, Python, Rust, Swift, Dart, or Kotlin).

## Related Repositories

**Specification:** [better-auth](https://github.com/jasoncolburne/better-auth)

**Reference Implementation:** [better-auth-ts](https://github.com/jasoncolburne/better-auth-ts) (TypeScript - Client + Server)

**Other Implementations:**
- Full (Client + Server): [Python](https://github.com/jasoncolburne/better-auth-py), [Rust](https://github.com/jasoncolburne/better-auth-rs)
- Server Only: [Ruby](https://github.com/jasoncolburne/better-auth-rb)
- Client Only: [Swift](https://github.com/jasoncolburne/better-auth-swift), [Dart](https://github.com/jasoncolburne/better-auth-dart), [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## Repository Structure

This repository is a **git submodule** of the parent [better-auth](https://github.com/jasoncolburne/better-auth) specification repository. The parent repository includes all 8 language implementations as submodules and provides orchestration scripts for cross-implementation testing.

### Standardized Build System

All implementations use standardized `Makefile` targets for consistency:

```bash
make setup          # Download Go modules (go mod download)
make test           # Run tests (go test ./...)
make type-check     # Type check (go vet ./...)
make lint           # Run linter (go vet + golangci-lint if installed)
make format         # Format code (go fmt ./...)
make format-check   # Check formatting (go fmt -l .)
make build          # Build project (go build)
make clean          # Clean artifacts
make server         # Run example server (go run examples/server.go)
```

### Parent Repository Orchestration

The parent repository provides scripts in `scripts/` for running operations across all implementations:

- `scripts/run-setup.sh` - Setup all implementations
- `scripts/run-unit-tests.sh` - Run tests across all implementations
- `scripts/run-type-checks.sh` - Run type checkers across all implementations
- `scripts/run-lints.sh` - Run linters across all implementations
- `scripts/run-format-checks.sh` - Check formatting across all implementations
- `scripts/run-integration-tests.sh` - Run cross-language integration tests
- `scripts/run-all-checks.sh` - Run all checks in sequence
- `scripts/pull-repos.sh` - Update all submodules

These scripts automatically skip implementations where tooling is not available.

## Architecture

### Directory Structure

```
api/                       # Server API implementation
├── betterauth.go          # BetterAuthServer struct and main logic
├── account.go             # Account protocol handlers (Create, Delete, Recover)
├── device.go              # Device protocol handlers (Link, Unlink, Rotate)
├── session.go             # Session protocol handlers (Request, Create, Refresh)
├── access.go              # Access protocol handlers
├── api_test.go            # API tests
└── token_test.go          # Token encoding tests

pkg/                       # Packages defining interfaces and types
├── cryptointerfaces/      # Crypto interface definitions
│   └── crypto.go          # Hasher, Verifier, SigningKey interfaces
├── encodinginterfaces/    # Encoding interface definitions
│   └── encoding.go        # Timestamper, TokenEncoder, IdentityVerifier interfaces
├── storageinterfaces/     # Storage interface definitions
│   └── storage.go         # Server storage interfaces
└── messages/              # Protocol message types
    ├── message.go         # Base message types
    ├── account.go         # Account messages
    ├── device.go          # Device messages
    ├── session.go         # Session messages
    └── access.go          # Access messages

examples/                  # Example implementations
├── server.go              # Example HTTP server
├── crypto/                # Example crypto implementations
├── encoding/              # Example encoding implementations
└── storage/               # Example storage implementations
```

### Key Components

**BetterAuthServer** (`api/betterauth.go`)
- Main server struct
- Composes crypto, encoding, and storage interfaces
- Routes requests to appropriate protocol handlers

**Protocol Handlers** (`api/*.go`)
- `account.go`: CreateAccount, DeleteAccount, RecoverAccount
- `device.go`: LinkDevice, UnlinkDevice, RotateDevice
- `session.go`: RequestSession, CreateSession, RefreshSession
- `access.go`: HandleAccessRequest, VerifyAccessToken

**Message Types** (`pkg/messages/`)
- Go structs with JSON tags
- Request and response types for all protocols
- Serialization via `encoding/json`

**Interfaces** (`pkg/*/`)
- Interface definitions for crypto, encoding, and storage
- Enable dependency injection
- Implementations provided via constructor

## Go-Specific Patterns

### Interface-Based Design

This implementation uses Go interfaces to define contracts:
- `Hasher`, `Verifier`, `SigningKey` for crypto
- `Timestamper`, `TokenEncoder`, `IdentityVerifier` for encoding
- Storage interfaces for server state management

Interfaces enable:
- Dependency injection
- Easy testing with mocks
- Pluggable implementations

### Struct Embedding

Uses struct embedding for composition:
- Server embeds crypto, encoding, and storage components
- Clean separation of concerns
- Easy to extend functionality

### Error Handling

Go-style error handling:
- Functions return `(result, error)` pairs
- Explicit error checking: `if err != nil { ... }`
- Custom error types for different failure modes
- No exceptions - errors are values

### JSON Serialization

All messages use `encoding/json`:
- Struct tags define JSON field names: `json:"fieldName"`
- Marshal/Unmarshal for serialization
- Easy integration with HTTP handlers

### Goroutines and Concurrency

While not heavily used in the core protocol:
- HTTP server can handle concurrent requests
- Storage implementations may use mutexes for thread safety
- Context support for cancellation and timeouts

## Reference Implementations

The `examples/` directory contains reference implementations:
- **crypto**: Blake3 hashing, ECDSA P-256 signing/verification
- **encoding**: RFC3339 timestamps, gzip token compression, identity verification
- **storage**: In-memory map-based stores with mutex protection

These demonstrate how to implement the protocol interfaces in Go.

## Testing

### Unit Tests (`api/api_test.go`)
Tests covering all protocol operations:
- Account creation, recovery, deletion
- Device linking/unlinking, rotation
- Session request/creation/refresh
- Access token generation and verification

Run with: `go test ./api`

### Token Tests (`api/token_test.go`)
Token encoding/decoding tests.

Run with: `go test ./api -run Token`

### Running Tests
```bash
go test ./...              # Test all packages
go test ./api              # Test API package
go test -v ./...           # Verbose output
go test -race ./...        # Race detector
go test -cover ./...       # Coverage
```

## Usage Patterns

### Server Initialization

```go
import "github.com/jasoncolburne/better-auth-go/api"

server := api.NewBetterAuthServer(api.ServerConfig{
    Crypto: api.CryptoConfig{
        Hasher: yourHasher,
        KeyPair: api.KeyPairConfig{
            Response: responseSigningKey,
            Access:   accessSigningKey,
        },
        Verifier: yourVerifier,
    },
    Encoding: api.EncodingConfig{
        IdentityVerifier: yourIdentityVerifier,
        Timestamper:      yourTimestamper,
        TokenEncoder:     yourTokenEncoder,
    },
    Expiry: api.ExpiryConfig{
        AccessInMinutes:  15,
        RefreshInHours:   24,
    },
    Store: api.StoreConfig{
        Access: api.AccessStoreConfig{
            KeyHash: accessKeyHashStore,
        },
        Authentication: api.AuthenticationStoreConfig{
            Key:   authKeyStore,
            Nonce: nonceStore,
        },
        Recovery: api.RecoveryStoreConfig{
            Hash: recoveryHashStore,
        },
    },
})
```

### Handling Requests

```go
// Parse request from HTTP body
var request messages.ClientRequest
err := json.Unmarshal(body, &request)
if err != nil {
    // Handle error
}

// Handle request
response, err := server.HandleRequest(request)
if err != nil {
    // Handle error
}

// Serialize response
responseBytes, err := json.Marshal(response)
if err != nil {
    // Handle error
}
```

### HTTP Server Example

See `examples/server.go` for a complete HTTP server implementation that:
- Listens on port 8080
- Handles JSON requests
- Routes to the BetterAuthServer
- Returns JSON responses

Run with: `go run examples/server.go`

## Development Workflow

### Building
```bash
go build ./...             # Build all packages
go build examples/server.go # Build example server
```

### Testing
```bash
go test ./...              # Run all tests
go test -v ./...           # Verbose
go test -race ./...        # With race detector
go test -cover ./...       # With coverage
```

### Linting & Formatting
```bash
go fmt ./...               # Format code
go vet ./...               # Vet code
golangci-lint run          # Run linters (if installed)
```

### Running Example Server
```bash
go run examples/server.go  # Start HTTP server on :8080
```

## Integration with Other Implementations

This Go server is designed for integration testing with client implementations:
- TypeScript client (`better-auth-ts`)
- Python client (`better-auth-py`)
- Rust client (`better-auth-rs`)
- Swift client (`better-auth-swift`)
- Dart client (`better-auth-dart`)
- Kotlin client (`better-auth-kt`)

The TypeScript integration tests connect to this server by default.

## Making Changes

When making changes to this implementation:
1. Update the code
2. Run tests: `go test ./...`
3. Format code: `go fmt ./...`
4. Vet code: `go vet ./...`
5. If protocol changes: sync with the TypeScript reference implementation
6. If breaking changes: update client implementations that depend on this server
7. Run integration tests from client repositories
8. Update this CLAUDE.md if architecture changes

## Key Files to Know

- `api/betterauth.go` - Main server struct and initialization
- `api/account.go` - Account protocol handlers
- `api/device.go` - Device protocol handlers
- `api/session.go` - Session protocol handlers
- `api/access.go` - Access protocol handlers and token verification
- `pkg/messages/` - Protocol message type definitions
- `pkg/cryptointerfaces/crypto.go` - Crypto interface definitions
- `pkg/encodinginterfaces/encoding.go` - Encoding interface definitions
- `pkg/storageinterfaces/storage.go` - Storage interface definitions
- `examples/server.go` - Example HTTP server
- `api/api_test.go` - Comprehensive test suite

## Go Modules

- Uses Go modules for dependency management
- `go.mod` defines module path and dependencies
- Run `go mod tidy` to update dependencies
- Run `go mod download` to download dependencies
