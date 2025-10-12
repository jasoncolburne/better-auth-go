# better-auth-go

**Go server-only implementation** of [Better Auth](https://github.com/jasoncolburne/better-auth) - a multi-repository, multi-language authentication protocol.

This implementation provides server-side protocol handling. For client functionality, use TypeScript, Python, Rust, Swift, Dart, or Kotlin implementations.

## What's Included

- ✅ **Server Only** - All server-side protocol operations
- ✅ **Interface-Based** - Clean dependency injection via Go interfaces
- ✅ **Concurrent** - Handles concurrent requests safely
- ✅ **Complete Test Suite** - Unit tests covering all server flows
- ✅ **Example Server** - HTTP server for integration testing

## Quick Start

This repository is a submodule of the [main spec repository](https://github.com/jasoncolburne/better-auth). For the full multi-language setup, see the parent repository.

### Setup

```bash
make setup          # Download Go modules
```

### Running Tests

```bash
make test           # Run go test
make lint           # Run linters
make format-check   # Check code formatting
```

### Running Example Server

```bash
make server         # Start HTTP server on localhost:8080
```

## Development

This implementation uses:
- **Go 1.21+** for modern Go features
- **Go modules** for dependency management
- **Interface-based design** for testability
- **JSON serialization** via encoding/json

All development commands use standardized `make` targets:

```bash
make setup          # go mod download
make test           # go test ./...
make lint           # go vet + golangci-lint (if installed)
make format         # go fmt ./...
make format-check   # Check go fmt
make build          # go build
make clean          # Remove build artifacts
make server         # Run example server
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation including:
- Directory structure and key components
- Go-specific patterns (interfaces, struct embedding, error handling)
- Message types and protocol handlers
- Usage examples and API patterns

### Key Features

- **Interface-Based Design**: Hasher, Verifier, SigningKey, Timestamper, TokenEncoder, etc.
- **Struct Embedding**: Clean composition of crypto, encoding, and storage components
- **Go-Style Errors**: Functions return `(result, error)` pairs
- **JSON Serialization**: Struct tags for field mapping
- **Goroutine-Safe**: Supports concurrent request handling

### Reference Implementations

The `examples/` directory contains reference implementations using:
- **Blake3** for cryptographic hashing
- **ECDSA P-256** for signing/verification
- **In-memory stores** with mutex protection
- **RFC3339** timestamps
- **gzip** token compression

## Integration with Other Implementations

This Go server is designed for integration testing with client implementations:
- **TypeScript client** (better-auth-ts)
- **Python client** (better-auth-py)
- **Rust client** (better-auth-rs)
- **Swift client** (better-auth-swift)
- **Dart client** (better-auth-dart)
- **Kotlin client** (better-auth-kt)

See `examples/server.go` for the HTTP server implementation.

## Related Implementations

**Full Implementations (Client + Server):**
- [TypeScript](https://github.com/jasoncolburne/better-auth-ts) - Reference implementation
- [Python](https://github.com/jasoncolburne/better-auth-py)
- [Rust](https://github.com/jasoncolburne/better-auth-rs)

**Server-Only:**
- [Go](https://github.com/jasoncolburne/better-auth-go) - **This repository**
- [Ruby](https://github.com/jasoncolburne/better-auth-rb)

**Client-Only:**
- [Swift](https://github.com/jasoncolburne/better-auth-swift)
- [Dart](https://github.com/jasoncolburne/better-auth-dart)
- [Kotlin](https://github.com/jasoncolburne/better-auth-kt)

## License

MIT
