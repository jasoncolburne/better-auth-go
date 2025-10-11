.PHONY: setup test type-check lint format format-check clean server

setup:
	go mod download

test:
	go test ./...

type-check:
	go build ./...

lint:
	go vet ./...

format:
	gofmt -w .

format-check:
	@output=$$(gofmt -l .); \
	if [ -n "$$output" ]; then \
		echo "$$output"; \
		exit 1; \
	fi

server:
	go run examples/server.go

clean:
	go clean -cache -testcache -modcache
	rm -rf bin
