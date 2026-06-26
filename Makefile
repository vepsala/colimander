BINARY := pg-agent-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt clean run

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/pg-agent-proxy

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

run: build
	./$(BINARY) serve -config config.yaml

clean:
	rm -f $(BINARY)
