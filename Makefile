BINARY := pg-agent-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt clean run dev

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

# Zero-config local run: proxy on 127.0.0.1:6432, admin UI on
# http://127.0.0.1:6480 (open, since it's loopback), dashboard approvals, and a
# ./pgproxy.db registry. No config file or admin token needed. Add a connection
# with `./pg-agent-proxy connections add -name x -upstream <url>` in another shell.
dev: build
	PGPROXY_APPROVAL_MODE=dashboard ./$(BINARY) serve

clean:
	rm -f $(BINARY)
