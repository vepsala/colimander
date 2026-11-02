# `make app` builds everything, restarts the daemon on the new build and opens the app.
.PHONY: build app

build:
	go build -o bin/colimander .
	CGO_LDFLAGS="-framework UniformTypeIdentifiers" go build -tags desktop,production -o bin/colimander-app ./cmd/colimander-app 2>/dev/null

app: build
	bin/colimander broker stop
	bin/colimander broker start
	bin/colimander-app
