# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
# CGO is disabled — modernc.org/sqlite is pure Go, so the binary is fully static
# and runs on a scratch/distroless base. TARGETOS/TARGETARCH are provided by
# buildx for cross-compilation.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/pg-agent-proxy ./cmd/pg-agent-proxy

# --- runtime stage ---
# distroless/static includes CA certificates (needed for upstream TLS and HTTPS
# approval webhooks). It runs as root so a mounted data volume is writable.
FROM gcr.io/distroless/static-debian12:latest

COPY --from=build /out/pg-agent-proxy /usr/local/bin/pg-agent-proxy

# 6432 = PostgreSQL proxy, 6480 = admin UI/API.
EXPOSE 6432 6480

# Persist the SQLite registry on a mounted volume and point the proxy at it:
#   docker run -v pgproxy-data:/data -e PGPROXY_DATABASE=/data/pgproxy.db ...
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/pg-agent-proxy"]
CMD ["serve"]
