# pg-agent-proxy

A PostgreSQL wire-protocol proxy that sits in front of your real databases and
makes them safe to hand to an agent (or a human doing investigation):

- **Speaks Postgres — any driver works.** Point any client at it with a normal
  connection string. It implements both the simple and the **extended query
  protocol** (Parse/Bind/Execute), so pgx, psycopg, asyncpg, node-pg, JDBC and
  `psql` all work, binary result formats included.
- **Routes by generated credentials.** Each "connection" has its own agent
  username/password that routes to a specific upstream database with its own
  rules. One proxy serves many databases; the real credentials never leave the
  registry.
- **Anonymizes PII on the way out.** Per-connection columns are SHA-256
  **hashed** (so values can still be compared for identity) or **redacted**
  before any row leaves the proxy. The raw value never reaches the client.
- **Gates writes and big reads behind approval.** Mutations (INSERT / UPDATE /
  DELETE / TRUNCATE / DDL) and reads over a row threshold pause for an approval
  decision over an HTTP hook — ready to back with a 2FA app, a Slack bot, or a
  browser extension. Reads are otherwise free.
- **Serves a live, PII-aware schema.** `SELECT pgproxy_schema();` returns every
  column annotated with the anonymization action, so an agent can pull an
  always-current schema into its context.
- **Manage it from a built-in web UI** (or the CLI): create a connection,
  auto-generate credentials, copy the agent connection string.

## Quick start

```bash
go build ./cmd/pg-agent-proxy

cp config.example.yaml config.yaml      # set hash_salt + approval
./pg-agent-proxy serve -config config.yaml
```

`serve` starts the proxy (`:6432`) and the admin UI (`http://127.0.0.1:6480`).
Set a master token to protect the admin surface (see [Admin
authentication](#admin-authentication)); on loopback it may run open.
Open the UI to create a connection, or use the CLI:

```bash
# Optionally scan a database for likely PII columns first:
./pg-agent-proxy detect-pii -upstream "postgres://user:pass@host:5432/db"

./pg-agent-proxy connections add \
  -name billing-db \
  -upstream "postgres://user:pass@host:5432/db?sslmode=disable" \
  -max-rows 1000 \
  -pii "email:hash,ssn:redact,phone:hash"
# prints the agent connection string (password shown once)
```

Hand the generated connection string to the agent. It connects like any
Postgres server:

```bash
psql "postgres://billing-db_a1b2c3:<password>@127.0.0.1:6432/postgres?sslmode=disable"
```

## What the agent sees

```
=> SELECT id, name, email, ssn, national_id FROM users LIMIT 1;
 id |    name     |                              email                               |    ssn     | national_id
----+-------------+------------------------------------------------------------------+------------+-------------
  1 | Alice Smith | c7531f392dcdbe29e455c6ca51910bdba97df8f21cd7a1a0bd720023d713b3a3 | [REDACTED] |   (null)

=> SELECT pgproxy_schema();
 table_schema | table_name | column_name | data_type | pii_action
--------------+------------+-------------+-----------+------------
 public       | users      | email       | text      | hash
 public       | users      | ssn         | text      | redact
 ...

=> UPDATE users SET name = 'x' WHERE id = 1;
ERROR:  pg-agent-proxy: statement denied (auto_deny)   -- or pauses for approval
```

`NULL` stays `NULL`. Equal inputs always hash equally, so you can still answer
"is this the same value here as there?". A PII column that is **not** a text
type (e.g. a `bigint` id) is returned as `NULL` rather than a hash — keep PII in
text columns to retain hashing.

## Connections (the registry)

Connections live in the SQLite file at `database`. Manage them in the web UI or
with the CLI:

```bash
pg-agent-proxy connections list
pg-agent-proxy connections add    -name <n> -upstream <url> [-max-rows N] [-gate=false] [-pii "col:hash,col2:redact"]
pg-agent-proxy connections rotate -id <id>     # new password, old one stops working
pg-agent-proxy connections rm     -id <id>
```

Each connection has its own `max_rows`, `gate_mutations`, and PII rules, so a
read-only reporting connection and a guarded admin connection can point at the
same database with different policies.

## Configuration

Process-wide settings live in `config.yaml` (see
[`config.example.yaml`](config.example.yaml)):

| Key | Meaning |
|---|---|
| `listen` | address agents connect to (default `127.0.0.1:6432`) |
| `admin_listen` | web UI / API address — **unauthenticated**, keep on localhost |
| `database` | path to the SQLite registry |
| `hash_salt` | secret salt mixed into every PII hash |
| `redact_string` | replacement for `redact` columns |
| `approval.mode` | `http`, `auto_approve`, or `auto_deny` |
| `approval.url` / `.timeout` | endpoint and deadline for `http` mode |

### Admin authentication

The admin UI and API are protected by a master token read from the
`PGPROXY_ADMIN_TOKEN` environment variable (keep it in your secrets manager,
e.g. Doppler, not in `config.yaml`).

- **API / automation:** send `Authorization: Bearer $PGPROXY_ADMIN_TOKEN`.
- **Web UI:** a login page exchanges the token for an httpOnly session cookie
  (marked `Secure` when served over HTTPS, including behind Fly's
  `X-Forwarded-Proto`).
- **No token set:** the admin server starts only when bound to loopback (with a
  warning). On any non-loopback address it refuses to start, so a misconfigured
  deploy can't expose an open admin.

Deploying to Fly.io with Doppler:

```bash
doppler secrets set PGPROXY_ADMIN_TOKEN="$(openssl rand -hex 32)"
# fly.toml: bind admin_listen to 0.0.0.0:6480; the token comes from the env.
```

### Approvals

Gated statements (mutations, and reads over `max_rows`) wait for a decision.
Pick how with `approval.mode`:

- **`dashboard`** — the request appears in the admin UI under *Pending
  approvals*; a human clicks Approve/Deny and the agent's query unblocks. No
  external service to wire up. Times out (deny) after `approval.timeout`.
- **`http`** — POST to an external endpoint (mobile 2FA, Slack bot, …); see below.
- **`auto_approve`** / **`auto_deny`** — for development / lockdown.

All modes **fail closed**: a timeout or a disconnected client denies.

#### The HTTP hook

In `http` mode the proxy POSTs JSON to your endpoint and proceeds only on an
explicit approval. Any timeout, connection error, or non-2xx response denies.

Request:

```json
{ "id": "req-ab12...", "reason": "mutation", "statement": "mutation",
  "query": "UPDATE users SET ...", "row_count": 0, "client": "10.0.0.5:54321" }
```

`reason` is `mutation` or `large_read` (the latter includes `row_count`).
Expected response:

```json
{ "approved": true, "reason": "approved by jane" }
```

This is where a mobile 2FA prompt / Slack approval / browser extension plugs in.

## Container image

A multi-arch image (amd64/arm64) is published to GHCR by the `publish` workflow
on pushes to `main` and on `v*` tags:

```
ghcr.io/kotisivukamu/pg-agent-proxy:latest
ghcr.io/kotisivukamu/pg-agent-proxy:<version>
```

It needs no config file — everything can come from the environment (handy with
Doppler/Fly):

```bash
docker run -p 6432:6432 -p 6480:6480 \
  -v pgproxy-data:/data \
  -e PGPROXY_DATABASE=/data/pgproxy.db \
  -e PGPROXY_ADMIN_LISTEN=0.0.0.0:6480 \
  -e PGPROXY_HASH_SALT="$HASH_SALT" \
  -e PGPROXY_ADMIN_TOKEN="$ADMIN_TOKEN" \
  -e PGPROXY_APPROVAL_MODE=dashboard \
  ghcr.io/kotisivukamu/pg-agent-proxy:latest
```

Every config key has an env override: `PGPROXY_LISTEN`, `PGPROXY_ADMIN_LISTEN`,
`PGPROXY_DATABASE`, `PGPROXY_HASH_SALT`, `PGPROXY_REDACT_STRING`,
`PGPROXY_SCHEMA_FUNCTION`, `PGPROXY_APPROVAL_MODE`, `PGPROXY_APPROVAL_URL`,
`PGPROXY_APPROVAL_TIMEOUT`, plus `PGPROXY_ADMIN_TOKEN`. Env overrides the file.

The SQLite registry is a single file, so mount a volume at `/data` (or wherever
`PGPROXY_DATABASE` points) to persist connections across restarts. On Fly.io
that means a Fly Volume, which pins the app to one machine/region.

## Statement classification

Each statement is classified and gated conservatively:

- **read** — `SELECT`, `SHOW`, `EXPLAIN` (without a writing target), `TABLE`,
  `VALUES`, `FETCH`. Allowed, subject to `max_rows`.
- **session** — `BEGIN`, `COMMIT`, `ROLLBACK`, `SET`, `RESET`, `DISCARD`, … —
  always allowed.
- **mutation** — everything else, including `WITH … DELETE …` CTEs and
  `EXPLAIN ANALYZE <write>`. Gated when the connection's `gate_mutations` is on.

When in doubt, a statement is treated as a mutation.

## How it works

The proxy authenticates the client against the registry, then opens an upstream
connection (via `pgconn`, so SCRAM and TLS to upstream are handled for you).
Simple-protocol `Query` runs through `pgconn.Exec`; extended-protocol
`Parse`/`Bind`/`Execute` is translated to `pgconn.ExecParams`, preserving the
client's parameter and result formats. Results are buffered so the proxy can
anonymize columns and enforce the row limit before any data is sent.

## Limitations (v1)

- **No TLS termination.** `SSLRequest` is declined; run the proxy on a trusted
  network or behind a TLS-terminating tunnel. Upstream TLS works normally.
- **PII matching is by column name**, applied across all tables. A rule's
  optional `table` is used only for `detect-pii` output and schema annotation,
  not to narrow which streamed rows get anonymized (deliberately conservative).
- **Non-text PII columns return NULL** (see above).
- **No query cancellation** (`CancelRequest` is ignored).

## Development

```bash
go test ./...     # classification, anonymization, config
go vet ./...
make build
```

## License

MIT — see [LICENSE](LICENSE).
