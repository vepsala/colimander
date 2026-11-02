# Database proxy

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

Run it entirely locally — no config file, no token, nothing to deploy:

```bash
make dev          # builds, then serves on localhost with dashboard approvals
```

That's the whole server: the proxy on `127.0.0.1:6432` and the admin UI on
`http://127.0.0.1:6480` (open, because it's loopback), with a `./pgproxy.db`
registry created on first run. This is all a solo developer needs — run it next
to your agent on your own machine. (Under the hood `make dev` is just
`PGPROXY_APPROVAL_MODE=dashboard pg-agent-proxy serve`; every setting has a safe
localhost default.)

For a persistent or shared setup, use a config file instead:

```bash
go build ./cmd/pg-agent-proxy

cp config.example.yaml config.yaml      # set hash_salt + approval
./pg-agent-proxy serve -config config.yaml
```

Set a master token to protect the admin surface (see [Admin
authentication](#admin-authentication)); on loopback it may run open. Deploy it
to a server (see [Deploying to Fly.io](#deploying-to-flyio)) when the consumers
aren't on your machine — remote/cloud agents, CI, or teammates — or when you
want the real database credentials custodied in one place instead of on every
laptop.

Open the UI to create a connection, or use the CLI:

```bash
# Optionally scan a database for likely PII columns first:
./pg-agent-proxy detect-pii -upstream "postgres://user:pass@host:5432/db"

./pg-agent-proxy connections add \
  -name billing-db \
  -upstream "postgres://user:pass@host:5432/db?sslmode=disable" \
  -max-rows 1000 \
  -strict-all -safe "products,sales_summary" \
  -pii "email:redact,ssn:redact,phone:redact"
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

Connections live in the SQLite file at `database`, with upstream URLs and agent
passwords encrypted under `master_key_file`. Keep that key out of backups of the
database. The proxy won't start if the key is missing or wrong; if it's lost,
delete the registry, re-add the connections and hand out new agent passwords. Manage them in the web UI or
with the CLI:

```bash
pg-agent-proxy connections list
pg-agent-proxy connections add    -name <n> -upstream <url> [-max-rows N] [-gate=false] [-pii "col:hash,col2:redact"] [-rotate-every 8h]
pg-agent-proxy connections rotate -id <id>     # new password, old one stops working
pg-agent-proxy connections rm     -id <id>
```

Each connection has its own `max_rows`, `gate_mutations`, and PII rules, so a
read-only reporting connection and a guarded admin connection can point at the
same database with different policies.

Credentials can be short-lived in two ways. A connection can **expire**
(`ttl`, e.g. `7d`): it stops authenticating at the deadline and is swept from
the registry. Independently, its password can **rotate automatically**
(`rotate_every`, e.g. `8h`, or `-rotate-every` in the CLI): a once-a-minute
sweep mints a new password whenever `rotated_at + rotate_every` has passed,
storing it exactly like a manual rotate so the dashboard, `GET
/api/connections` and `connections list` keep showing the current connection
string (and the next rotation time). Sessions already open are not cut off; the
old password simply stops working for new ones. A manual rotate restarts the
interval. Leave `rotate_every` blank (or `0`) for manual rotation only.

## Configuration

Process-wide settings live in `config.yaml` (see
[`config.example.yaml`](config.example.yaml)):

| Key | Meaning |
|---|---|
| `listen` | address agents connect to (default `127.0.0.1:6432`) |
| `admin_listen` | web UI / API address — **unauthenticated**, keep on localhost |
| `database` | path to the SQLite registry |
| `master_key_file` | key that encrypts secrets in the registry, generated on first start (default: `master.key` beside `database`) |
| `hash_salt` | secret salt mixed into every PII hash |
| `redact_string` | replacement for `redact` columns |
| `approval.mode` | `dashboard`, `http`, `auto_approve`, or `auto_deny` |
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
# Bind admin_listen to 0.0.0.0:6480; the token comes from the env.
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

## Running it

The Colimander daemon runs the proxy for you as a child process, listening on `127.0.0.1:15488`, with its settings in `~/.colimander/db.yaml` and its management screens in the Mac app. Sandboxes reach it as `host.lima.internal:15488`.

Credentials are manual on purpose: create a connection in the app, copy its connection string, and paste it where it's needed. Nothing injects them into a VM.

To run it without the daemon, use `colimander db serve -config config.yaml`. Every config key has an env override: `PGPROXY_LISTEN`, `PGPROXY_ADMIN_LISTEN`, `PGPROXY_DATABASE`, `PGPROXY_HASH_SALT`, `PGPROXY_REDACT_STRING`, `PGPROXY_SCHEMA_FUNCTION`, `PGPROXY_APPROVAL_MODE`, `PGPROXY_APPROVAL_URL`, `PGPROXY_APPROVAL_TIMEOUT`, plus `PGPROXY_ADMIN_TOKEN`. Env overrides the file.

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

## What this protects against

This reduces **accidental** exposure of personal data and secrets, for example
to a model provider, by a well-meaning agent writing ordinary queries. **It is
not a security boundary against someone deliberately digging for data**, and it
doesn't make a database's contents anonymous. Hashes generally remain personal
data under GDPR, so `redact` is the default.

Each statement is parsed with PostgreSQL's own parser before it reaches the
database:

- **Every statement:** file and server access, roles and extensions, `COPY`, `DO`
  and statistics views like `pg_stats` are refused.
- **Statements touching a table with PII:** only plain columns (which are masked),
  and allowlisted computed results that don't use a PII column. Whole rows, JSON
  conversions, subqueries in the select list and `UNION` on PII columns are refused
  with a message the agent can act on. A statement is strict as a whole if any table
  in it is.
- **Other tables:** full control, including JSON and any built-in function.

You choose what's masked. A table is strict if it has a rule, and **nothing is
masked without one**. `detect-pii` and the admin UI's Detect button only suggest
rules for you to review and save, so a new table stays unmasked until you add
rules, apart from the scanner below. Views, materialized views and foreign tables
are always strict, because they may read a PII table. Use `strict_all` to make
every table strict until listed in `safe_relations`, and `allow` rules to exempt a
column from a broader rule.

Every result and error message also passes a scanner for emails, phone numbers,
Finnish personal IDs, IBANs, card numbers and API keys.

Connections run read-only until a write is approved, and superuser upstream roles
are refused.

### Tripwire

Attempting something no honest agent needs (`pg_read_file`, `dblink`, `COPY ...
PROGRAM`, `pg_shadow`, `CREATE ROLE`), or 10 blocked statements within 5 minutes,
**suspends the connection**: its password stops working and its open sessions are
closed, across restarts. Assume the environment is compromised and investigate.
Resuming (`connections resume` or the admin UI) always issues a new password.
Everything is recorded under Security events, with queries encrypted at rest.

### Known gaps

- A view or function that renames a PII column gets past column rules, leaving
  only the scanner.
- The scanner can't recognise a person's name. Mark free-text columns as PII.
- `WHERE email LIKE 'a%'` can reveal values one guess at a time.
- PII in a query the agent wrote itself isn't touched, and nor is anything agents
  read from outside this proxy.
- Non-text PII columns return NULL.
- No query cancellation (`CancelRequest` is ignored).

## Development

```bash
go test ./...     # classification, anonymization, config
go vet ./...
make build
```

## License

MIT — see [LICENSE](LICENSE).
