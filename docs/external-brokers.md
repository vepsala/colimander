# External-service brokers: fly.io and Doppler

Colimander's broker proxies `github.com` and `api.github.com` by default. You
can optionally enable the same proxying for two more origins:

| Service     | Broker route prefix    | Upstream                |
|-------------|------------------------|-------------------------|
| fly.io      | `/fly`                 | `https://api.fly.io`    |
| Doppler     | `/doppler`             | `https://api.doppler.com` |

The motivation: you want an agent running inside the VM to be able to do
useful things like `fly logs -a kotisivukamu` or `doppler secrets set
NEW_KEY=value`, but you do **not** want it to be able to delete apps,
over-provision, read existing secret values, or touch projects outside a
list you control.

## How it differs from the GitHub broker

The GitHub policy is a **denylist** — the broker proxies everything except a
specific set of destructive operations. That fits because the GitHub API is
huge and most of it is benign (create commit, list PRs, etc.).

For fly and Doppler the broker uses an **allowlist** instead. Only methods +
paths that match `allowed_endpoints` get through; everything else is denied
with no chance to "forget to enumerate this dangerous endpoint." Smaller
surface, less to keep up-to-date as the upstreams add features.

## What gets configured

Two on-disk files:

- `~/.colima/<profile>/policy.json` — the rules (committed to your own
  config if you want; safe to share).
- `~/.colimander/tokens.json` — the upstream tokens (mode `0600`, **never
  commit**; treat like `~/.aws/credentials`).

And two extra env vars get baked into `/etc/profile.d/colimander.sh` inside
the VM (when the corresponding policy section exists):

```sh
# fly:
export FLY_API_HOSTNAME=http://host.lima.internal:8765/fly
export FLY_API_TOKEN=<profile>:<handle>
# doppler:
export DOPPLER_API_HOST=http://host.lima.internal:8765/doppler
export DOPPLER_TOKEN=<profile>:<handle>
```

`<profile>:<handle>` is the same Basic-auth identity used by the GitHub
broker, just packed into the `Bearer` slot because that's all the fly /
Doppler CLIs send.

## Setting up via the wizard

`colimander setup` will ask, after the GitHub policy step:

```
? Enable fly.io API brokering?
? Fly upstream token            (masked input — paste a scoped token)
? Allowed fly app names         (comma-separated)
? Enable Doppler secrets brokering?
? Doppler upstream token        (masked input)
? Allowed Doppler project names (comma-separated)
```

Skip either or both — they're independent.

## Setting up after the fact

If you already have a profile and want to add fly/doppler later:

```sh
# 1. Store the upstream token.
colimander tokens set kotisivukamu fly      fo1_xxxxxxxxxxxxxxxxxx
colimander tokens set kotisivukamu doppler  dp.st.dev.xxxxxxxxxxxx

# 2. Edit ~/.colima/kotisivukamu/policy.json and add the relevant sections:
#    "fly_policy":     { "allowed_apps":     ["kotisivukamu"], "allowed_endpoints": [...] }
#    "doppler_policy": { "allowed_projects": ["kotisivukamu"], "allowed_endpoints": [...] }
#    (see "Sensible defaults" below for the rule shapes.)

# 3. Re-wire the VM so the env vars get written.
colimander broker rewire kotisivukamu
```

## Sensible defaults

The wizard pre-fills `allowed_endpoints` with these starter sets. You can
edit them in `policy.json` after the fact.

### fly.io — read-only + logs

```json
"fly_policy": {
  "allowed_apps": ["kotisivukamu"],
  "allowed_endpoints": [
    { "method": "GET", "path_glob": "/v1/apps/*",                    "description": "App metadata" },
    { "method": "GET", "path_glob": "/v1/apps/*/machines",           "description": "List machines" },
    { "method": "GET", "path_glob": "/v1/apps/*/machines/*",         "description": "Machine state" },
    { "method": "GET", "path_glob": "/v1/apps/*/machines/*/events",  "description": "Machine event history" },
    { "method": "GET", "path_glob": "/v1/apps/*/logs",               "description": "App log stream" },
    { "method": "GET", "path_glob": "/v1/apps/*/releases",           "description": "Release history" }
  ]
}
```

What this allows: `fly status -a kotisivukamu`, `fly logs -a kotisivukamu`,
`fly machine status <id>`, `fly releases`.

What it denies: `fly apps create`, `fly apps destroy`, `fly scale`, `fly
deploy`, `fly secrets`, `fly machine update`, `fly volumes ...` — anything
that mutates state or creates resources.

### Doppler — write-only secrets

```json
"doppler_policy": {
  "allowed_projects": ["kotisivukamu"],
  "allowed_endpoints": [
    { "method": "POST", "path_glob": "/v3/configs/config/secrets",   "description": "Create a secret in an allowed project" },
    { "method": "GET",  "path_glob": "/v3/configs",                  "description": "List configs (no secret values)" },
    { "method": "GET",  "path_glob": "/v3/configs/config",           "description": "Single config metadata" }
  ]
}
```

What this allows: `doppler secrets set NEW_KEY=value --project
kotisivukamu --config dev`.

What it denies: reading any secret value, deleting a secret, modifying or
deleting a config, touching the `production` project (because it's not on
the list), or any project outside `allowed_projects`.

## Scope your upstream tokens too

The broker is a second line of defence. Your **first** line is the upstream
token itself — make it least-privilege at the source.

### Fly

Don't use your personal flyctl token. Instead create a scoped one:

```sh
# Read-only over one org:
fly tokens create org-read-only -o my-org

# Deploy permission to one specific app (still consider whether you really
# want the agent able to deploy):
fly tokens create deploy -a my-app
```

Tokens are macaroons — they encode their own scope and can't be elevated
in the broker.

### Doppler

In the Doppler dashboard → your workplace → Tokens, create a **service
token** scoped to a single project + config. Doppler service tokens are
already per-config; pair that with `allowed_projects` in the broker policy
and you've got two narrow gates.

## Streaming

`fly logs` opens a long-lived chunked HTTP stream. The broker uses
`httputil.ReverseProxy` with `FlushInterval=-1` so each chunk is flushed to
the agent as it arrives. No buffering, no line-blocking.

## Audit trail

Every allowed and denied call lands in `~/.colimander/audit.log`:

```
… kotisivukamu FLY GET /v1/apps/kotisivukamu/logs — ALLOW (proxied)
… kotisivukamu DOPPLER GET /v3/configs/config/secrets — DENY (no allowed_endpoints match)
```

Same surface format as the GitHub broker entries.

## Threat-model summary

| Thing the agent could attempt                                    | Blocked by                                |
|------------------------------------------------------------------|-------------------------------------------|
| `fly apps create` (overprovisioning)                             | `allowed_endpoints` (no POST `/v1/apps`)  |
| `fly apps destroy <name>` (deleting yours)                       | `allowed_endpoints` (no DELETE `/v1/apps/*`) |
| `fly logs -a <not-your-app>`                                     | `allowed_apps`                            |
| `doppler secrets get` on a real secret value                     | `allowed_endpoints` (no GET on secrets)   |
| `doppler secrets set` on a project you didn't list               | `allowed_projects`                        |
| Stealing the broker handle and impersonating from outside        | Broker listens on loopback only (lima fwd)|
| Using the upstream fly/doppler token directly outside the broker | The agent never sees it — only `<profile>:<handle>` |

Everything routed through the broker is audited. Everything not allowed by
policy is denied. Anything the broker doesn't intercept (raw outbound HTTPS
to `api.fly.io`) would have to go through Colima's network — the agent has
no token of its own to authenticate with, so even a direct connection is
useless without one.
