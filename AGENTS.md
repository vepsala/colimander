# Agent notes

For agents (Claude Code, OpenCode, Codex, etc.) working in this repo. The
project's design rationale lives in `README.md` — read it first if you don't
already know what Colimander is.

## Build / run / test

```
go build -o colimander .   # binary is symlinked from ~/.local/bin/colimander
go test ./...
go vet ./...
```

The user typically has the binary symlinked from `~/.local/bin/colimander` →
`./colimander`, so every `go build` here is live. Don't add a separate
install step.

## Repo layout

- `main.go` — entrypoint, command dispatch, profile lifecycle (`setup`, `create`,
  `start`, `stop`, `destroy`, `ssh`, `status`, `ls`, `ports`, `init`, `hosts-sync`,
  `tokens`), wizard.
- `broker.go` — `colimanderd` daemon. HTTP proxy for github.com /
  api.github.com, Basic-auth handle identity, gh-token injection, audit log.
- `external.go` — `colimanderd` extension: same daemon, two more routes —
  `/fly` → `https://api.fly.io`, `/doppler` → `https://api.doppler.com`.
  Allowlist policy (not denylist), Bearer-token identity, `httputil.ReverseProxy`
  for streaming (fly logs).
- `policy.go` — `Policy` shape (incl. `FlyPolicy`, `DopplerPolicy`), default
  deny rules, allow-rule matcher.
- `tokens.go` — upstream-token storage at `~/.colimander/tokens.json` (0600).
  Used only by the external brokers; the GitHub broker still sources from
  `gh auth token`.
- `gitpkt.go` — minimal git pkt-line parser for ref-deletion detection on push.
- `packages.go` — optional package catalog (Claude Code, OpenCode, Postgres-16,
  Node-via-mise) plus the always-on `tmux` baseline.
- `docs/external-brokers.md` — user-facing doc for the fly + doppler surface.
- `*_test.go` — unit tests for policy matchers, allow-rules, and pkt-line
  parser. No network / VM tests; the broker is smoke-tested by hand.

## Conventions

- **Commit style**: short imperative subject (under 70 chars), then a short
  body explaining *why*. No emojis. Follow existing log: `git log --oneline`.
- **Prompts**: the wizard uses `github.com/charmbracelet/huh` for arrow-key
  TUI selects. Don't reintroduce "type space-separated numbers" prompts.
- **No `nvm`** — `mise` is the runtime version manager of choice (faster shell
  init, polyglot, per-project auto-switching).
- **Don't auto-take destructive actions** without surfacing them. Even the
  broker startup got promoted from silent auto-start to an explicit wizard
  confirm because the user wanted it visible.
- **Symlink install is intentional** — don't replace with `go install` or
  copy-to-bin. Rebuilds need to take effect instantly.

## Known gotchas (don't re-discover these)

- **Colima 0.8+ stores lima state at `~/.colima/_lima/`**, not the default
  `~/.lima/`. Any `limactl` invocation must set `LIMA_HOME=~/.colima/_lima`.
  Use the `runLimactl` helper in `main.go`.
- **VM user vs home dir**: SSH user is `<host-user>` (e.g. `tapio`), but home
  is `/home/<host-user>.linux/` (e.g. `/home/tapio.linux/`). Don't conflate.
- **`--import-dir` is a one-shot copy** — by design. The VM is the source of
  truth after; no host bind-mount, no sync-back. That's the security model,
  not an oversight. Don't add sync.
- **Git URL `insteadOf` config with dots+colons works**: the config var
  `url.http://host.lima.internal:8765/git/.insteadOf` survives git's parser.
  Tested.
- **`gh` token is fetched via `gh auth token`** with a 60s cache in the
  broker. Don't add a separate credential store.
- **Fly/Doppler tokens live in `~/.colimander/tokens.json` (0600).** Don't
  echo them back to the user, don't include in `colimander status` /
  `colimander policy show`, don't commit. The broker reads them at request
  time (no caching needed — they're small).
- **Fly/Doppler use Bearer auth with `<profile>:<handle>` as the token.**
  flyctl and the Doppler CLI only respect their single env-var token, so we
  pack the broker identity into the Bearer slot rather than negotiating
  Basic. Don't try to make the upstream CLIs use Basic — they won't.

## Threat model anchor

The default deny list is **deliberately aggressive** about destructive
operations. The principle: if the agent in the VM is compromised, what's
unrecoverable? Repo/branch deletion, force-push to main (TODO, see backlog),
webhook tampering, SSH/GPG key changes, secret deletion, org settings,
member-role escalation. All denied by default. Read access and benign writes
(commits, PRs, comments) are allowed.

Don't relax the defaults without thinking through "what's the worst the
agent can do with this permission, and is it reversible?"

## Backlog / not-yet-built

- Force-push detection on git push (requires upstream HEAD compare per push).
- `gh` CLI brokering (needs GHE-style `/api/v3/` path support).
- mTLS profile identity (currently HTTP Basic-auth with handle).
- Excludes for `--import-dir` (skip `node_modules`, `.next`, etc., or offer
  `--from-repo` clone-in-VM as an alternative).
- Quota-as-policy for fly (e.g. "no more than N apps") — would need
  stateful counters per profile; today we just deny app-create entirely.
- README/docs are written for humans; this file is the agent-facing
  equivalent — keep them in sync if you change behaviour either way.
