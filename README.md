# Colimander

Local agent orchestrator for macOS, built on top of [Colima](https://colima.run) / [Lima](https://lima-vm.io), with a credential-firewalling proxy so a compromised agent inside a sandboxed environment can't exfiltrate anything that works off your machine.

## Heads up — this is vibe coded

This is a one-person, "figuring it out as I go" project. I'm building Colimander because I want it for my own setup, not because I have a master plan.

If you read this and think *"the idea is interesting but the implementation is shaky"* — you're probably right. **Please feel free to take the idea and build a better version.** I'd rather see someone do this properly than guard a half-finished thing. Fork freely, no need to ask.

Contributions to this repo are also welcome, but no promises on review speed or direction.

## Why this exists

I work on 3-5 projects in parallel. My machine is an M3 with 36 GB of RAM. That's a lot, but it's not enough to keep five fully-provisioned dev environments running at once — language servers, Postgres, browsers, agent VMs all stacked. So today I run 1-2 "safe" environments and use unsafe shortcuts (host credentials, host filesystem, no isolation) on the other 2-3 that I'm only touching occasionally.

I don't want to give up local-first development. Agents like Claude Code thrive when they can see and use the full environment — language servers, real databases, real tools. The cloud-sandbox version is always a step behind. The cost is that "local-first agentic development" is currently synonymous with "the agent has access to your real GitHub token, your real DB password, your real filesystem."

The two halves of the chore are:

1. **Lifecycle ergonomics** — spinning up, swapping between, and tearing down environments without losing track of what's where, on a machine where you can't keep all of them hot.
2. **Safety without overhead** — being able to run `claude --dangerously-skip-permissions` in any of them without holding your breath.

Colimander tackles both:

- Each project is a one-command Colima VM with edit-over-SSH (no host bind-mount), fast start/stop/recreate, predictable ports, and a stable `.local` hostname for browser access. Easy enough that you actually do it for every project, not just the important ones.
- All sensitive outbound traffic — git operations, LLM API keys, prod databases — is routed through a host-side broker that holds the real credentials. The VM only ever sees inert local handles. A leaked handle is useless off-host.

The broker is what lets us *relax* the rest of the sandbox. Most agent-sandbox setups need egress allow-lists, DNS filtering, iptables rules — because they're trying to prevent credential exfiltration at the network layer. If the credential the agent has access to doesn't work off your machine in the first place, you don't need that ceremony. The VM can have wide network access; the interesting things are gated at the broker.

### What "scoped" actually means

A concrete example. GitHub's permission model — even fine-grained PATs — caps out at "this token can read/write these repos with these permissions." GitHub Apps can be more precise but you need to install them per org, which is heavyweight when you collaborate across orgs you don't control. Forgejo has similar limitations.

Colimander's broker can enforce policies the platform itself doesn't expose. For example:

- Allow writes to `org/repo-A` and `org/repo-B`.
- Allow `POST /orgs/org/repos` (create new repos in the org).
- Deny `DELETE /repos/*` (no repo deletion).
- Deny `PATCH /repos/*` payloads that rename.

The broker holds your real PAT (or App credentials, or Forgejo token) and acts as a policy-enforcing reverse proxy in front of `api.github.com` / your Forgejo host. The agent in the VM gets a handle that only this proxy honors, and only for operations the proxy allows.

This is what makes `--dangerously-skip-permissions` actually defensible: not because the agent is well-behaved, but because the worst it can do is bounded by the policy.

## The design in one paragraph

Each project is a Colima profile — its own VM, its own disk, its own Docker context. The VM has no host bind-mount; you edit files via SSH-remote in Zed/VS Code/Cursor/JetBrains. Real secrets live in macOS Keychain on the host. The VM gets local-only handles (e.g., a Postgres DSN pointing at a host-only IP, a placeholder GitHub token). A host daemon listens on a per-profile gateway address and brokers connections — swapping in the real credential, optionally enforcing scope (read-only DB, allowed GitHub paths). Leak a handle and it's inert outside this machine. Rotate a secret and nothing in the VM has to change.

## The pieces

### 1. Per-project Colima profile

One Colima profile per project. Each gets its own VM, qcow2 disk, and Docker context (`colima-<profile>`). Each profile's `colima.yaml` lives under `~/.colima/<profile>/` and Colimander owns and templates it.

Provisioning uses Colima's declarative `provision:` blocks (cloud-init-style, idempotent system/user mode), not bash heredocs piped over SSH.

`colimander create`, `start`, `stop`, `recreate`, `destroy`, `export`, `import` are thin wrappers around `colima` + this YAML.

### 2. No host bind-mount, edit-over-SSH

Default mount mode is `--mount-none`. Project files live only inside the VM disk. You import a project by either:

- `colimander create myproj --from-repo git@github.com:you/myproj` — the VM clones it on first boot, via the proxy.
- `colimander create myproj --import-dir ~/code/myproj` — one-shot `limactl cp` at creation; the host copy is no longer touched after.

Editing happens via SSH-remote from your editor (Zed, VS Code, Cursor, JetBrains all work). Add this to `~/.ssh/config`:

```
Include ~/.lima/*/ssh.config
```

…and every profile shows up automatically in the editor's remote-host picker. Colimander adds this line during `colimander init` if it isn't there.

**Why no bind-mount:** if the VM gets popped and drops a malicious binary, the host never sees it. macOS Gatekeeper can't quarantine files written over virtiofs anyway, so the only safe answer is "don't have them on the host filesystem in the first place."

### 3. Ports and browser access

Multiple projects running at once **will** collide on common dev ports (3000, 5173, 5432, 8000). You shouldn't have to think about this.

Each profile starts with `--network-address`, so the VM gets a routable IP from the host (e.g., `192.168.64.x`). Colimander adds a per-profile entry to `/etc/hosts` (one-time sudo prompt on first run):

```
192.168.64.8   myproj.local
192.168.64.9   otherproj.local
```

Now `http://myproj.local:3000` and `http://otherproj.local:3000` both work in your host browser, simultaneously, with no port collision. No port-forwarding tables to maintain. The agent inside the VM can advertise URLs as `http://localhost:3000` and you, on the host, just substitute the profile hostname.

`colimander ports myproj` shows what's listening inside the VM, so you can copy a URL into your browser without guessing.

For services that *need* a stable host-side port mapping (e.g., a desktop DB GUI that only speaks `localhost`), per-profile explicit mappings are declared in the profile YAML and listed by `colimander ports`.

### 4. The credential broker

A host daemon (`colimanderd`) that:

- Stores real secrets in macOS Keychain. No new crypto.
- Listens on a per-profile host-only IP/port reachable only from that profile's Lima gateway.
- Brokers connections: swaps in the real value, can enforce scope (Postgres read-only, GitHub API path allow-list).
- Identifies the calling VM via per-profile source IP (v1) or mTLS client cert (v2).
- Logs every redemption to a host audit file.

The VM gets local-only handles via env injection at start:

```
PROD_DB_URL='postgresql://myproj:any@host.lima.internal:15432/app'
GITHUB_TOKEN='cmd-handle-7af2'
```

Leaked off-host, these are dead — they point at non-routable addresses or refer to handles only this daemon understands.

### 5. Borrowed-secret slots

Lending a real prod credential temporarily, without rotation pain:

```
colimander secret add \
  --profile myproj \
  --kind postgres \
  --name PROD_DB_URL \
  --ttl 2h \
  --mode ro \
  postgresql://real_user:real_pass@prod-db.example.com:5432/app
```

TTL is required (no infinite borrowed secrets). After expiry: listener tears down, Keychain entry wipes, any leaked handle is dead.

### 6. Secret CLI

```
colimander secret ls [--profile foo] [--all]
colimander secret show NAME [--reveal]      # --reveal gated by Touch ID
colimander secret swap NAME [VALUE | --from-env | --from-stdin | --editor]
colimander secret extend NAME 1h
colimander secret rm NAME
colimander secret bind NAME --profile foo
colimander secret unbind NAME --profile foo
```

`ls` shows: name, profile, kind, mode, TTL remaining, last used, usage count, whether the listener is live.

`swap` is the headline win — update Keychain, broker reloads, nothing in the VM changes. No VM restart, no manual `~/.git-credentials` fix-up.

`show` defaults to printing the local handle (safe to display). `--reveal` prints the real value behind a macOS Touch ID prompt, so a compromised in-VM agent that gains a shell back to the host can't silently exfiltrate by calling the CLI in a loop.

### 7. Easy resize + proactive health

`colimander scale myproj --memory 16 --disk 80` runs the stop / restart-with-new-values dance. Memory and CPU are easy. Disk is grow-only (Colima limit).

`colimander health` (or a tray-bar indicator) polls `free`, `df`, container counts over SSH and warns when a profile crosses 80% RAM or disk — so you resize *before* the OOM killer eats your work, not after.

## Threat model

What Colimander tries to defend against:

- Agent or dependency inside the VM doing arbitrary things to the host filesystem → no host bind-mount.
- Credential exfiltration from a compromised VM → only handles are present in the VM, handles are inert off-host and revocable.
- Cross-project credential reuse → broker checks the calling profile's identity.
- "I forgot the prod token is still loaded" → TTLs on borrowed secrets.

What Colimander does **not** defend against:

- A kernel exploit that escapes the VM. Use Lima's hardening flags and don't rely on Colimander if you're running deliberately adversarial code.
- A user that types the real secret into the VM. We can't help with that.
- macOS itself being compromised. Keychain is the trust root; if it's gone, everything is gone.

## Open design questions

If you fork this and want a starting point on things I haven't decided:

- **VM-to-broker identity**: per-profile source IP (simple, weaker) vs mTLS client cert minted at `colima start` (more code, stronger).
- **Secret CLI from inside the VM**: should the agent be able to *request* a secret (with broker-side policy), or is the CLI host-only?
- **Default import flow**: clone-on-create vs `--import-dir` as the headline path. Probably ship both, but which is documented as default?
- **Implementation language**: the repo currently has a Go `.gitignore` but nothing's been written.

## Status

Nothing is built yet. This is the design before the code. If you're reading this hoping for v1: there is no v1 yet.

## Prior art that informed this

- [Trail of Bits — claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer) — closest existing thing. Filesystem boundary is solid, no credential broker.
- [Anthropic — Securely deploying AI agents](https://platform.claude.com/docs/en/agent-sdk/secure-deployment) — gestures at the proxy pattern.
- [Patrick McCanna — A better way to limit Claude Code access to secrets](https://patrickmccanna.net/a-better-way-to-limit-claude-code-and-other-coding-agents-access-to-secrets/) — also gestures at the proxy pattern.
- [Lima](https://lima-vm.io) and [Colima](https://colima.run) — the foundation Colimander sits on top of.

## License

[MIT](LICENSE).
