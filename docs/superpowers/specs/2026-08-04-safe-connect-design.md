# Safe Connect — Design

**Date:** 2026-08-04
**Status:** Approved

## Purpose

Expose RDP access to a home PC (PC1) on demand, controlled from a Telegram bot, so that
the public attack surface exists only while a session is deliberately open. The connecting
machine (PC2) needs nothing but a standard RDP client.

## Requirements

1. PC1 is reachable by RDP only while a session is open, and only from one nominated source IP.
2. A public port exists on the VDS only while a session is open.
3. RDP is disabled at the OS level on PC1 when no session is open.
4. Sessions tear themselves down without user action.
5. **The VDS is untrusted.** Root on the VDS must not yield a shell on PC1, must not yield
   tailnet access beyond two ports, and must not yield PC1 credentials.
6. Deployment is by script and runbook, executed by the operator. Nothing in this project
   connects to the operator's machines on its behalf.

## Non-goals

- Wake-on-LAN. PC1 is assumed powered on.
- Any VPN, agent, or client software on PC2.
- Multi-user support. One Telegram user, one target PC.

## Environment

| Host | OS | Role |
|---|---|---|
| PC1 | Windows 11 Pro | RDP target. Behind NAT, no public IP. |
| VDS | Ubuntu 22.04/24.04, root available | Bot host and TCP forwarder. Public IP. |
| PC2 | any | RDP client only. |

Nothing is currently installed on any host. The project includes bootstrap for all of it.

## Architecture

```
PC2 ──RDP──► VDS:<random high port> ──Tailscale──► PC1:3389
                     ▲
               socat (per-session)
                     ▲
               bot (systemd, user `safeconnect`)
                     │
                     └──SSH forced command──► agent.ps1 on PC1
```

Transport between VDS and PC1 is Tailscale. It was chosen over a hand-rolled SSH reverse
tunnel and over self-hosted Headscale because reconnect-after-outage is the failure mode
that matters most for a home machine, and it is the part least worth writing ourselves.

RDP traffic between PC2 and the VDS crosses the public internet protected only by RDP's own
TLS. It is not inside the Tailscale tunnel. This is a deliberate consequence of requirement 2
(nothing installed on PC2) and is addressed in the threat model.

## Components

| Module | Responsibility | Must not know about |
|---|---|---|
| `bot/forwarder.py` | socat and ufw lifecycle: `start(port, cidr)`, `stop()`, `is_alive()`, `established_count()` | Telegram, PC1 |
| `bot/pc1.py` | SSH forced-command client: `enable()`, `disable()`, `status()`, `probe_rdp()`, `logon_events()` | Telegram, socat |
| `bot/session.py` | State machine, persistence, timers, orchestration | Telegram transport |
| `bot/main.py` | aiogram handlers: parse, delegate, format reply | socat, SSH, ufw |
| `bot/config.py` | `pydantic-settings`; `config.toml` plus secrets from the environment | everything else |
| `bot/notify.py` | Message formatting | orchestration logic |
| `deploy/ufw-port` | Root-owned wrapper that validates and applies one ufw rule | everything else |
| `agent/agent.ps1` | The only thing the SSH key can execute on PC1 | the bot |

## State machine

States: `CLOSED → OPENING → OPEN → CLOSING → CLOSED`, persisted to
`/var/lib/safe-connect/state.json`.

On startup the bot reconciles rather than trusting the file: if the state is `OPEN` but the
recorded socat process is gone, it runs a full teardown.

### Opening (`/rdp_on <ip>`)

PC1 is prepared before any public port exists.

1. Validate the source IP. Parsed with Python's `ipaddress` module and re-serialised; the
   operator's original string never reaches a command line. Private, loopback, multicast and
   reserved ranges are rejected. The literal `any` is accepted as an explicit opt-out and
   logged at warning level.
2. SSH `enable` → PC1 sets `fDenyTSConnections=0` and creates/enables the firewall rule
   `SafeConnect-RDP-In`.
3. TCP-probe the tailnet address on 3389 from the VDS. On failure: roll back PC1, report,
   remain `CLOSED`.
4. Choose a random port from the configured range, apply the ufw rule, start socat. On bind
   failure: retry twice with fresh ports, then roll back everything.
5. Reply with `<vds_ip>:<port>`.

### Closing (`/rdp_off`, idle timeout, or hard cap)

Reverse order, and fail-forward: killing the public listener never waits on PC1.

1. Kill socat. The public port ceases to exist.
2. Remove the ufw rule.
3. SSH `disable`.
4. Fetch logon events (see below) and report.

If step 3 fails, the port is already closed. The operator receives an explicit
`port closed, PC1 cleanup FAILED` message with a retry action, rather than a silent
half-open state.

### Timers

Run on the asyncio loop, independent of Telegram, so auto-close still fires during a Telegram
outage; the notification is best-effort.

- `connect_grace` (default 5 min): idle counting does not begin until the first connection is
  observed or the grace period expires.
- `idle_timeout` (default 10 min): teardown after this long with zero established connections
  on the forwarder port, sampled every 30 s via `ss -tn`.
- `hard_cap` (default 8 h): teardown regardless of activity, with a warning message 5 minutes
  prior.

## Commands

| Command | Behaviour |
|---|---|
| `/rdp_on <ip>` | Open a session for that source IP. `/rdp_on any` opens to all sources. |
| `/rdp_off` | Tear down immediately. |
| `/status` | Current state, active port, source IP, time remaining on both timers. |
| `/help` | Command list. |

Messages from any Telegram ID other than the configured one produce **no reply** and a single
log line. A refusal message would confirm the bot's existence.

## Post-session logon audit

After teardown the agent returns Windows security events 4624 (success) and 4625 (failure)
for RDP logon types within the session window. The bot reports, for example:

```
Session closed after 41m.
Logons: 1 success (user `<name>` from 203.0.113.9), 0 failures.
```

This is the operator's tripwire for anything unexplained. The runbook covers enabling logon
auditing on PC1.

## Security model

Full threat model lives in `docs/SECURITY.md`. Summary of the controls:

**SSH key is pinned to a forced command.** PC1's `C:\ProgramData\ssh\administrators_authorized_keys`
holds:

```
restrict,command="powershell.exe -NoProfile -File C:\ProgramData\SafeConnect\agent.ps1" ssh-ed25519 AAAA...
```

The agent reads `SSH_ORIGINAL_COMMAND` and matches it against exactly `enable`, `disable`,
`status`, or `audit`. Everything else is refused. A stolen key therefore yields the ability to
toggle RDP and nothing else — no shell, no file write, no port forwarding. If PC1's OpenSSH
predates 7.2 and lacks `restrict`, the installer substitutes
`no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding`. The file's ACL is restricted
to `SYSTEM` and `Administrators`; `agent.ps1` is likewise not writable by non-administrators,
so a low-privilege foothold on PC1 cannot rewrite what the forced command runs.

**Narrow firewall rule on PC1.** A single rule `SafeConnect-RDP-In` permits TCP/3389 from the
VDS's tailnet address only, across all profiles. The built-in "Remote Desktop" rule group is
never enabled, because it would also expose 3389 to the home LAN.

**Default-deny tailnet ACL** (`deploy/tailnet-acl.json`): the only permitted flow anywhere on
the tailnet is `tag:vds → tag:pc1:22,3389`. Tailscale SSH is disabled on PC1; PC1 advertises
no subnet routes and is not an exit node. Tailnet lock and device approval are enabled so that
neither a compromised Tailscale account nor a compromised coordination server can silently
introduce a node.

**The bot has narrow root only.** `/etc/sudoers.d/safe-connect` grants exactly:

```
safeconnect ALL=(root) NOPASSWD: /usr/local/lib/safe-connect/ufw-port
```

`ufw-port open|close <port> <cidr>` is root-owned, mode 0755, not writable by `safeconnect`,
and independently re-validates that the port is inside the configured range and the source
argument is either a single-host CIDR matching `^\d{1,3}(\.\d{1,3}){3}/32$` or the literal
token `any`, before invoking ufw. A bare `NOPASSWD` on `ufw` itself would permit arbitrary
rule syntax. socat's own `range=` option is applied as a second layer for single-host sources;
with `any` it is omitted and the port ACL is the only source restriction.

This choice costs the unit `NoNewPrivileges=yes`, which is incompatible with sudo. Accepted
knowingly. The unit retains `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`RestrictAddressFamilies`, an emptied `CapabilityBoundingSet`, and
`ReadWritePaths=/var/lib/safe-connect`. The bot user cannot write to its own code, so a
compromise of the process does not become persistence.

**No shell interpolation, ever.** All subprocess calls use argv lists; `shell=True` appears
nowhere. Enforced by test.

**Dependencies stay minimal.** `aiogram` and `pydantic-settings` only; the system `ssh` binary
is invoked directly rather than adding `paramiko`, keeping SSH behaviour auditable from the
command line. Dependencies are pinned with hashes and installed into a venv the bot user
cannot write to.

### Accepted risks

- **RDP as an administrative account.** The operator will RDP as an admin user rather than a
  dedicated standard account, so a single credential compromise is full compromise of PC1.
  Mitigated only by password strength, an account lockout policy, and the closed-by-default
  port. Accepted deliberately.
- **No cert pinning by default.** The VDS is on-path for RDP by design. RDP's TLS is
  end-to-end, so a passive attacker with root on the VDS sees ciphertext, but an active one
  can present its own endpoint and self-signed certificate to harvest credentials — Windows
  warns rather than refuses. Pinning PC1's certificate into PC2's trusted root with
  `authentication level:i:2` converts that warning into a failed connection. Shipped as an
  optional runbook appendix, not a required step. Until it is applied, requirement 5's
  credentials clause holds only so long as certificate warnings are never accepted.
- **No second factor on `/rdp_on`.** A Telegram account takeover permits opening the port to
  an attacker-chosen IP. They still require PC1 credentials. Telegram cloud-password 2FA is a
  runbook step; bot-side TOTP is documented as an optional appendix.
- **Telegram sees command traffic**, including PC2's public IP. Bot chats are not
  end-to-end encrypted.

## Error handling

| Condition | Behaviour |
|---|---|
| PC1 unreachable over tailnet | Report "PC1 unreachable — powered on?", remain `CLOSED` |
| RDP probe fails after `enable` | Roll back PC1, report, remain `CLOSED` |
| socat cannot bind | Retry twice with new ports, then roll back and report |
| PC1 `disable` fails during teardown | Port already closed; report failure explicitly with retry action |
| Bot restarts mid-session | Reconcile from `state.json`; teardown if socat is gone |
| Telegram unreachable | Timers unaffected; notifications best-effort; all transitions logged to journald |

## Testing

Test-driven, `pytest`.

- **`session.py`** carries the bulk of the suite, with an injected fake clock, fake forwarder
  and fake PC1 client: every transition, both rollback paths, `connect_grace` suppressing
  premature idle teardown, hard-cap warning then teardown, crash reconciliation, and teardown
  completing when PC1 errors.
- **Input validation** has its own module, feeding hostile strings (`1.2.3.4; rm -rf /`,
  `$(id)`, embedded newlines, IPv6 forms, private and loopback ranges) and asserting rejection
  before any subprocess is constructed.
- **`forwarder.py`** is tested against real socat and a local echo server: allowed source
  connects, disallowed source is dropped, `established_count()` is accurate, `stop()` leaves no
  orphan process.
- **`ufw-port`** has shell-level tests for out-of-range ports and malformed CIDRs.
- **Handlers** assert that an unauthorised sender receives no reply and produces one log line.

`agent.ps1` and both installers cannot be unit-tested off-host. They ship with dry-run modes
and explicit smoke steps in the runbook.

## Deliverables

```
safe-connect/
  bot/       main.py config.py session.py forwarder.py pc1.py notify.py
  agent/     agent.ps1  install-pc1.ps1
  deploy/    install-vds.sh  safe-connect.service  ufw-port
             config.example.toml  tailnet-acl.json
  tests/
  docs/      RUNBOOK.md  SECURITY.md
```

`RUNBOOK.md` follows execution order: Tailscale account, ACL and tailnet lock → PC1 install →
VDS install → BotFather → first smoke test → troubleshooting → optional appendices
(certificate pinning, TOTP). Each step carries a verification command so failures surface
where they occur.

Installers are idempotent and safe to re-run.

## Verification limits

This project cannot reach the VDS or PC1. Unit-testable behaviour is verified locally; the
deployment itself is verified by the operator following the runbook's per-step checks.
