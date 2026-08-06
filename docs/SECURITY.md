# Safe Connect — Threat Model

This is the source of truth for what Safe Connect defends against, what it
deliberately does not, and why. `docs/RUNBOOK.md` builds and verifies the
controls described here; if a runbook verification step fails, treat the
corresponding property below as **not** holding until it is fixed.

## Trust boundary

**The VDS is untrusted.** It has a public IP and runs a bot that anyone on
the internet can attempt to reach. The design's central requirement is:
root on the VDS must not yield a shell on PC1, must not yield tailnet access
beyond two ports, and must not yield PC1 credentials.

Everything below either enforces that boundary or explains where it is
deliberately incomplete.

## The six channels that reach PC1, and their mitigations

1. **Telegram → bot.** Only the configured `telegram_user_id` gets a
   response; every other sender is silently dropped (`AuthMiddleware` in
   `bot/main.py`) — no refusal message, because a refusal would confirm the
   bot's existence. Mitigation: allow-list plus Telegram's own auth. Gap:
   Telegram account takeover (see Accepted risks).

2. **Bot → PC1, over SSH.** The key on PC1 is pinned to a forced command
   (`restrict,command="...agent.ps1"` in `administrators_authorized_keys`).
   `agent.ps1` reads `SSH_ORIGINAL_COMMAND` and accepts exactly `enable`,
   `disable`, `status`, or `audit <epoch>` — nothing else, no shell, no file
   write, no port forwarding. A stolen key yields only those four verbs.
   The key file's ACL is restricted to SYSTEM and Administrators via
   locale-independent SIDs (`*S-1-5-18`, `*S-1-5-32-544`), and `agent.ps1`
   itself is under the same lockdown, so a low-privilege foothold on PC1
   cannot rewrite what the forced command runs.

3. **Bot → PC1, over the tailnet (transport for #2 and for RDP).**
   `deploy/tailnet-acl.json` is default-deny: the only permitted flow on the
   whole tailnet is `tag:vds → tag:pc1:22,3389`. Tailscale SSH is disabled on
   PC1, and PC1 advertises no subnet routes and is not an exit node. Tailnet
   lock and device approval (enabled during the Tailscale setup step) mean
   neither a compromised Tailscale account nor a compromised coordination
   server can silently introduce a node onto this ACL.

4. **Bot → ufw, over sudo.** `/etc/sudoers.d/safe-connect` grants exactly
   `safeconnect ALL=(root) NOPASSWD: /usr/local/lib/safe-connect/ufw-port`.
   `ufw-port` is root-owned, mode 0755, not writable by `safeconnect`, and
   independently re-validates the port (inside the configured range) and the
   source (a single-host `/32` CIDR or the literal `any`) before ever
   invoking `ufw`. A bare `NOPASSWD` on `ufw` itself would let a compromised
   bot rewrite arbitrary rules — including deleting the SSH allow rule that
   the installer adds before enabling the firewall.

5. **PC2 → VDS, over public RDP.** Nothing is installed on PC2 by design
   (design non-goal). This traffic crosses the public internet inside RDP's
   own TLS, not inside Tailscale. Mitigation: the public port exists only
   during an open session, is restricted by ufw and by socat's `range=` to
   the single source IP given to `/rdp_on` (unless the operator explicitly
   opens `any`), and the session self-expires. Gap: without certificate
   pinning, an on-path attacker with root on the VDS can substitute their own
   RDP endpoint (Appendix A of the runbook).

6. **VDS → PC1, over RDP (the forwarded leg).** `socat` relays
   `VDS:<port>` to `PC1's tailnet IP:3389`. PC1's own firewall additionally
   restricts inbound 3389 to the VDS's tailnet address via the
   `SafeConnect-RDP-In` rule, so even a node that somehow joined the tailnet
   outside the ACL (e.g. during a lock-key rotation window) still cannot
   reach 3389 on PC1 directly.

## Ranked residual risks

Highest impact first.

| Rank | Risk | Why it survives | Primary mitigation in place |
|---|---|---|---|
| 1 | Compromise of PC1 itself (malware, other exposed service) | Out of scope — Safe Connect only gates RDP reachability, it cannot harden the OS behind it | Operator's own patching/AV hygiene; RDP closed by default |
| 2 | Active on-path attacker on the VDS harvests RDP credentials via a substituted TLS endpoint | Certificate pinning is optional, not default (Accepted risk) | NLA is required (`UserAuthentication=1`); Appendix A closes this if applied |
| 3 | Telegram account takeover opens the port to an attacker-chosen IP | No second factor on `/rdp_on` (Accepted risk) | Attacker still needs PC1 credentials; Telegram cloud-password 2FA; Appendix B |
| 4 | Stolen VDS-side SSH private key | Forced command limits it to `enable`/`disable`/`status`/`audit` | No shell, no file write, no port forwarding; key file ACL SYSTEM+Administrators only |
| 5 | Compromised bot process on the VDS escalates beyond its narrow sudo grant | `ufw-port` re-validates port range and CIDR shape independently of the bot | `NOPASSWD` scoped to one root-owned, non-writable script; systemd sandboxing (`ProtectSystem=strict`, capability set narrowed to just what `sudo` and `ufw`'s netfilter calls need — see below) |
| 6 | Brute-force RDP login during an open session | Session is time-bounded and IP-restricted, but a valid credential guess within the window still succeeds | Account lockout policy (5 attempts / 15 min) set by `install-pc1.ps1`; NLA; idle/hard-cap timers bound the window |
| 7 | Telegram sees command traffic, including PC2's public IP | Telegram chats are not end-to-end encrypted | Accepted; no mitigation shipped |
| 8 | A compromised Tailscale account or coordination server introduces a rogue node | Tailnet lock and device approval, once enabled, require an existing signing key or manual approval | Runbook step 2 (Tailscale setup) |

## Accepted risks

Each entry below is a deliberate design trade-off recorded in
`docs/superpowers/specs/2026-08-04-safe-connect-design.md`, not an oversight.

- **RDP runs as an administrative account.** The operator connects as an
  admin user rather than a dedicated standard account, so a single
  credential compromise is a full compromise of PC1. Mitigated only by
  password strength, the account lockout policy `install-pc1.ps1` sets, and
  the fact that the port is closed by default. **No appendix closes this**
  — it is a standing operator choice, not a technical gap; the fix is to
  create a dedicated non-admin RDP account, outside this project's scope.

- **Certificate pinning is optional, not default.** The VDS is on-path for
  RDP by design (channel 5 above). RDP's TLS is end-to-end, so a passive
  attacker with root on the VDS sees only ciphertext, but an active one can
  present its own endpoint and self-signed certificate to harvest
  credentials — Windows warns rather than refuses. Until pinning is applied,
  the design's credential-confidentiality property (requirement 5 in the
  spec) holds only so long as certificate warnings are never accepted.
  **Closed by RUNBOOK.md Appendix A** (pin PC1's Remote Desktop certificate
  into PC2's Trusted Root store, and require `authentication level:i:2`).

- **`/rdp_on` has no second factor.** A Telegram account takeover lets an
  attacker open the port to an IP of their choosing; they still need valid
  PC1 credentials to do anything with it. Telegram's own cloud-password 2FA
  is a runbook step (protects the Telegram account, not the bot itself).
  **Closed by RUNBOOK.md Appendix B** (add a TOTP factor the bot checks
  before honoring `/rdp_on`) — closes it only partially, since a compromised
  VDS holds the TOTP seed; see the appendix for the limit.

- **`safe-connect.service` omits `NoNewPrivileges=yes` and leaves
  `CapabilityBoundingSet` non-empty.** Both are deliberate, not dropped
  sandboxing. The bot's sole root escalation path is `sudo ufw-port` (channel
  4 above): `NoNewPrivileges` blocks the setuid transition sudo needs to
  reach uid 0 at all, and an *empty* `CapabilityBoundingSet` would let sudo
  reach uid 0 but hand it zero capabilities — the kernel intersects the
  binary's permitted set with the bounding set on `execve`, so ufw's
  netfilter calls would fail regardless of sudo succeeding. The bounding set
  is scoped to exactly `CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID
  CAP_SETPCAP CAP_AUDIT_WRITE` — what `sudo` and `ufw` need — not the full
  default set.

  A third concession belongs to the same family: `ProtectSystem=strict` stays
  on, but `ReadWritePaths` had to widen from `/var/lib/safe-connect` alone to
  also include `/etc/ufw` and `/run`. `ProtectSystem=strict` mounts the whole
  hierarchy read-only inside the unit's mount namespace, and the `sudo` → `ufw`
  child inherits it; a read-only mount refuses writes regardless of uid, so
  reaching root is not sufficient. `ufw` persists rules to
  `/etc/ufw/user.rules`, and the `iptables-restore` it shells out to takes
  `/run/xtables.lock`. Without those two carve-outs, `/rdp_on` fails with
  `'/etc/ufw/user.rules' is not writable` — which is how this was found, at
  runtime on the real VDS rather than in review.

  `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictNamespaces`, `LockPersonality`,
  `MemoryDenyWriteExecute` and the restricted `RestrictAddressFamilies` all
  remain in force.

  **No appendix closes any of the three** — they are the price of the
  narrow-sudo design (channel 4), and removing them means removing that design
  entirely. They are recorded here so a future reviewer does not "fix" them by
  re-adding `NoNewPrivileges`, emptying the bounding set, or trimming
  `ReadWritePaths`, each of which silently breaks session setup or teardown.

  **A note for whoever revisits this.** All three concessions were discovered
  in sequence, each later than the last: `NoNewPrivileges` at design time, the
  bounding set in review, `ReadWritePaths` only in production. Each removes a
  layer of sandboxing from a process reachable from Telegram. That progression
  is evidence about the architecture, not three unrelated bugs — running `ufw`
  under `sudo` inside a hardened unit's namespace fights the container by
  design. The alternative considered and deferred is to pre-open the whole
  configured port range in `ufw` once at install time and let socat's own
  `range=` option do per-session source filtering. That needs no sudo, no
  capabilities and no namespace carve-outs, so it restores
  `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet`, and
  `ReadWritePaths=/var/lib/safe-connect` alone. Its cost is that `ufw status`
  permanently lists an open range on which nothing listens unless a session is
  live. If a fourth concession ever becomes necessary, take that as the signal
  to switch.

## Verification limits

This project cannot reach the VDS or PC1: none of the above was exercised
against real infrastructure by this codebase. `bot/`, `agent/agent.ps1`'s
verb dispatch, `deploy/ufw-port`, and the argv-only subprocess boundary are
covered by the automated test suite (146 tests, see `docs/RUNBOOK.md`
section 9, "Run the socat integration tests on the VDS"). Everything that
requires real hosts — the forced command actually being in effect, the
tailnet ACL actually being default-deny, the systemd capability set
actually being sufficient and not more — is verified by the operator
following `docs/RUNBOOK.md`'s per-step checks, in particular **section 8,
"Verify the forced command actually restricts the key"**, which is the
only check that proves the forced command is really in force.
