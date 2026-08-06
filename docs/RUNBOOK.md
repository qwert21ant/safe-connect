# Safe Connect — Operator Runbook

Follow this in order. Every step ends with a verification command and the
output it must produce — if a step's verification does not match, stop and
fix it before moving on; later steps assume earlier ones actually hold, not
just that the commands were typed.

Read `docs/SECURITY.md` first, or at least in parallel: it explains *why*
each of these steps exists, in particular why **section 8, "Verify the
forced command actually restricts the key," is the one that must never be
skipped**.

A note on ordering: this runbook installs the **VDS before PC1**, even
though PC1 is the machine being protected. That is not arbitrary —
`agent/install-pc1.ps1` takes the VDS's SSH public key as a mandatory
argument, and that key does not exist until `deploy/install-vds.sh` has
generated it. Doing PC1 first would leave you stuck at a required parameter
with nothing to put in it.

Three machines are named throughout: **PC1** is the Windows box being
protected (the RDP target). The **VDS** is the public Ubuntu host that
brokers access. **PC2** is whatever device you'll actually run an RDP
client from when connecting — a laptop, another desktop, even a phone; it
needs nothing installed beyond a standard RDP client, and can be different
each session.

## 1. Prerequisites

- A Telegram account (this will be the only account the bot ever answers).
- A Tailscale account.
- Root (or passwordless sudo) on the VDS — Ubuntu 22.04 or 24.04, with a
  public IP.
- An administrator account on PC1 — Windows 11 Pro, currently on the same
  local network as you (you'll need to run one script there elevated).
- A way to get files onto the VDS (git clone, scp, whatever you normally
  use).

*Verify:* `ssh root@<vds-ip> id` prints `uid=0(root) ...`, and you can log
into PC1 with an administrator account.

## 2. Tailscale

Install and join both machines, tag them, lock down the tailnet ACL, and
turn on the two account-level protections the design relies on.

1. **Install.**
   - PC1 (elevated PowerShell): `winget install tailscale.tailscale`
   - VDS: `curl -fsSL https://tailscale.com/install.sh | sh`
2. **Join both**, authenticating with the same Tailscale account:
   - PC1: `tailscale up`
   - VDS: `sudo tailscale up`
3. **Tag them.** In the admin console (https://login.tailscale.com/admin/machines),
   open each machine's `···` menu → **Edit tags** → add `tag:vds` to the VDS
   and `tag:pc1` to PC1. (The CLI equivalent, `tailscale up
   --advertise-tags=tag:vds`, requires the tag to already exist in
   `tagOwners` and the account to be an owner of it — the console method
   sidesteps that and is simpler for a one-off setup.)
4. **Apply the ACL.** Admin console → **Access Controls** → replace the
   policy with the contents of `deploy/tailnet-acl.json` → Save. This is a
   default-deny policy: the only permitted flow anywhere on the tailnet
   becomes `tag:vds → tag:pc1:22,3389`, and it disables Tailscale SSH
   (`"ssh": []`).
5. **Disable key expiry on the VDS node.** Admin console → Machines → the
   VDS row → `···` → **Disable key expiry**. Without this, the VDS's
   tailnet key silently expires (Tailscale's default is 180 days) and PC1
   becomes unreachable over the tailnet — every `/rdp_on` then fails with
   "PC1 unreachable", even though Telegram itself keeps working fine (the
   bot's Telegram connection doesn't go over the tailnet at all).
6. **Enable device approval.** Admin console → **Settings → Device
   management** → toggle on. New devices joining the tailnet (including a
   rogue one from a compromised Tailscale account) now need manual
   admin approval before they can talk to anything.
7. **Enable tailnet lock.** From an already-approved node:
   `tailscale lock init` — the admin console will walk you through
   generating the exact command with the correct key arguments; running it
   prints ten disablement secrets. Store those somewhere durable and
   offline (not on the VDS). Verify with `tailscale lock status`, which
   should list your signing key and report the lock as enabled.

*Verify:* on the VDS, `tailscale status` lists both PC1 and the VDS itself
(each on a `100.x.y.z` address, `tag:pc1` / `tag:vds` shown as the owner).
Then `tailscale ping <PC1's 100.x address>` succeeds (reports `pong from
... via ...`). If the ping never resolves, the ACL or the tags are wrong —
fix this before continuing; nothing past this point works without it.

## 3. VDS install

From a checkout of this repository on the VDS:

```
sudo deploy/install-vds.sh
```

This is idempotent — safe to re-run for updates. It, in order: installs
`socat`, `ufw`, `python3-venv`, `openssh-client`; creates the `safeconnect`
system account; copies `bot/` in root-owned and read-only (the bot cannot
rewrite its own code); builds a venv and installs dependencies with
`--require-hashes`; installs `deploy/ufw-port` and validates
`deploy/sudoers.safe-connect` with `visudo -cf` *before* installing it (a
malformed sudoers fragment breaks `sudo` system-wide, not just this grant —
the script refuses to install to `/etc/sudoers.d/` first); writes
`/etc/safe-connect/config.toml` and `/etc/safe-connect/env` from templates,
if they don't already exist; generates the SSH keypair PC1 will trust, if
one doesn't already exist; allows OpenSSH through `ufw` *and only then*
enables it (allowing first matters — enabling with default-deny-incoming
and no SSH rule yet would cut off the very SSH session running the
installer); and installs and enables the systemd unit, restarting it only
if it was already running (so a first install never starts the bot before
you've supplied a token, and a later re-run picks up new code immediately).

At the end it prints the VDS's SSH public key. **Copy it now** — you need
it for the next step.

Also decide `pc1_ssh_user` now: it's the login name of the PC1
administrator account you'll use — the same one you're about to run
`install-pc1.ps1` under. On PC1, an elevated PowerShell prompt's title bar
or `whoami` shows `COMPUTERNAME\username`; use just the `username` part
(no backslash, no computer name) as `pc1_ssh_user`. This works even on a
Russian-locale Windows install because it's the account's own login name,
which you chose — it is not one of the localized built-in group/account
names that trip up `icacls`/`auditpol` elsewhere in this project.

You can fill in `vds_public_ip` and `pc1_tailnet_ip` in
`/etc/safe-connect/config.toml` now (both are already known — the VDS's own
public IP, and PC1's `100.x` address from `tailscale status`). Leave
`telegram_user_id` for after the BotFather step, and leave
`SAFE_CONNECT_TELEGRAM_TOKEN=replace-me` in `/etc/safe-connect/env` for now.

*Verify:* the script exits 0 and its final block lists the public key
starting `ssh-ed25519 AAAA...`. `systemctl is-enabled safe-connect` prints
`enabled` (it is not yet *running* — that's expected, you haven't supplied
a token).

## 4. PC1 install

Copy `agent/` from this repository onto PC1 (any transport — USB stick,
file share, `scp` if you've enabled it manually). From an **elevated**
PowerShell prompt on PC1, in the `agent` directory:

```powershell
.\install-pc1.ps1 -VdsPublicKey "ssh-ed25519 AAAA...(the key printed in step 3)" -VdsTailnetIp 100.x.y.z
```

`-VdsTailnetIp` is the VDS's own `100.x` tailnet address (from
`tailscale status`, run on either node). Paste the public key exactly as
printed — the script rejects it outright if it contains an embedded
newline (an easy paste slip that would otherwise corrupt
`administrators_authorized_keys` into an unrestricted key line with no
forced command at all) or if it doesn't look like a single
`<type> <base64> [comment]` line.

This script, in order: installs and starts the OpenSSH Server optional
feature; copies `agent.ps1` and writes `agent.config.json` with your VDS's
tailnet IP; **locks down `C:\ProgramData\SafeConnect` and
`administrators_authorized_keys`** using the well-known SIDs `*S-1-5-18`
(SYSTEM) and `*S-1-5-32-544` (Administrators) rather than the readable
names `SYSTEM`/`Administrators` — on a Russian-locale Windows (this
machine) the localized group name is `Администраторы`, and `icacls` fails
to resolve the English literal with exit code 1332; every `icacls` call is
checked for a non-zero exit and aborts the script rather than silently
leaving the target writable; writes the forced-command line into
`administrators_authorized_keys` (auto-detecting whether the local OpenSSH
build is new enough for `restrict`, falling back to the equivalent
`no-pty,no-port-forwarding,...` option list otherwise); sets
`fDenyTSConnections=1` (RDP starts disabled) and disables the
`SafeConnect-RDP-In` firewall rule if a stale one exists; requires NLA
(`UserAuthentication=1`); sets an account lockout policy (5 attempts, 15
minute lockout/window) via `net accounts`, whose switches are fixed English
tokens and so — unlike `icacls`/`auditpol` — work unmodified on a localized
Windows; and enables Windows logon auditing (success and failure) via the
audit-subcategory GUID `{0CCE9215-69AE-11D9-BED3-505054503030}` rather than
the localized name `"Logon"` (which is `"Вход в систему"` here and would
make `auditpol` fail with exit code 87). Every one of these steps that can
silently fail on a non-English system is checked and aborts the script
loudly rather than reporting `Done` over a partial lockdown.

*Verify (on PC1):* `Get-Service sshd` shows `Status: Running`,
`StartType: Automatic`. `(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections`
prints `1`.

Now go back to the VDS and accept PC1's host key — this must be a plain,
interactive `ssh`, not a call through the bot (the bot's own connections
use `StrictHostKeyChecking=yes`, which refuses to prompt and will simply
fail on a host it has never seen):

```
sudo -H -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <pc1_ssh_user>@<pc1-tailnet-ip> status
```

Type `yes` at the fingerprint prompt. The `-H` here is deliberate and goes
beyond what `install-vds.sh` prints at the end of step 3: without it, plain
`sudo -u safeconnect` leaves `$HOME` as your own login's home directory
(Ubuntu's `sudo` does not repoint `$HOME` at the target user on `-u` alone),
so `ssh` would try to read and write `~root/.ssh/known_hosts` — a path
`safeconnect` cannot write to — and the accepted host key would never
persist. Under the real systemd service, this isn't an issue: systemd sets
`$HOME` for `User=safeconnect` automatically. `-H` here just reproduces
that for this one manual command, so the fingerprint is saved to
`/var/lib/safe-connect/.ssh/known_hosts`, the same place the running bot
will look for it.

*Verify:* the command's last line of output is exactly:

```
{"ok":true,"rdp_enabled":false}
```

`rdp_enabled` is `false` because `install-pc1.ps1` left RDP disabled — that
is correct at this point, nothing has enabled it yet.

## 5. BotFather

1. Message `@BotFather` on Telegram, `/newbot`, follow the prompts. Copy
   the token it gives you.
2. `/setprivacy` on `@BotFather`, choose your bot, set it to **Disabled**
   (group privacy off — irrelevant here since this bot only ever talks to
   one user in a DM, but harmless either way; skip it if you prefer).
3. Message `@userinfobot` from the Telegram account you'll be operating
   from. It replies with your numeric user ID.

*Verify:* you have a token that looks like `123456789:AA...` and a numeric
user ID.

## 6. Finish configuration and start the bot

On the VDS, edit `/etc/safe-connect/config.toml`:

```toml
telegram_user_id = 123456789        # from @userinfobot
vds_public_ip = "198.51.100.7"      # this VDS's public IP
pc1_tailnet_ip = "100.101.102.103"  # PC1's 100.x address
pc1_ssh_user = "rdpadmin"           # decided in step 3
```

Put the token in `/etc/safe-connect/env`:

```
SAFE_CONNECT_TELEGRAM_TOKEN=123456789:AA...
```

Start it:

```
sudo systemctl start safe-connect
sudo journalctl -u safe-connect -f
```

*Verify:* the journal shows `safe-connect started` with no traceback
immediately after. Message `/help` to your bot on Telegram — it should
reply within a couple of seconds with the four-command list. If a message
from your own Telegram account produces no reply at all, `telegram_user_id`
is wrong (the bot's `AuthMiddleware` drops anything from an unrecognized
sender with no reply, by design — check the journal for a line like
`ignored a message from unauthorised Telegram user ...` to confirm that's
what's happening, and compare the number against what `@userinfobot`
reported).

## 7. First smoke test

With `journalctl -u safe-connect -f` still open in one terminal:

1. `/status` — expect exactly `Closed. No public port, RDP disabled on
   PC1.`
2. `/rdp_on <your current public IP>` (find it with `curl -4 ifconfig.me`
   from PC2, or whatever machine you'll connect from) — expect, with the
   default `idle_timeout_seconds`/`hard_cap_seconds` from
   `config.example.toml`:
   ```
   RDP open at <vds-ip>:<port>
   Source: <your ip>/32
   Closes after 10 min idle, or 8 h maximum.
   ```
   with `<port>` between 40000 and 40100.
3. Connect with `mstsc /v:<vds-ip>:<port>` from PC2.
4. `/status` again — expect four lines: `Open at <vds-ip>:<port>`,
   `Source: <your ip>/32`, an `Idle timeout in Nm.` line (N close to 10,
   now that a connection has been seen), and `Hard cap in Nm.` (N close to
   480).
5. `/rdp_off` — expect `Session closed after 0m (operator request).` on
   the first line, then a logon line: `Logons: 1 success (<windows
   username> from <your ip>), 0 failures.` if you completed the Windows
   login, or `Logons: 0 successes, 0 failures.` if you only reached the
   connection dialog. (Note the code's own pluralization is inconsistent —
   "success"/"successes" is correctly pluralized but "failures" is not
   grammatically singular for a count of 1; harmless, just don't be
   surprised by `1 failures`.)

*Verify, on the VDS:* while the session from list items 2–4 above is open,
`ss -ltn | grep :<port>` shows a `LISTEN` line; `sudo ufw status | grep
<port>` shows an `ALLOW` rule for it. After list item 5 (`/rdp_off`), both
commands show nothing for that port.

## 8. Verify the forced command actually restricts the key — do not skip this

Everything in `docs/SECURITY.md` about "root on the VDS cannot get a shell
on PC1" depends entirely on the forced-command line in PC1's
`administrators_authorized_keys` actually being honored by `sshd`, not just
present in the file. Test it directly, from the VDS:

```
sudo -H -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <pc1_ssh_user>@<pc1-tailnet-ip> "whoami"
```

(`-H` for the same reason as step 4 — it makes this manual invocation use
the same known-hosts file the running bot uses, so this test reflects the
bot's real behaviour rather than a fresh, unrelated known-hosts prompt.)

*Expected output, exactly:*

```
{"ok":false,"error":"unknown verb: whoami"}
```

This is what `agent.ps1` prints when it receives a command outside its
four-verb vocabulary (`enable`, `disable`, `status`, `audit`) — `whoami`
falls to the `default` branch, which throws `unknown verb: $verb`, caught
and reported as this JSON line rather than crashing.

**If a Windows username comes back instead of that JSON line — stop.** That
means the forced command in `administrators_authorized_keys` is not being
applied (a missing `restrict,command="..."` prefix, a key mismatch, or a
line that got split across two lines by a copy-paste newline). The key now
grants a full shell to whoever holds it. Do not open any session, do not
proceed to Appendix A or B, until this line reads back the JSON refusal
above. Re-run `install-pc1.ps1` (it is idempotent) or inspect
`C:\ProgramData\ssh\administrators_authorized_keys` by hand.

## 9. Run the socat integration tests on the VDS

The forwarder tests that talk to a real `socat` process and a real kernel
socket table are skipped anywhere `socat` isn't installed — which, until
now, was every machine this project was developed on. `install-vds.sh`
just put `socat` on the VDS, so this is the first place they can actually
run. The app's own venv at `/opt/safe-connect/.venv` is deliberately
`--require-hashes` production-only (no `pytest`) and root-owned — don't
install test tooling into it. Build a separate, throwaway venv from the
repo checkout instead:

```
cd /path/to/safe-connect   # your checkout, not /opt/safe-connect
python3 -m venv .venv-test
.venv-test/bin/pip install -r requirements.txt
.venv-test/bin/pip install pytest pytest-asyncio
.venv-test/bin/pytest tests/test_forwarder_integration.py -v
```

Two separate `pip install` calls, deliberately: `requirements.txt` is
generated with `--generate-hashes`, which puts `pip` into hash-checking
mode for that call — every entry in it has a hash, so it's satisfied on its
own. Passing `pytest pytest-asyncio` on the same command line as that file
would put pip in the position of hash-checking packages that were never
given hashes, which it refuses to do. Installing them in a second,
plain call sidesteps that; this venv never runs in production, so
hash-enforcement doesn't need to apply to it the way it does to
`/opt/safe-connect/.venv`.

*Verify:* every test in that file passes, none skipped. If you see
`SKIPPED (socat not installed)`, the package install in step 3 didn't
succeed — check `apt list --installed | grep socat`.

## 10. Troubleshooting

**PC1 unreachable** (`/rdp_on` replies `PC1 unreachable — is it powered on
and on the tailnet?`) — Is PC1 powered on? `tailscale ping
<pc1-tailnet-ip>` from the VDS: if that fails, it's a tailnet problem
(check ACL, tags, and that `tailscale up` was actually run on PC1, not just
installed). If ping succeeds but the bot still reports unreachable, `ssh`
itself is failing — try the manual `status` command from step 4 again and
read the stderr.

**socat cannot bind** (`/rdp_on` replies `Could not open a public port
after three attempts. Nothing was opened.`) — something else is already
listening on ports in 40000–40100 on the VDS, or `ufw`'s state is
inconsistent. Check `ss -ltn` for stray listeners and `sudo ufw status
numbered` for leftover rules from a previous crashed session; `sudo ufw
delete <n>` to clear one.

**`ufw-port open failed: ERROR: '/etc/ufw/user.rules' is not writable`** —
the sudo call reached root (you'll see `session opened for user root` in
`journalctl -u safe-connect`), but the write was refused by the sandbox, not
by file permissions. `ProtectSystem=strict` mounts the filesystem read-only
inside the unit's mount namespace and the `sudo` → `ufw` child inherits it;
a read-only mount refuses writes regardless of uid, so being root doesn't
help. The unit must carve out both paths `ufw` needs:

```
ReadWritePaths=/var/lib/safe-connect /etc/ufw /run
```

`/etc/ufw` for `user.rules`/`user6.rules`, `/run` for the
`/run/xtables.lock` that `iptables-restore` takes. To confirm this is the
cause rather than real permissions, run the same command from an
interactive shell, outside the service's namespace:

```bash
sudo -u safeconnect sudo -n /usr/local/lib/safe-connect/ufw-port open 40082 203.0.113.9/32
```

If that succeeds while the service's identical call fails, it is the
namespace. If it also fails, check `lsattr /etc/ufw/user.rules` for an
immutable flag. Apply the fix by re-running `sudo deploy/install-vds.sh`,
which reinstalls the unit, reloads systemd, and restarts the service if it
was already running.

**`sudo: a password is required`** — the sudoers fragment at
`/etc/sudoers.d/safe-connect` is missing, wrong, or was hand-edited badly.
Re-run `sudo deploy/install-vds.sh` (it validates with `visudo -cf` before
installing, so a broken *source* file would have been caught at install
time — but a file edited by hand afterward isn't re-validated by anything).
Confirm with `sudo -l -U safeconnect`, which should list exactly
`/usr/local/lib/safe-connect/ufw-port` as a `NOPASSWD` command.

**A stale state file** — if the bot was killed with `kill -9` or the VDS
lost power mid-session, `/var/lib/safe-connect/state.json` may say `open`
when nothing is actually listening. You shouldn't need to touch this by
hand: `SessionManager.reconcile()` runs on every startup and tears down any
`open` state whose recorded `socat` pid isn't alive, sending you a
`cleanup after a bot restart` notification. If the bot isn't restarting on
its own, `sudo systemctl restart safe-connect` forces reconciliation.

**Telegram not polling** — `journalctl -u safe-connect -e` for the actual
exception; `aiogram` logs failures from `dispatcher.start_polling` loudly.
A `401 Unauthorized` there means the token in `/etc/safe-connect/env` is
wrong or was revoked; regenerate it with `@BotFather` → `/revoke` (or
`/token`) and update the file, then `sudo systemctl restart safe-connect`.

## Appendix A: pinning PC1's RDP certificate on PC2

**Closes:** the VDS is on-path for RDP by design (`docs/SECURITY.md`,
channel 5 and the "no cert pinning by default" accepted risk). Without
this, an active attacker with root on the VDS can present their own RDP
endpoint and self-signed certificate to PC2, and Windows will *warn* about
the mismatch rather than refuse the connection — a habituated operator can
click through that warning and hand over credentials to the attacker's
fake endpoint. This closes that: it turns the warning into an outright
connection failure.

1. **On PC1**, run `certlm.msc` (elevated). Navigate to
   **Remote Desktop → Certificates**. Find the certificate whose subject is
   PC1's hostname. Right-click → **All Tasks → Export**. Choose **No, do
   not export the private key**, DER-encoded binary X.509 (`.cer`).
2. Move the exported `.cer` file to PC2 by a channel that does **not**
   cross the VDS — a USB drive, a direct LAN copy while both machines are
   local, etc. If it travels through the VDS (e.g. as a Telegram
   attachment, or `scp` via the VDS), an attacker who already controls the
   VDS could substitute their own certificate in transit, defeating the
   entire point.
3. **On PC2**, run `certlm.msc` (or `certmgr.msc` for a per-user store,
   elevated either way). Navigate to
   **Trusted Root Certification Authorities → Certificates → All Tasks →
   Import**. Select the `.cer` file.
4. Build or edit the `.rdp` file/shortcut you use to connect and add:
   ```
   authentication level:i:2
   ```
   (`0` = connect regardless of cert problems, `1` = warn and let the user
   decide — the RDP client default, `2` = refuse to connect if
   authentication fails. `2` is what makes the pinned certificate load-
   bearing rather than cosmetic.)

*Verify:* connect once normally to confirm the pinned cert is trusted (no
warning). Then temporarily point the `.rdp` file's `full address` at
something that presents a *different* certificate (any other host running
RDP, or a `socat` relay to a different backend) — the connection should be
refused outright, not just warned about. Point it back at the real VDS
address afterward.

## Appendix B: adding a TOTP factor to `/rdp_on`

**Defends against:** a Telegram account takeover. If someone gains control
of the operator's Telegram session (SIM-swap, stolen session, a leaked
Telegram cloud-password), they can message the bot as the authorized
`telegram_user_id` and issue `/rdp_on <their IP>`. Requiring a TOTP code
the attacker doesn't have stops that specific escalation cold, even though
they've already defeated Telegram's own auth.

**Does not defend against:** a compromised VDS. The TOTP shared secret has
to live somewhere the bot process can read it to verify codes, and the bot
process runs on the VDS — the one host this whole design treats as
untrusted. Root on the VDS reads the secret the same way it would read
anything else `safeconnect` can read, and can then compute valid codes
itself, or simply skip the check by patching the running process. This is
a mitigation for *Telegram-side* compromise only, layered on top of, not a
replacement for, the VDS-untrusted model in `docs/SECURITY.md`.

**Code change required** (not applied by this runbook — this project ships
documentation only for this task):

1. Add a dependency, e.g. `pyotp`, pinned with hashes like the rest of
   `requirements.txt`.
2. `bot/config.py`: add `totp_secret: SecretStr | None = None`.
3. `bot/main.py`'s `handle_rdp_on`: require and verify a second token in
   the command, e.g. `/rdp_on <ip> <6-digit code>` — extend the `maxsplit`
   parsing to pull both fields, verify with
   `pyotp.TOTP(secret).verify(code, valid_window=1)`, and return a refusal
   string (not a silent drop — this sender is already authenticated as the
   operator by Telegram, just missing the second factor) on failure
   *before* calling `manager.open(...)`.
4. Guard against code replay within the same 30-second window: track the
   last-accepted code (or its timestamp) and reject a repeat, since TOTP
   alone permits reusing an intercepted code until it expires.
5. Generate the shared secret once, out of band, and enroll it in an
   authenticator app — never transmit it through Telegram or store it
   anywhere the VDS-untrusted boundary doesn't already cover (i.e., no
   weaker protection than the SSH key already gets).
