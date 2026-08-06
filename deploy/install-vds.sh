#!/bin/bash
# Idempotent VDS installer. Re-running it is safe and is the supported way to
# apply an update. Run as root from a checkout of this repository.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=/opt/safe-connect
CONFDIR=/etc/safe-connect
STATEDIR=/var/lib/safe-connect
LIBDIR=/usr/local/lib/safe-connect

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

echo "==> packages"
apt-get update -qq
apt-get install -y -qq socat ufw python3-venv openssh-client

echo "==> service account"
id -u safeconnect >/dev/null 2>&1 || useradd --system --home "$STATEDIR" --shell /usr/sbin/nologin safeconnect

echo "==> directories"
install -d -o root -g root -m 0755 "$PREFIX" "$LIBDIR" "$CONFDIR"
install -d -o safeconnect -g safeconnect -m 0700 "$STATEDIR"

echo "==> application code (root-owned; the bot cannot rewrite itself)"
rm -rf "$PREFIX/bot"
cp -r "$REPO/bot" "$PREFIX/bot"
chown -R root:root "$PREFIX/bot"
chmod -R a-w "$PREFIX/bot"

echo "==> virtualenv (hash-enforced, so a substituted package fails the install)"
[ -d "$PREFIX/.venv" ] || python3 -m venv "$PREFIX/.venv"
"$PREFIX/.venv/bin/pip" install -q --upgrade pip
install -o root -g root -m 0644 "$REPO/requirements.txt" "$PREFIX/requirements.txt"
"$PREFIX/.venv/bin/pip" install -q --require-hashes -r "$PREFIX/requirements.txt"
chown -R root:root "$PREFIX/.venv"

echo "==> ufw wrapper and sudo grant"
install -o root -g root -m 0755 "$REPO/deploy/ufw-port" "$LIBDIR/ufw-port"
# Validate the sudoers fragment before it ever lands in /etc/sudoers.d: a
# malformed file there breaks sudo for the whole system, not just this grant.
visudo -cf "$REPO/deploy/sudoers.safe-connect"
install -o root -g root -m 0440 "$REPO/deploy/sudoers.safe-connect" /etc/sudoers.d/safe-connect

echo "==> configuration"
if [ ! -f "$CONFDIR/config.toml" ]; then
  install -o root -g safeconnect -m 0640 "$REPO/deploy/config.example.toml" "$CONFDIR/config.toml"
  echo "    wrote $CONFDIR/config.toml — edit it before starting the service"
fi
if [ ! -f "$CONFDIR/env" ]; then
  printf 'SAFE_CONNECT_TELEGRAM_TOKEN=replace-me\n' > "$CONFDIR/env"
  chown root:safeconnect "$CONFDIR/env"
  chmod 0640 "$CONFDIR/env"
  echo "    wrote $CONFDIR/env — put your BotFather token there"
fi

echo "==> SSH key for PC1"
if [ ! -f "$STATEDIR/id_ed25519" ]; then
  sudo -u safeconnect ssh-keygen -t ed25519 -N '' -C safe-connect -f "$STATEDIR/id_ed25519"
  echo "    generated a key; its public half goes into PC1's administrators_authorized_keys"
fi

echo "==> baseline firewall"
# Allow SSH before enabling: enabling first (with default-deny incoming and no
# SSH rule yet) would cut off the very session running this installer.
ufw allow OpenSSH
ufw --force enable

echo "==> service"
install -o root -g root -m 0644 "$REPO/deploy/safe-connect.service" /etc/systemd/system/safe-connect.service
systemctl daemon-reload
systemctl enable safe-connect.service

cat <<'DONE'

Installed. Remaining steps, in order:
  1. edit /etc/safe-connect/config.toml
  2. put the bot token in /etc/safe-connect/env
  3. add this public key to PC1 (see docs/RUNBOOK.md step 4):
DONE
cat "$STATEDIR/id_ed25519.pub"
cat <<'DONE'
  4. accept PC1's host key once:
       sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1-tailnet-ip> status
  5. systemctl start safe-connect && journalctl -u safe-connect -f
DONE
