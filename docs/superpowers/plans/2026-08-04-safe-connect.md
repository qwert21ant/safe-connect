# Safe Connect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Telegram bot that opens on-demand, IP-restricted, auto-expiring RDP access to a Windows PC behind NAT, bridged by a public Ubuntu VDS over Tailscale.

**Architecture:** An unprivileged systemd service on the VDS owns a state machine. Opening a session enables RDP on PC1 through an SSH key pinned to a forced command, then spawns a per-session `socat` listener on a random high port with a per-session `ufw` rule applied by a single root-owned validated wrapper. Closing reverses that order, killing the public listener first. Timers run on the asyncio loop, independent of Telegram.

**Tech Stack:** Python 3.12, aiogram 3, pydantic-settings, socat, ufw, OpenSSH, Tailscale, PowerShell 5.1 (PC1 agent), systemd.

**Spec:** `docs/superpowers/specs/2026-08-04-safe-connect-design.md`

## Global Constraints

- Python 3.12. Runtime dependencies are **exactly** `aiogram` and `pydantic-settings`. No `paramiko` — the system `ssh` binary is invoked directly.
- **`shell=True` must appear nowhere in `bot/`.** All subprocess calls use argv lists. Enforced by a test in Task 4.
- The operator's raw input string must never reach a command line. `parse_source()` output is used instead.
- All development and testing happens in **WSL Ubuntu** (`wsl -d Ubuntu`). Git Bash lacks `socat`, `ss`, and POSIX `bash` semantics. The repo lives at `/mnt/c/projects/safe-connect`.
- Target hosts: Ubuntu 22.04/24.04 VDS, Windows 11 Pro PC1.
- Defaults, all overridable in `config.toml`: `port_range` 40000–40100, `connect_grace` 300 s, `idle_timeout` 600 s, `hard_cap` 28800 s, `poll_interval` 30 s.
- The bot's only sudo right is `/usr/local/lib/safe-connect/ufw-port`. Never add `env_keep` to the sudoers entry.
- The Windows firewall rule is named `SafeConnect-RDP-In`. The built-in "Remote Desktop" rule group is never enabled.
- Agent verbs are exactly `enable`, `disable`, `status`, `audit`.
- Commit after every task.

---

## File Structure

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata, pinned deps, pytest config |
| `bot/config.py` | Settings model; TOML file plus secrets from environment |
| `bot/validation.py` | `parse_source()` — the only sanctioned way to interpret operator input |
| `bot/proc.py` | Async argv-only subprocess runner |
| `bot/forwarder.py` | socat + ufw lifecycle |
| `bot/pc1.py` | SSH forced-command client and RDP TCP probe |
| `bot/session.py` | State machine, persistence, timers, orchestration |
| `bot/notify.py` | Message formatting; Telegram notifier |
| `bot/main.py` | aiogram wiring, auth middleware, handlers, tick loop |
| `deploy/ufw-port` | Root-owned validated ufw wrapper |
| `deploy/install-vds.sh` | Idempotent VDS installer |
| `deploy/safe-connect.service` | Hardened systemd unit |
| `deploy/tailnet-acl.json` | Default-deny Tailscale ACL |
| `agent/agent.ps1` | The only program the SSH key may execute on PC1 |
| `agent/install-pc1.ps1` | PC1 bootstrap |
| `docs/RUNBOOK.md`, `docs/SECURITY.md` | Operator documentation |

---

### Task 1: Dev environment, packaging, and config

**Files:**
- Create: `pyproject.toml`, `requirements.txt`, `bot/__init__.py`, `bot/config.py`, `deploy/config.example.toml`
- Test: `tests/__init__.py`, `tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `bot.config.Config` (pydantic `BaseSettings`) and `bot.config.load_config(path: Path) -> Config`. Every later task takes a `Config` instance. Field names are fixed here and used verbatim throughout.

- [ ] **Step 1: Create the WSL venv and install dependencies**

```bash
wsl -d Ubuntu -- bash -lc 'sudo apt-get update && sudo apt-get install -y socat python3-venv'
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && python3 -m venv .venv && .venv/bin/pip install -q aiogram==3.15.0 pydantic-settings==2.7.0 pytest==8.3.4 pytest-asyncio==0.25.0'
```

Run every later `pytest` command as `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest ...'`.

- [ ] **Step 2: Write `pyproject.toml`**

```toml
[project]
name = "safe-connect"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["aiogram==3.15.0", "pydantic-settings==2.7.0"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = ["requires_socat: needs a real socat binary and Linux /proc"]
```

- [ ] **Step 3: Generate the hash-pinned requirements file**

The spec requires dependencies pinned with hashes, so a compromised index cannot
substitute a package. Generate them rather than transcribing them:

```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pip install -q pip-tools && printf "aiogram==3.15.0\npydantic-settings==2.7.0\n" > requirements.in && .venv/bin/pip-compile --generate-hashes --quiet --output-file requirements.txt requirements.in'
```

Verify the result installs under hash enforcement:

```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pip install -q --require-hashes -r requirements.txt && echo "hashes ok"'
```
Expected: `hashes ok`.

- [ ] **Step 4: Create `tests/__init__.py`**

An empty file. It makes `tests` a package so `tests/conftest.py` can do
`from tests.test_forwarder import make_config` in Task 8, and it puts the repo
root on `sys.path` so `import bot` resolves without installing the package.

```bash
wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && mkdir -p tests bot && touch tests/__init__.py bot/__init__.py'
```

- [ ] **Step 5: Write the failing test**

`tests/test_config.py`:

```python
from pathlib import Path

import pytest

from bot.config import Config, load_config

MINIMAL = """
telegram_user_id = 12345
vds_public_ip = "198.51.100.7"
pc1_tailnet_ip = "100.101.102.103"
pc1_ssh_user = "rdpadmin"
pc1_ssh_key_path = "/var/lib/safe-connect/id_ed25519"
"""


def write_cfg(tmp_path: Path, body: str = MINIMAL) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def test_loads_toml_and_takes_token_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert cfg.telegram_user_id == 12345
    assert cfg.telegram_token.get_secret_value() == "123:ABC"


def test_defaults_match_the_spec(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert (cfg.port_range_start, cfg.port_range_end) == (40000, 40100)
    assert cfg.connect_grace_seconds == 300
    assert cfg.idle_timeout_seconds == 600
    assert cfg.hard_cap_seconds == 28800
    assert cfg.poll_interval_seconds == 30


def test_token_is_not_exposed_by_repr(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert "123:ABC" not in repr(cfg)


def test_rejects_inverted_port_range(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    body = MINIMAL + "\nport_range_start = 40100\nport_range_end = 40000\n"
    with pytest.raises(ValueError, match="port_range_start"):
        load_config(write_cfg(tmp_path, body))


def test_rejects_unknown_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    with pytest.raises(ValueError):
        load_config(write_cfg(tmp_path, MINIMAL + '\nnonsense = "x"\n'))
```

- [ ] **Step 6: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_config.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.config'`.

- [ ] **Step 7: Implement `bot/config.py`**

```python
from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """Runtime settings.

    Everything except the bot token comes from config.toml. The token comes from
    the environment (SAFE_CONNECT_TELEGRAM_TOKEN) so it never lands in a file
    that could be committed.
    """

    model_config = SettingsConfigDict(env_prefix="SAFE_CONNECT_", extra="forbid")

    telegram_token: SecretStr
    telegram_user_id: int

    vds_public_ip: str
    pc1_tailnet_ip: str
    pc1_ssh_user: str
    pc1_ssh_key_path: Path

    port_range_start: int = 40000
    port_range_end: int = 40100

    connect_grace_seconds: int = 300
    idle_timeout_seconds: int = 600
    hard_cap_seconds: int = 28800
    poll_interval_seconds: int = 30
    hard_cap_warning_seconds: int = 300

    state_path: Path = Path("/var/lib/safe-connect/state.json")
    ufw_port_helper: Path = Path("/usr/local/lib/safe-connect/ufw-port")
    sudo_path: Path = Path("/usr/bin/sudo")
    socat_path: Path = Path("/usr/bin/socat")
    ssh_path: Path = Path("/usr/bin/ssh")
    ss_path: Path = Path("/usr/bin/ss")

    @model_validator(mode="after")
    def _check_port_range(self) -> "Config":
        if self.port_range_start >= self.port_range_end:
            raise ValueError("port_range_start must be below port_range_end")
        if self.port_range_start < 1024:
            raise ValueError("port_range_start must be above 1023 so no privileges are needed")
        return self


def load_config(path: Path) -> Config:
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return Config(**data)
```

- [ ] **Step 8: Write `deploy/config.example.toml`**

```toml
# Copy to /etc/safe-connect/config.toml. The bot token does NOT belong here —
# it is read from SAFE_CONNECT_TELEGRAM_TOKEN, supplied by systemd's EnvironmentFile.

telegram_user_id = 000000000        # your numeric Telegram user ID
vds_public_ip = "198.51.100.7"      # the address you will point mstsc at
pc1_tailnet_ip = "100.101.102.103"  # PC1's 100.x address from `tailscale status`
pc1_ssh_user = "rdpadmin"           # the PC1 account holding the forced-command key
pc1_ssh_key_path = "/var/lib/safe-connect/id_ed25519"

# port_range_start = 40000
# port_range_end = 40100
# connect_grace_seconds = 300
# idle_timeout_seconds = 600
# hard_cap_seconds = 28800
# poll_interval_seconds = 30
```

- [ ] **Step 9: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_config.py -v'`
Expected: 5 passed.

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml requirements.in requirements.txt bot/ deploy/config.example.toml tests/
git commit -m "feat: config model loaded from TOML with token from environment"
```

---

### Task 2: Source address validation

**Files:**
- Create: `bot/validation.py`
- Test: `tests/test_validation.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `parse_source(raw: str) -> str` returning either the literal `"any"` or a single-host CIDR `"203.0.113.9/32"`; raises `InvalidSource(ValueError)`. `bot/session.py` and `bot/main.py` call this and use only the return value.

- [ ] **Step 1: Write the failing test**

`tests/test_validation.py`:

```python
import pytest

from bot.validation import InvalidSource, parse_source


def test_public_address_becomes_single_host_cidr():
    assert parse_source("203.0.113.9") == "203.0.113.9/32"


def test_surrounding_whitespace_is_tolerated():
    assert parse_source("  203.0.113.9  ") == "203.0.113.9/32"


def test_any_is_accepted_verbatim():
    assert parse_source("any") == "any"


@pytest.mark.parametrize(
    "hostile",
    [
        "203.0.113.9; rm -rf /",
        "203.0.113.9 && id",
        "$(id)",
        "`id`",
        "203.0.113.9\nid",
        "203.0.113.9|id",
        "203.0.113.9/32",       # we accept bare addresses only
        "203.0.113.9,203.0.113.10",
        "--flag",
        "",
        "ANY",                  # the opt-out token is case-sensitive
        "2001:db8::1",          # IPv6 is out of scope
        "999.1.1.1",
        "203.0.113.09",         # leading zeros are ambiguous, rejected
        "example.com",
    ],
)
def test_hostile_and_malformed_input_is_rejected(hostile):
    with pytest.raises(InvalidSource):
        parse_source(hostile)


@pytest.mark.parametrize(
    "nonroutable",
    ["10.0.0.5", "192.168.1.10", "172.16.4.4", "127.0.0.1",
     "169.254.1.1", "224.0.0.1", "0.0.0.0", "100.101.102.103"],
)
def test_non_routable_addresses_are_rejected(nonroutable):
    """100.64/10 matters specifically: it is the tailnet range."""
    with pytest.raises(InvalidSource):
        parse_source(nonroutable)
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_validation.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.validation'`.

- [ ] **Step 3: Implement `bot/validation.py`**

```python
from __future__ import annotations

import ipaddress

ANY = "any"

# Enumerated rather than derived from ipaddress's classification properties.
# `is_private` treats the RFC 5737 documentation ranges (including 203.0.113.0/24,
# this project's canonical example address) as private, and on Python 3.12.3 it
# does NOT cover 100.64.0.0/10 — the Tailscale range, which must be rejected.
# Its meaning has also shifted between releases. Pinning the ranges here makes
# the behaviour version-independent.
_REJECTED_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),        # unspecified / "this network"
    ipaddress.IPv4Network("10.0.0.0/8"),       # RFC1918
    ipaddress.IPv4Network("100.64.0.0/10"),    # CGNAT — also the Tailscale range
    ipaddress.IPv4Network("127.0.0.0/8"),      # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
    ipaddress.IPv4Network("172.16.0.0/12"),    # RFC1918
    ipaddress.IPv4Network("192.168.0.0/16"),   # RFC1918
    ipaddress.IPv4Network("224.0.0.0/4"),      # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # reserved
)


class InvalidSource(ValueError):
    """The operator's source argument is not an acceptable public IPv4 host."""


def parse_source(raw: str) -> str:
    """Normalise an operator-supplied source argument.

    Returns "any" or a single-host CIDR. Callers must use this return value and
    must never pass `raw` onward — it is attacker-influenced text.
    """
    candidate = raw.strip()
    if candidate == ANY:
        return ANY
    try:
        address = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError as exc:
        raise InvalidSource(f"not an IPv4 address: {raw!r}") from exc
    if any(address in network for network in _REJECTED_NETWORKS):
        raise InvalidSource(f"not a routable public address: {address}")
    return f"{address}/32"
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_validation.py -v'`
Expected: 26 passed.

- [ ] **Step 5: Commit**

```bash
git add bot/validation.py tests/test_validation.py
git commit -m "feat: reject hostile and non-routable source addresses"
```

---

### Task 3: Root-owned `ufw-port` wrapper

**Files:**
- Create: `deploy/ufw-port`
- Test: `tests/test_ufw_port.py`

**Interfaces:**
- Consumes: nothing.
- Produces: an executable taking `open|close <port> <source>`, exiting 0 on success and 2 on any validation failure. `bot/forwarder.py` invokes it as `sudo -n /usr/local/lib/safe-connect/ufw-port open 40017 203.0.113.9/32`.

**Why a wrapper rather than `NOPASSWD: /usr/sbin/ufw`:** a bare sudo right on `ufw` lets a compromised bot process pass arbitrary rule syntax, including rules that open unrelated ports or delete the SSH allow rule. This wrapper is the whole reason the sudo grant is safe.

- [ ] **Step 1: Write the failing test**

`tests/test_ufw_port.py`:

```python
import os
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "deploy" / "ufw-port"


@pytest.fixture
def fake_ufw(tmp_path):
    """A stand-in for ufw that records the argv it was called with."""
    log = tmp_path / "calls.log"
    recorder = tmp_path / "ufw"
    recorder.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$UFW_LOG"\nexit 0\n')
    recorder.chmod(0o755)
    return recorder, log


def run_wrapper(fake_ufw, *args):
    recorder, log = fake_ufw
    env = {**os.environ, "SAFE_CONNECT_UFW": str(recorder), "UFW_LOG": str(log)}
    result = subprocess.run(
        ["/bin/bash", str(WRAPPER), *args], capture_output=True, text=True, env=env
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result, calls


def test_open_with_single_host_builds_the_expected_ufw_rule(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "open", "40017", "203.0.113.9/32")
    assert result.returncode == 0, result.stderr
    assert calls == ["allow from 203.0.113.9 to any port 40017 proto tcp"]


def test_close_deletes_the_same_rule(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "close", "40017", "203.0.113.9/32")
    assert result.returncode == 0, result.stderr
    assert calls == ["delete allow from 203.0.113.9 to any port 40017 proto tcp"]


def test_any_opens_the_port_to_all_sources(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "open", "40017", "any")
    assert result.returncode == 0, result.stderr
    assert calls == ["allow 40017/tcp"]


@pytest.mark.parametrize(
    "args",
    [
        ("open", "39999", "203.0.113.9/32"),          # below the range
        ("open", "40101", "203.0.113.9/32"),          # above the range
        ("open", "22", "203.0.113.9/32"),             # the SSH port
        ("open", "abc", "203.0.113.9/32"),
        ("open", "40017", "203.0.113.0/24"),          # whole subnets are not allowed
        ("open", "40017", "203.0.113.9"),             # must be an explicit /32
        ("open", "40017", "999.1.1.1/32"),
        ("open", "40017", "203.0.113.9/32; id"),
        ("open", "40017", "-anything"),
        ("flush", "40017", "203.0.113.9/32"),         # unknown action
        ("open", "40017"),                            # too few arguments
        ("open", "40017", "203.0.113.9/32", "extra"),  # too many
    ],
)
def test_invalid_input_is_refused_without_touching_ufw(fake_ufw, args):
    result, calls = run_wrapper(fake_ufw, *args)
    assert result.returncode == 2, f"expected refusal, got {result.returncode}"
    assert calls == []
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_ufw_port.py -v'`
Expected: FAIL — the wrapper does not exist yet, so every case errors.

- [ ] **Step 3: Implement `deploy/ufw-port`**

```bash
#!/bin/bash
# Root-owned. The only command the `safeconnect` user may run under sudo.
#
#   ufw-port open|close <port> <source>
#     <port>    integer inside PORT_MIN..PORT_MAX
#     <source>  "any", or a single-host CIDR such as 203.0.113.9/32
#
# SAFE_CONNECT_UFW / SAFE_CONNECT_PORT_MIN / SAFE_CONNECT_PORT_MAX exist for the
# test suite. They are unreachable through the sudo path because sudo's default
# env_reset discards the caller's environment. Never add env_keep for them.
set -euo pipefail

PORT_MIN="${SAFE_CONNECT_PORT_MIN:-40000}"
PORT_MAX="${SAFE_CONNECT_PORT_MAX:-40100}"
UFW="${SAFE_CONNECT_UFW:-/usr/sbin/ufw}"

die() { printf 'ufw-port: %s\n' "$1" >&2; exit 2; }

[ "$#" -eq 3 ] || die "usage: ufw-port open|close <port> <source>"

action="$1"
port="$2"
source="$3"

case "$action" in
  open|close) ;;
  *) die "unknown action: $action" ;;
esac

[[ "$port" =~ ^[0-9]{1,5}$ ]] || die "port is not numeric: $port"
[ "$port" -ge "$PORT_MIN" ] && [ "$port" -le "$PORT_MAX" ] \
  || die "port $port is outside the permitted range $PORT_MIN-$PORT_MAX"

if [ "$source" != "any" ]; then
  [[ "$source" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/32$ ]] || die "bad source: $source"
  IFS='./' read -r o1 o2 o3 o4 _ <<< "$source"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [ "$octet" -le 255 ] || die "bad source octet in: $source"
  done
fi

host="${source%/32}"

if [ "$action" = "open" ]; then
  if [ "$source" = "any" ]; then
    "$UFW" allow "${port}/tcp"
  else
    "$UFW" allow from "$host" to any port "$port" proto tcp
  fi
else
  if [ "$source" = "any" ]; then
    "$UFW" delete allow "${port}/tcp"
  else
    "$UFW" delete allow from "$host" to any port "$port" proto tcp
  fi
fi
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && chmod +x deploy/ufw-port && .venv/bin/pytest tests/test_ufw_port.py -v'`
Expected: 15 passed.

- [ ] **Step 5: Commit**

```bash
git add deploy/ufw-port tests/test_ufw_port.py
git commit -m "feat: validated root wrapper for per-session ufw rules"
```

---

### Task 4: Subprocess runner and the no-shell guarantee

**Files:**
- Create: `bot/proc.py`
- Test: `tests/test_proc.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `bot.proc.Result` (frozen dataclass with `returncode: int`, `stdout: str`, `stderr: str`, property `ok: bool`), `async bot.proc.run(argv: Sequence[str], timeout: float = 30.0) -> Result`, and `bot.proc.ProcTimeout(RuntimeError)`. `Forwarder` and `PC1Client` both take a `runner` callable with `run`'s signature so tests can substitute a fake.

- [ ] **Step 1: Write the failing test**

`tests/test_proc.py`:

```python
from pathlib import Path

import pytest

from bot import proc


async def test_captures_stdout_and_returncode():
    result = await proc.run(["/bin/echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"


async def test_nonzero_exit_is_reported_not_raised():
    result = await proc.run(["/bin/false"])
    assert not result.ok
    assert result.returncode != 0


async def test_shell_metacharacters_stay_literal():
    """The whole point of argv lists: this must print the text, not run `id`."""
    result = await proc.run(["/bin/echo", "; id && rm -rf /"])
    assert result.stdout.strip() == "; id && rm -rf /"


async def test_timeout_kills_the_child():
    with pytest.raises(proc.ProcTimeout):
        await proc.run(["/bin/sleep", "5"], timeout=0.2)


async def test_empty_argv_is_rejected():
    with pytest.raises(ValueError):
        await proc.run([])


def test_no_module_in_bot_uses_shell_true():
    """A standing guard, not a one-off check. Re-run for the life of the project."""
    root = Path(__file__).resolve().parents[1] / "bot"
    offenders = [p.name for p in root.rglob("*.py") if "shell=True" in p.read_text()]
    assert offenders == []
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_proc.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.proc'`.

- [ ] **Step 3: Implement `bot/proc.py`**

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ProcTimeout(RuntimeError):
    """The child did not finish within the allotted time and was killed."""


async def run(argv: Sequence[str], timeout: float = 30.0) -> Result:
    """Run argv with no shell involved.

    There is deliberately no `shell` parameter. Every argument reaches the child
    verbatim, so operator-supplied text cannot become syntax.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise ProcTimeout(f"timed out after {timeout}s: {argv[0]}") from exc
    return Result(
        returncode=process.returncode or 0,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
    )
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_proc.py -v'`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add bot/proc.py tests/test_proc.py
git commit -m "feat: argv-only subprocess runner with a standing no-shell test"
```

---

### Task 5: Forwarder — socat and ufw lifecycle

**Files:**
- Create: `bot/forwarder.py`
- Test: `tests/test_forwarder.py`, `tests/test_forwarder_integration.py`

**Interfaces:**
- Consumes: `bot.config.Config`, `bot.proc.run`, `bot.proc.Result`.
- Produces:
  - `class Forwarder(config: Config, runner=proc.run, spawn=asyncio.create_subprocess_exec)`
  - `async start(port: int, source: str) -> int` — returns the socat pid; opens the ufw rule first, rolls it back if socat fails to listen.
  - `async stop(pid: int | None, port: int, source: str) -> None` — kills socat, then removes the ufw rule. Safe to call twice.
  - `is_alive(pid: int, port: int) -> bool` — checks `/proc/<pid>/cmdline`, so it works after a bot restart.
  - `async established_count(port: int) -> int`
  - `ForwarderError(RuntimeError)`

- [ ] **Step 1: Write the failing unit test**

`tests/test_forwarder.py`:

```python
from pathlib import Path

import pytest

from bot.config import Config
from bot.forwarder import Forwarder, ForwarderError
from bot.proc import Result


def make_config(**overrides) -> Config:
    base = dict(
        telegram_token="123:ABC",
        telegram_user_id=1,
        vds_public_ip="198.51.100.7",
        pc1_tailnet_ip="100.101.102.103",
        pc1_ssh_user="rdpadmin",
        pc1_ssh_key_path=Path("/tmp/key"),
    )
    return Config(**{**base, **overrides})


class FakeRunner:
    """Records argv and replays queued Results."""

    def __init__(self, results=None):
        self.calls: list[list[str]] = []
        self.results = list(results or [])

    async def __call__(self, argv, timeout=30.0) -> Result:
        self.calls.append(list(argv))
        if self.results:
            return self.results.pop(0)
        return Result(0, "", "")


class FakeProcess:
    def __init__(self, pid=4242, returncode=None):
        self.pid = pid
        self.returncode = returncode

    async def communicate(self):
        return b"", b"socat: bind failed"

    def kill(self):
        self.returncode = -9

    async def wait(self):
        return self.returncode


async def test_start_opens_ufw_before_spawning_socat():
    runner = FakeRunner([
        Result(0, "", ""),                                     # sudo ufw-port open
        Result(0, "LISTEN 0 5 0.0.0.0:40017 0.0.0.0:*\n", ""),  # ss listening probe
    ])
    spawned = []

    async def spawn(*argv, **kwargs):
        spawned.append(list(argv))
        return FakeProcess(pid=4242)

    fwd = Forwarder(make_config(), runner=runner, spawn=spawn)
    pid = await fwd.start(40017, "203.0.113.9/32")

    assert pid == 4242
    assert runner.calls[0] == [
        "/usr/bin/sudo", "-n", "/usr/local/lib/safe-connect/ufw-port",
        "open", "40017", "203.0.113.9/32",
    ]
    assert spawned[0] == [
        "/usr/bin/socat",
        "TCP4-LISTEN:40017,fork,reuseaddr,range=203.0.113.9/32",
        "TCP:100.101.102.103:3389",
    ]


async def test_source_any_omits_the_socat_range_option():
    runner = FakeRunner([Result(0, "", ""), Result(0, "LISTEN 0 5 *:40017 *:*\n", "")])
    spawned = []

    async def spawn(*argv, **kwargs):
        spawned.append(list(argv))
        return FakeProcess()

    await Forwarder(make_config(), runner=runner, spawn=spawn).start(40017, "any")
    assert spawned[0][1] == "TCP4-LISTEN:40017,fork,reuseaddr"


async def test_ufw_rule_is_rolled_back_when_socat_never_listens():
    runner = FakeRunner([
        Result(0, "", ""),   # ufw open succeeds
        Result(0, "", ""),   # ss shows nothing listening
    ])

    async def spawn(*argv, **kwargs):
        return FakeProcess(returncode=1)   # socat exited immediately

    fwd = Forwarder(make_config(), runner=runner, spawn=spawn)
    with pytest.raises(ForwarderError):
        await fwd.start(40017, "203.0.113.9/32")

    assert runner.calls[-1][-3:] == ["close", "40017", "203.0.113.9/32"]


async def test_start_raises_when_ufw_refuses():
    runner = FakeRunner([Result(2, "", "ufw-port: port 22 is outside the permitted range")])

    async def spawn(*argv, **kwargs):
        raise AssertionError("socat must not be spawned when ufw failed")

    with pytest.raises(ForwarderError, match="outside the permitted range"):
        await Forwarder(make_config(), runner=runner, spawn=spawn).start(40017, "any")


async def test_stop_kills_socat_before_closing_ufw():
    """Order matters: the public listener must die first."""
    runner = FakeRunner()
    killed = []
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    fwd._terminate = lambda pid: killed.append(pid)   # noqa: SLF001

    await fwd.stop(4242, 40017, "203.0.113.9/32")

    assert killed == [4242]
    assert runner.calls[0][-3:] == ["close", "40017", "203.0.113.9/32"]


async def test_stop_still_closes_ufw_when_pid_is_unknown():
    runner = FakeRunner()
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    await fwd.stop(None, 40017, "any")
    assert runner.calls[0][-3:] == ["close", "40017", "any"]


async def test_established_count_counts_ss_output_lines():
    runner = FakeRunner([Result(0, "ESTAB 0 0 10.0.0.1:40017 203.0.113.9:51000\n\n", "")])
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    assert await fwd.established_count(40017) == 1
    assert runner.calls[0] == [
        "/usr/bin/ss", "-Htn", "state", "established", "( sport = :40017 )",
    ]


async def test_established_count_raises_when_ss_fails():
    runner = FakeRunner([Result(1, "", "ss: something broke")])
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    with pytest.raises(ForwarderError):
        await fwd.established_count(40017)


def test_is_alive_is_false_for_a_pid_that_does_not_exist():
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    assert fwd.is_alive(999999, 40017) is False
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_forwarder.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.forwarder'`.

- [ ] **Step 3: Implement `bot/forwarder.py`**

```python
from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path

from bot import proc
from bot.config import Config

RDP_PORT = 3389
_LISTEN_POLL_INTERVAL = 0.1
_LISTEN_POLL_ATTEMPTS = 20


class ForwarderError(RuntimeError):
    """The public listener or its firewall rule could not be brought up or down."""


class Forwarder:
    """Owns the per-session public listener and its ufw rule.

    Deliberately holds no session state: the pid comes from persisted state, so
    the forwarder can be driven correctly after a bot restart.
    """

    def __init__(self, config: Config, runner=proc.run, spawn=asyncio.create_subprocess_exec) -> None:
        self._config = config
        self._run = runner
        self._spawn = spawn
        self._processes: dict[int, object] = {}

    async def start(self, port: int, source: str) -> int:
        await self._ufw("open", port, source)
        try:
            return await self._spawn_socat(port, source)
        except Exception:
            await self._ufw("close", port, source)
            raise

    async def stop(self, pid: int | None, port: int, source: str) -> None:
        if pid is not None:
            self._terminate(pid)
            self._processes.pop(pid, None)
        await self._ufw("close", port, source)

    def is_alive(self, pid: int, port: int) -> bool:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False
        return b"socat" in cmdline and f"TCP4-LISTEN:{port}".encode() in cmdline

    async def established_count(self, port: int) -> int:
        result = await self._run(
            [str(self._config.ss_path), "-Htn", "state", "established", f"( sport = :{port} )"]
        )
        if not result.ok:
            raise ForwarderError(f"ss failed: {result.stderr.strip()}")
        return len([line for line in result.stdout.splitlines() if line.strip()])

    # -- internals -------------------------------------------------------

    async def _ufw(self, action: str, port: int, source: str) -> None:
        result = await self._run([
            str(self._config.sudo_path), "-n", str(self._config.ufw_port_helper),
            action, str(port), source,
        ])
        if not result.ok:
            raise ForwarderError(f"ufw-port {action} failed: {result.stderr.strip()}")

    def _socat_argv(self, port: int, source: str) -> list[str]:
        # TCP4-LISTEN, not TCP-LISTEN: socat 1.8.0 refuses an IPv4 `range=` on a
        # dual-stack listener ("syntax error in range ... of unspecified address
        # family"). The forwarded protocol and the ufw rule are both IPv4 anyway.
        listen = f"TCP4-LISTEN:{port},fork,reuseaddr"
        if source != "any":
            listen += f",range={source}"
        return [
            str(self._config.socat_path),
            listen,
            f"TCP:{self._config.pc1_tailnet_ip}:{RDP_PORT}",
        ]

    async def _spawn_socat(self, port: int, source: str) -> int:
        process = await self._spawn(
            *self._socat_argv(port, source),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        for _ in range(_LISTEN_POLL_ATTEMPTS):
            await asyncio.sleep(_LISTEN_POLL_INTERVAL)
            if process.returncode is not None:
                raise ForwarderError(f"socat exited immediately with {process.returncode}")
            if await self._is_listening(port):
                self._processes[process.pid] = process
                return process.pid
        self._terminate(process.pid)
        raise ForwarderError(f"socat did not listen on {port} within 2s")

    async def _is_listening(self, port: int) -> bool:
        result = await self._run(
            [str(self._config.ss_path), "-Hltn", f"( sport = :{port} )"]
        )
        return result.ok and bool(result.stdout.strip())

    def _terminate(self, pid: int) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                return
            except PermissionError:
                raise ForwarderError(f"not permitted to signal pid {pid}")
```

- [ ] **Step 4: Run unit tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_forwarder.py -v'`
Expected: 9 passed.

- [ ] **Step 5: Write the socat integration test**

`tests/test_forwarder_integration.py`:

```python
"""Exercises real socat. Skipped where socat or Linux /proc is unavailable.

Run these on the VDS too, as part of the runbook smoke test.
"""
import asyncio
import shutil
import socket
from pathlib import Path

import pytest

from bot.forwarder import Forwarder
from tests.test_forwarder import make_config

pytestmark = [
    pytest.mark.requires_socat,
    pytest.mark.skipif(shutil.which("socat") is None, reason="socat not installed"),
    pytest.mark.skipif(not Path("/proc").is_dir(), reason="needs Linux /proc"),
]


@pytest.fixture
async def echo_server():
    async def handle(reader, writer):
        writer.write(await reader.read(100))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def local_forwarder(echo_server, monkeypatch):
    """A Forwarder pointed at the echo server, with the ufw call stubbed out."""
    cfg = make_config(pc1_tailnet_ip="127.0.0.1")
    fwd = Forwarder(cfg)

    async def no_ufw(action, port, source):
        return None

    monkeypatch.setattr(fwd, "_ufw", no_ufw)
    monkeypatch.setattr(fwd, "_socat_argv", lambda port, source: [
        "socat",
        f"TCP-LISTEN:{port},fork,reuseaddr" + ("" if source == "any" else f",range={source}"),
        f"TCP:127.0.0.1:{echo_server}",
    ])
    return fwd


async def test_traffic_flows_and_stop_leaves_no_process(local_forwarder):
    port = free_port()
    pid = await local_forwarder.start(port, "any")
    assert local_forwarder.is_alive(pid, port)

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"ping")
    await writer.drain()
    assert await reader.read(4) == b"ping"

    assert await local_forwarder.established_count(port) >= 1
    writer.close()

    await local_forwarder.stop(pid, port, "any")
    await asyncio.sleep(0.2)
    assert not local_forwarder.is_alive(pid, port)


async def test_disallowed_source_is_dropped_by_the_range_option(local_forwarder):
    """range=203.0.113.9/32 must reject a connection arriving from 127.0.0.1."""
    port = free_port()
    pid = await local_forwarder.start(port, "203.0.113.9/32")
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"ping")
        await writer.drain()
        assert await reader.read(4) == b""      # socat closed it without relaying
        writer.close()
    finally:
        await local_forwarder.stop(pid, port, "203.0.113.9/32")


async def test_bind_failure_on_an_occupied_port_raises(local_forwarder):
    from bot.forwarder import ForwarderError

    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        with pytest.raises(ForwarderError):
            await local_forwarder.start(port, "any")
```

- [ ] **Step 6: Run the integration tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_forwarder_integration.py -v'`
Expected: 3 passed. If they are skipped, socat is missing — install it before continuing, as these are the only tests that prove the relay actually relays.

- [ ] **Step 7: Commit**

```bash
git add bot/forwarder.py tests/test_forwarder.py tests/test_forwarder_integration.py
git commit -m "feat: per-session socat listener with ufw rule and rollback"
```

---

### Task 6: PC1 client over SSH

**Files:**
- Create: `bot/pc1.py`
- Test: `tests/test_pc1.py`

**Interfaces:**
- Consumes: `Config`, `proc.run`, `proc.Result`.
- Produces:
  - `class PC1Client(config: Config, runner=proc.run)`
  - `async enable() -> None`, `async disable() -> None`, `async status() -> bool`
  - `async audit(since_epoch: float) -> AuditReport`
  - `async probe_rdp(timeout: float = 5.0) -> bool` — a plain TCP connect from the VDS, no SSH
  - `@dataclass(frozen=True) LogonEvent(time: str, user: str, source_ip: str)`
  - `@dataclass(frozen=True) AuditReport(successes: list[LogonEvent], failures: list[LogonEvent])`
  - `PC1Error(RuntimeError)`

The agent's stdout contract is JSON, so nothing here parses free text.

- [ ] **Step 1: Write the failing test**

`tests/test_pc1.py`:

```python
import json

import pytest

from bot.pc1 import AuditReport, PC1Client, PC1Error
from bot.proc import Result
from tests.test_forwarder import FakeRunner, make_config


def ssh_argv(verb: str) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-i", "/tmp/key",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-o", "IdentitiesOnly=yes",
        "rdpadmin@100.101.102.103",
        verb,
    ]


async def test_enable_sends_only_the_verb():
    runner = FakeRunner([Result(0, json.dumps({"ok": True}), "")])
    await PC1Client(make_config(), runner=runner).enable()
    assert runner.calls[0] == ssh_argv("enable")


async def test_disable_sends_only_the_verb():
    runner = FakeRunner([Result(0, json.dumps({"ok": True}), "")])
    await PC1Client(make_config(), runner=runner).disable()
    assert runner.calls[0] == ssh_argv("disable")


async def test_status_reports_whether_rdp_is_enabled():
    runner = FakeRunner([Result(0, json.dumps({"ok": True, "rdp_enabled": True}), "")])
    assert await PC1Client(make_config(), runner=runner).status() is True


async def test_ssh_failure_raises_pc1_error():
    runner = FakeRunner([Result(255, "", "ssh: connect to host ... No route to host")])
    with pytest.raises(PC1Error, match="No route to host"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_agent_reporting_failure_raises_pc1_error():
    runner = FakeRunner([Result(0, json.dumps({"ok": False, "error": "access denied"}), "")])
    with pytest.raises(PC1Error, match="access denied"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_unparseable_agent_output_raises_pc1_error():
    runner = FakeRunner([Result(0, "not json at all", "")])
    with pytest.raises(PC1Error, match="unparseable"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_audit_parses_logon_events():
    payload = {
        "ok": True,
        "successes": [{"time": "2026-08-04T18:02:11", "user": "rdpuser", "source_ip": "203.0.113.9"}],
        "failures": [{"time": "2026-08-04T18:01:40", "user": "administrator", "source_ip": "203.0.113.9"}],
    }
    runner = FakeRunner([Result(0, json.dumps(payload), "")])
    report = await PC1Client(make_config(), runner=runner).audit(1785000000.0)

    assert isinstance(report, AuditReport)
    assert len(report.successes) == 1 and len(report.failures) == 1
    assert report.successes[0].user == "rdpuser"
    assert report.failures[0].source_ip == "203.0.113.9"
    assert runner.calls[0][-1] == "audit 1785000000"


async def test_probe_rdp_is_false_when_nothing_listens():
    client = PC1Client(make_config(pc1_tailnet_ip="127.0.0.1"), runner=FakeRunner())
    assert await client.probe_rdp(timeout=0.3) is False
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_pc1.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.pc1'`.

- [ ] **Step 3: Implement `bot/pc1.py`**

```python
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from bot import proc
from bot.config import Config

RDP_PORT = 3389


class PC1Error(RuntimeError):
    """PC1 was unreachable, or its agent refused or failed the request."""


@dataclass(frozen=True)
class LogonEvent:
    time: str
    user: str
    source_ip: str


@dataclass(frozen=True)
class AuditReport:
    successes: list[LogonEvent]
    failures: list[LogonEvent]


class PC1Client:
    """Speaks to the forced-command agent on PC1.

    The SSH key is pinned to agent.ps1 on PC1's side, so the strings sent here
    are the complete vocabulary available to this process — and to anyone who
    steals the key.
    """

    def __init__(self, config: Config, runner=proc.run) -> None:
        self._config = config
        self._run = runner

    async def enable(self) -> None:
        await self._call("enable")

    async def disable(self) -> None:
        await self._call("disable")

    async def status(self) -> bool:
        return bool((await self._call("status")).get("rdp_enabled", False))

    async def audit(self, since_epoch: float) -> AuditReport:
        payload = await self._call(f"audit {int(since_epoch)}")
        return AuditReport(
            successes=[LogonEvent(**item) for item in payload.get("successes", [])],
            failures=[LogonEvent(**item) for item in payload.get("failures", [])],
        )

    async def probe_rdp(self, timeout: float = 5.0) -> bool:
        """Confirm 3389 accepts connections over the tailnet before opening a public port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._config.pc1_tailnet_ip, RDP_PORT), timeout
            )
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True

    # -- internals -------------------------------------------------------

    def _ssh_argv(self, remote_command: str) -> list[str]:
        return [
            str(self._config.ssh_path),
            "-i", str(self._config.pc1_ssh_key_path),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            "-o", "IdentitiesOnly=yes",
            f"{self._config.pc1_ssh_user}@{self._config.pc1_tailnet_ip}",
            remote_command,
        ]

    async def _call(self, remote_command: str) -> dict:
        result = await self._run(self._ssh_argv(remote_command))
        if not result.ok:
            raise PC1Error(f"ssh to PC1 failed ({result.returncode}): {result.stderr.strip()}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PC1Error(f"unparseable agent response: {result.stdout[:200]!r}") from exc
        if not payload.get("ok"):
            raise PC1Error(f"agent refused: {payload.get('error', 'no reason given')}")
        return payload
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_pc1.py -v'`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add bot/pc1.py tests/test_pc1.py
git commit -m "feat: PC1 client over an SSH key pinned to a forced command"
```

---

### Task 7: The PC1 agent

**Files:**
- Create: `agent/agent.ps1`
- Test: `tests/test_agent_contract.py`

**Interfaces:**
- Consumes: `SSH_ORIGINAL_COMMAND`, set by sshd on PC1.
- Produces: a single line of JSON on stdout matching what `PC1Client._call` parses: `{"ok": true, ...}` or `{"ok": false, "error": "..."}`. Verbs: `enable`, `disable`, `status`, `audit <epoch>`.

This script is the entire authority granted by the SSH key. Everything it does not implement is something a stolen key cannot do.

- [ ] **Step 1: Write the failing contract test**

`tests/test_agent_contract.py`:

```python
"""Guards the agent's side of the JSON contract without a Windows host.

These assertions are deliberately about the script's text: they catch the
mistakes that would silently break PC1Client — a renamed verb, a dropped
whitelist, a stray Write-Host that corrupts stdout.
"""
import re
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "agent.ps1"


@pytest.fixture(scope="module")
def source() -> str:
    return AGENT.read_text(encoding="utf-8")


def test_every_verb_the_client_sends_is_handled(source):
    for verb in ("enable", "disable", "status", "audit"):
        assert re.search(rf"^\s*'{verb}'", source, re.MULTILINE), f"no branch for {verb}"


def test_unknown_verbs_fall_through_to_a_refusal(source):
    assert "default" in source
    assert "unknown verb" in source


def test_the_command_is_matched_against_a_whitelist_not_invoked(source):
    """A stolen key must not be able to reach Invoke-Expression."""
    assert "Invoke-Expression" not in source
    assert "iex " not in source
    assert "SSH_ORIGINAL_COMMAND" in source


def test_it_creates_a_scoped_rule_and_never_enables_the_builtin_group(source):
    assert "SafeConnect-RDP-In" in source
    assert "Enable-NetFirewallRule" not in source or "RemoteDesktop" not in source


def test_the_firewall_rule_is_scoped_to_the_vds_address(source):
    assert "RemoteAddress" in source


def test_nothing_writes_to_stdout_except_the_json_reply(source):
    """Write-Host would corrupt the response PC1Client parses."""
    assert "Write-Host" not in source
    assert source.count("ConvertTo-Json") >= 1
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_agent_contract.py -v'`
Expected: FAIL — `agent/agent.ps1` does not exist.

- [ ] **Step 3: Implement `agent/agent.ps1`**

```powershell
<#
  The only program the safe-connect SSH key may execute.

  authorized_keys pins it:
    restrict,command="powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\SafeConnect\agent.ps1" ssh-ed25519 AAAA...

  Whoever holds that key can run these four verbs and nothing else. Keep it that
  way: never add a verb that takes a path, a command, or an address.

  Writes exactly one line of JSON to stdout. Never Write-Host.
#>

$ErrorActionPreference = 'Stop'

$ConfigPath = Join-Path $PSScriptRoot 'agent.config.json'
$RuleName   = 'SafeConnect-RDP-In'
$RegPath    = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'

function Write-Reply([hashtable]$Payload) {
    $Payload | ConvertTo-Json -Compress -Depth 5
}

function Get-VdsAddress {
    if (-not (Test-Path $ConfigPath)) { throw "missing $ConfigPath" }
    $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    if (-not $cfg.vds_tailnet_ip) { throw 'vds_tailnet_ip not set in agent.config.json' }
    return $cfg.vds_tailnet_ip
}

function Enable-Rdp {
    Set-ItemProperty -Path $RegPath -Name 'fDenyTSConnections' -Value 0 -Type DWord
    $vds = Get-VdsAddress
    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 3389 -RemoteAddress $vds -Profile Any -Enabled True | Out-Null
    } else {
        Set-NetFirewallRule -DisplayName $RuleName -RemoteAddress $vds -Enabled True | Out-Null
    }
}

function Disable-Rdp {
    Set-ItemProperty -Path $RegPath -Name 'fDenyTSConnections' -Value 1 -Type DWord
    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Set-NetFirewallRule -DisplayName $RuleName -Enabled False | Out-Null
    }
}

function Get-RdpEnabled {
    $deny = (Get-ItemProperty -Path $RegPath -Name 'fDenyTSConnections').fDenyTSConnections
    $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    return ($deny -eq 0) -and ($null -ne $rule) -and ($rule.Enabled -eq 'True')
}

function Get-LogonEvents([datetime]$Since) {
    # 4624 = successful logon, 4625 = failed. LogonType 10 is RemoteInteractive (RDP);
    # 3 appears for the network leg of some NLA flows, so both are collected.
    $successes = @()
    $failures  = @()
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4624, 4625; StartTime = $Since
    } -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $xml  = [xml]$event.ToXml()
        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
        if ($data['LogonType'] -notin @('3', '10')) { continue }
        $record = @{
            time      = $event.TimeCreated.ToString('s')
            user      = [string]$data['TargetUserName']
            source_ip = [string]$data['IpAddress']
        }
        if ($event.Id -eq 4624) { $successes += $record } else { $failures += $record }
    }
    return @{ successes = $successes; failures = $failures }
}

try {
    $raw = $env:SSH_ORIGINAL_COMMAND
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'no command supplied' }

    $parts = $raw.Trim() -split '\s+'
    $verb  = $parts[0]

    switch ($verb) {
        'enable' {
            Enable-Rdp
            Write-Reply @{ ok = $true }
        }
        'disable' {
            Disable-Rdp
            Write-Reply @{ ok = $true }
        }
        'status' {
            Write-Reply @{ ok = $true; rdp_enabled = (Get-RdpEnabled) }
        }
        'audit' {
            if ($parts.Count -ne 2 -or $parts[1] -notmatch '^[0-9]{1,12}$') {
                throw 'audit requires a single epoch-seconds argument'
            }
            $since  = [datetimeoffset]::FromUnixTimeSeconds([int64]$parts[1]).LocalDateTime
            $events = Get-LogonEvents -Since $since
            Write-Reply @{ ok = $true; successes = $events.successes; failures = $events.failures }
        }
        default {
            throw "unknown verb: $verb"
        }
    }
} catch {
    Write-Reply @{ ok = $false; error = "$($_.Exception.Message)" }
    exit 0   # the transport succeeded; the payload carries the failure
}
```

- [ ] **Step 4: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_agent_contract.py -v'`
Expected: 6 passed.

- [ ] **Step 5: Verify the script parses on this Windows machine**

Run: `powershell -NoProfile -Command "$null = [System.Management.Automation.Language.Parser]::ParseFile('C:\projects\safe-connect\agent\agent.ps1', [ref]$null, [ref]$e); if ($e) { $e; exit 1 } else { 'parse ok' }"`
Expected: `parse ok`. This catches syntax errors without needing PC1.

- [ ] **Step 6: Commit**

```bash
git add agent/agent.ps1 tests/test_agent_contract.py
git commit -m "feat: PC1 agent exposing exactly four verbs over a forced command"
```

---

### Task 8: Session state — persistence and transitions

**Files:**
- Create: `bot/session.py`
- Test: `tests/test_session_open.py`, `tests/test_session_close.py`, `tests/conftest.py`

**Interfaces:**
- Consumes: `Config`, `Forwarder`, `PC1Client`, `PC1Error`, `ForwarderError`.
- Produces:
  - `class State(str, Enum)` with `CLOSED`, `OPENING`, `OPEN`, `CLOSING`
  - `@dataclass SessionState` — fields `state`, `port`, `source`, `socat_pid`, `opened_at`, `last_connection_at`, `saw_connection`, `hard_cap_warned`
  - `class SessionManager(config, forwarder, pc1, notifier, clock=SystemClock(), rng=random.Random())`
  - `async open(source: str) -> str`, `async close(reason: str) -> str`, `def describe() -> str`
  - `class FakeClock` is defined in `tests/conftest.py`, not in `bot/`.

Timers and reconciliation land in Task 9, on top of this.

- [ ] **Step 1: Write the shared fixtures**

`tests/conftest.py`:

```python
import pytest

from bot.forwarder import ForwarderError
from bot.pc1 import AuditReport, PC1Error
from tests.test_forwarder import make_config


class FakeClock:
    def __init__(self, start: float = 1_785_000_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeForwarder:
    def __init__(self) -> None:
        self.started: list[tuple[int, str]] = []
        self.stopped: list[tuple[int | None, int, str]] = []
        self.alive = True
        self.connections = 0
        self.start_failures = 0
        self.next_pid = 4242

    async def start(self, port: int, source: str) -> int:
        if self.start_failures > 0:
            self.start_failures -= 1
            raise ForwarderError(f"could not bind {port}")
        self.started.append((port, source))
        return self.next_pid

    async def stop(self, pid, port, source) -> None:
        self.stopped.append((pid, port, source))
        self.alive = False

    def is_alive(self, pid, port) -> bool:
        return self.alive

    async def established_count(self, port) -> int:
        return self.connections


class FakePC1:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.enable_error: Exception | None = None
        self.disable_error: Exception | None = None
        self.rdp_reachable = True
        self.report = AuditReport(successes=[], failures=[])

    async def enable(self) -> None:
        self.calls.append("enable")
        if self.enable_error:
            raise self.enable_error

    async def disable(self) -> None:
        self.calls.append("disable")
        if self.disable_error:
            raise self.disable_error

    async def probe_rdp(self, timeout: float = 5.0) -> bool:
        self.calls.append("probe")
        return self.rdp_reachable

    async def audit(self, since_epoch: float) -> AuditReport:
        self.calls.append("audit")
        return self.report


class FakeNotifier:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, text: str) -> None:
        self.sent.append(text)


@pytest.fixture
def parts(tmp_path):
    """Everything a SessionManager needs, with a state file under tmp_path."""
    return {
        "config": make_config(state_path=tmp_path / "state.json"),
        "forwarder": FakeForwarder(),
        "pc1": FakePC1(),
        "notifier": FakeNotifier(),
        "clock": FakeClock(),
    }


@pytest.fixture
def manager(parts):
    from bot.session import SessionManager

    return SessionManager(**parts)
```

- [ ] **Step 2: Write the failing open-path tests**

`tests/test_session_open.py`:

```python
import json

import pytest

from bot.pc1 import PC1Error
from bot.session import State


async def test_open_prepares_pc1_before_any_public_port_exists(manager, parts):
    await manager.open("203.0.113.9/32")

    assert parts["pc1"].calls[:2] == ["enable", "probe"]
    assert parts["forwarder"].started, "forwarder should have started"
    assert manager.state.state is State.OPEN


async def test_open_reports_the_address_to_connect_to(manager, parts):
    message = await manager.open("203.0.113.9/32")
    port = parts["forwarder"].started[0][0]
    assert f"198.51.100.7:{port}" in message


async def test_chosen_port_is_inside_the_configured_range(manager, parts):
    await manager.open("any")
    port = parts["forwarder"].started[0][0]
    assert 40000 <= port <= 40100


async def test_unreachable_pc1_leaves_the_session_closed(manager, parts):
    parts["pc1"].enable_error = PC1Error("No route to host")

    message = await manager.open("203.0.113.9/32")

    assert manager.state.state is State.CLOSED
    assert parts["forwarder"].started == []
    assert "unreachable" in message.lower()


async def test_failed_rdp_probe_rolls_pc1_back(manager, parts):
    parts["pc1"].rdp_reachable = False

    message = await manager.open("203.0.113.9/32")

    assert "disable" in parts["pc1"].calls, "PC1 must be rolled back"
    assert parts["forwarder"].started == []
    assert manager.state.state is State.CLOSED
    assert "3389" in message


async def test_bind_failures_are_retried_with_a_new_port(manager, parts):
    parts["forwarder"].start_failures = 2

    await manager.open("any")

    assert manager.state.state is State.OPEN
    assert len(parts["forwarder"].started) == 1


async def test_giving_up_after_three_bind_failures_rolls_pc1_back(manager, parts):
    parts["forwarder"].start_failures = 3

    message = await manager.open("any")

    assert manager.state.state is State.CLOSED
    assert "disable" in parts["pc1"].calls
    assert "port" in message.lower()


async def test_opening_twice_is_refused_without_disturbing_the_session(manager, parts):
    await manager.open("203.0.113.9/32")
    before = manager.state.port

    message = await manager.open("198.51.100.20/32")

    assert manager.state.port == before
    assert len(parts["forwarder"].started) == 1
    assert "already open" in message.lower()


async def test_open_state_is_persisted_to_disk(manager, parts):
    await manager.open("203.0.113.9/32")

    saved = json.loads(parts["config"].state_path.read_text())
    assert saved["state"] == "open"
    assert saved["source"] == "203.0.113.9/32"
    assert saved["socat_pid"] == 4242
```

- [ ] **Step 3: Write the failing close-path tests**

`tests/test_session_close.py`:

```python
from bot.pc1 import AuditReport, LogonEvent, PC1Error
from bot.session import State


async def test_close_kills_the_forwarder_then_disables_pc1(manager, parts):
    await manager.open("203.0.113.9/32")
    parts["pc1"].calls.clear()

    await manager.close("operator request")

    assert parts["forwarder"].stopped, "forwarder must be stopped"
    assert parts["pc1"].calls[0] in ("disable", "audit")
    assert "disable" in parts["pc1"].calls
    assert manager.state.state is State.CLOSED


async def test_close_still_shuts_the_port_when_pc1_cleanup_fails(manager, parts):
    await manager.open("203.0.113.9/32")
    parts["pc1"].disable_error = PC1Error("agent refused")

    message = await manager.close("operator request")

    assert parts["forwarder"].stopped, "the public port must close regardless"
    assert manager.state.state is State.CLOSED
    assert "FAILED" in message


async def test_close_reports_the_logon_audit(manager, parts):
    parts["pc1"].report = AuditReport(
        successes=[LogonEvent(time="2026-08-04T18:02:11", user="rdpuser", source_ip="203.0.113.9")],
        failures=[],
    )
    await manager.open("203.0.113.9/32")

    message = await manager.close("operator request")

    assert "1 success" in message
    assert "0 failures" in message
    assert "rdpuser" in message


async def test_closing_an_already_closed_session_is_harmless(manager, parts):
    message = await manager.close("operator request")
    assert parts["forwarder"].stopped == []
    assert "not open" in message.lower()


async def test_close_clears_the_persisted_state(manager, parts):
    await manager.open("203.0.113.9/32")
    await manager.close("operator request")

    import json
    saved = json.loads(parts["config"].state_path.read_text())
    assert saved["state"] == "closed"
    assert saved["port"] is None
    assert saved["socat_pid"] is None
```

- [ ] **Step 4: Run both files and confirm they fail**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_session_open.py tests/test_session_close.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.session'`.

- [ ] **Step 5: Implement `bot/session.py`**

```python
from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Protocol

from bot.config import Config
from bot.forwarder import ForwarderError
from bot.pc1 import AuditReport, PC1Error

log = logging.getLogger(__name__)

BIND_ATTEMPTS = 3


class State(str, Enum):
    CLOSED = "closed"
    OPENING = "opening"
    OPEN = "open"
    CLOSING = "closing"


class Clock(Protocol):
    def now(self) -> float: ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class Notifier(Protocol):
    async def send(self, text: str) -> None: ...


@dataclass
class SessionState:
    state: State = State.CLOSED
    port: int | None = None
    source: str | None = None
    socat_pid: int | None = None
    opened_at: float | None = None
    last_connection_at: float | None = None
    saw_connection: bool = False
    hard_cap_warned: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "SessionState":
        data = dict(data)
        data["state"] = State(data.get("state", State.CLOSED.value))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


class SessionManager:
    """Owns the single session's lifecycle.

    Ordering is the safety property here: PC1 is prepared before a public port
    exists, and the public port dies before PC1 cleanup is attempted.
    """

    def __init__(self, config: Config, forwarder, pc1, notifier,
                 clock: Clock | None = None, rng: random.Random | None = None) -> None:
        self._config = config
        self._forwarder = forwarder
        self._pc1 = pc1
        self._notifier = notifier
        self._clock = clock or SystemClock()
        self._rng = rng or random.Random()
        self.state = self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> SessionState:
        path = self._config.state_path
        if not path.exists():
            return SessionState()
        try:
            return SessionState.from_dict(json.loads(path.read_text()))
        except (OSError, ValueError):
            log.warning("state file unreadable, assuming closed", exc_info=True)
            return SessionState()

    def _save(self) -> None:
        path = self._config.state_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state.to_dict(), indent=2))
        tmp.replace(path)

    # -- opening ---------------------------------------------------------

    async def open(self, source: str) -> str:
        if self.state.state is not State.CLOSED:
            return (f"Session is already {self.state.state.value} "
                    f"on port {self.state.port} for {self.state.source}. Use /rdp_off first.")

        self.state = SessionState(state=State.OPENING)
        self._save()

        try:
            await self._pc1.enable()
        except PC1Error as exc:
            log.warning("enabling RDP on PC1 failed: %s", exc)
            self._reset()
            return f"PC1 unreachable — is it powered on and on the tailnet?\n\n`{exc}`"

        if not await self._pc1.probe_rdp():
            log.warning("RDP probe failed after enable")
            await self._rollback_pc1()
            self._reset()
            return "RDP was enabled on PC1 but port 3389 did not answer over the tailnet. Nothing was opened."

        port, pid = await self._start_forwarder(source)
        if port is None:
            await self._rollback_pc1()
            self._reset()
            return "Could not open a public port after three attempts. Nothing was opened."

        now = self._clock.now()
        self.state = SessionState(
            state=State.OPEN, port=port, source=source, socat_pid=pid, opened_at=now
        )
        self._save()

        log.info("session open on %s for %s", port, source)
        return (f"RDP open at `{self._config.vds_public_ip}:{port}`\n"
                f"Source: `{source}`\n"
                f"Closes after {self._config.idle_timeout_seconds // 60} min idle, "
                f"or {self._config.hard_cap_seconds // 3600} h maximum.")

    async def _start_forwarder(self, source: str) -> tuple[int | None, int | None]:
        for _ in range(BIND_ATTEMPTS):
            port = self._rng.randint(self._config.port_range_start, self._config.port_range_end)
            try:
                return port, await self._forwarder.start(port, source)
            except ForwarderError as exc:
                log.warning("could not start forwarder on %s: %s", port, exc)
        return None, None

    async def _rollback_pc1(self) -> None:
        try:
            await self._pc1.disable()
        except PC1Error as exc:
            log.error("rollback of PC1 failed: %s", exc)

    def _reset(self) -> None:
        self.state = SessionState()
        self._save()

    # -- closing ---------------------------------------------------------

    async def close(self, reason: str) -> str:
        if self.state.state is State.CLOSED:
            return "Session is not open."

        opened_at = self.state.opened_at or self._clock.now()
        port, source, pid = self.state.port, self.state.source, self.state.socat_pid
        self.state.state = State.CLOSING
        self._save()

        if port is not None and source is not None:
            try:
                await self._forwarder.stop(pid, port, source)
            except ForwarderError as exc:
                log.error("stopping the forwarder failed: %s", exc)

        pc1_ok = True
        try:
            await self._pc1.disable()
        except PC1Error as exc:
            pc1_ok = False
            log.error("disabling RDP on PC1 failed: %s", exc)

        audit_line = await self._audit_line(opened_at)
        self._reset()

        elapsed = int((self._clock.now() - opened_at) // 60)
        header = f"Session closed after {elapsed}m ({reason})."
        if not pc1_ok:
            header = (f"Public port closed after {elapsed}m ({reason}).\n"
                      f"PC1 cleanup FAILED — RDP may still be enabled on PC1. "
                      f"Retry with /rdp_off.")
        return f"{header}\n{audit_line}"

    async def _audit_line(self, since: float) -> str:
        try:
            report: AuditReport = await self._pc1.audit(since)
        except PC1Error as exc:
            log.warning("audit fetch failed: %s", exc)
            return "Logon audit unavailable."
        detail = ""
        if report.successes:
            who = ", ".join(f"{e.user} from {e.source_ip}" for e in report.successes)
            detail = f" ({who})"
        return (f"Logons: {len(report.successes)} success"
                f"{'es' if len(report.successes) != 1 else ''}{detail}, "
                f"{len(report.failures)} failures.")

    # -- reporting -------------------------------------------------------

    def describe(self) -> str:
        if self.state.state is State.CLOSED:
            return "Closed. No public port, RDP disabled on PC1."
        if self.state.state is not State.OPEN:
            return f"{self.state.state.value.capitalize()}…"
        now = self._clock.now()
        opened_at = self.state.opened_at or now
        hard_left = int((self._config.hard_cap_seconds - (now - opened_at)) // 60)
        if self.state.saw_connection and self.state.last_connection_at:
            idle_left = int(
                (self._config.idle_timeout_seconds - (now - self.state.last_connection_at)) // 60
            )
            idle_line = f"Idle timeout in {max(idle_left, 0)}m."
        else:
            grace_left = int((self._config.connect_grace_seconds - (now - opened_at)) // 60)
            idle_line = f"No connection yet; closes in {max(grace_left, 0)}m if none arrives."
        return (f"Open at `{self._config.vds_public_ip}:{self.state.port}`\n"
                f"Source: `{self.state.source}`\n"
                f"{idle_line}\nHard cap in {max(hard_left, 0)}m.")
```

- [ ] **Step 6: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_session_open.py tests/test_session_close.py -v'`
Expected: 14 passed.

- [ ] **Step 7: Commit**

```bash
git add bot/session.py tests/conftest.py tests/test_session_open.py tests/test_session_close.py
git commit -m "feat: session state machine with ordered setup and fail-forward teardown"
```

---

### Task 9: Timers and crash reconciliation

**Files:**
- Modify: `bot/session.py` (add `tick` and `reconcile` to `SessionManager`)
- Test: `tests/test_session_timers.py`, `tests/test_session_reconcile.py`

**Interfaces:**
- Consumes: everything from Task 8.
- Produces: `async SessionManager.tick() -> None` (called every `poll_interval_seconds`) and `async SessionManager.reconcile() -> None` (called once at startup). Both send messages through the notifier rather than returning text.

- [ ] **Step 1: Write the failing timer tests**

`tests/test_session_timers.py`:

```python
from bot.session import State


async def test_tick_does_nothing_while_closed(manager, parts):
    await manager.tick()
    assert parts["forwarder"].stopped == []


async def test_an_observed_connection_is_recorded(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1

    await manager.tick()

    assert manager.state.saw_connection is True
    assert manager.state.last_connection_at == parts["clock"].now()


async def test_no_connection_within_the_grace_period_closes_the_session(manager, parts):
    await manager.open("any")

    parts["clock"].advance(299)
    await manager.tick()
    assert manager.state.state is State.OPEN, "must not close before the grace period ends"

    parts["clock"].advance(2)
    await manager.tick()
    assert manager.state.state is State.CLOSED
    assert any("no connection" in m.lower() for m in parts["notifier"].sent)


async def test_grace_period_does_not_close_a_session_that_connected(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1
    await manager.tick()

    parts["clock"].advance(400)          # past the grace period
    await manager.tick()

    assert manager.state.state is State.OPEN


async def test_idle_timeout_closes_after_the_last_connection_drops(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1
    await manager.tick()

    parts["forwarder"].connections = 0
    parts["clock"].advance(599)
    await manager.tick()
    assert manager.state.state is State.OPEN

    parts["clock"].advance(2)
    await manager.tick()
    assert manager.state.state is State.CLOSED
    assert any("idle" in m.lower() for m in parts["notifier"].sent)


async def test_an_active_connection_holds_the_session_open_indefinitely(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1

    for _ in range(100):
        parts["clock"].advance(60)
        await manager.tick()

    assert manager.state.state is State.OPEN


async def test_hard_cap_warns_first_then_closes_even_while_connected(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1
    await manager.tick()

    parts["clock"].advance(28800 - 300)
    await manager.tick()
    assert manager.state.state is State.OPEN
    assert any("5 min" in m for m in parts["notifier"].sent)

    parts["clock"].advance(301)
    await manager.tick()
    assert manager.state.state is State.CLOSED
    assert any("maximum" in m.lower() for m in parts["notifier"].sent)


async def test_the_hard_cap_warning_is_sent_only_once(manager, parts):
    await manager.open("any")
    parts["forwarder"].connections = 1
    parts["clock"].advance(28800 - 300)

    await manager.tick()
    await manager.tick()
    await manager.tick()

    assert len([m for m in parts["notifier"].sent if "5 min" in m]) == 1


async def test_a_dead_forwarder_closes_the_session_and_reports(manager, parts):
    await manager.open("any")
    parts["forwarder"].alive = False

    await manager.tick()

    assert manager.state.state is State.CLOSED
    assert any("unexpectedly" in m.lower() for m in parts["notifier"].sent)
```

- [ ] **Step 2: Write the failing reconciliation tests**

`tests/test_session_reconcile.py`:

```python
import json

from bot.session import SessionManager, State


def write_state(parts, **fields) -> None:
    base = {
        "state": "open", "port": 40017, "source": "203.0.113.9/32",
        "socat_pid": 4242, "opened_at": parts["clock"].now(),
        "last_connection_at": None, "saw_connection": False, "hard_cap_warned": False,
    }
    parts["config"].state_path.parent.mkdir(parents=True, exist_ok=True)
    parts["config"].state_path.write_text(json.dumps({**base, **fields}))


async def test_a_surviving_forwarder_is_adopted(parts):
    write_state(parts)
    parts["forwarder"].alive = True
    manager = SessionManager(**parts)

    await manager.reconcile()

    assert manager.state.state is State.OPEN
    assert parts["forwarder"].stopped == []
    assert any("resumed" in m.lower() for m in parts["notifier"].sent)


async def test_a_vanished_forwarder_triggers_a_full_teardown(parts):
    write_state(parts)
    parts["forwarder"].alive = False
    manager = SessionManager(**parts)

    await manager.reconcile()

    assert manager.state.state is State.CLOSED
    assert "disable" in parts["pc1"].calls
    assert parts["forwarder"].stopped, "the ufw rule must still be removed"


async def test_a_session_stuck_in_opening_is_torn_down(parts):
    write_state(parts, state="opening", port=None, socat_pid=None)
    manager = SessionManager(**parts)

    await manager.reconcile()

    assert manager.state.state is State.CLOSED
    assert "disable" in parts["pc1"].calls


async def test_a_closed_state_file_needs_no_action(parts):
    write_state(parts, state="closed", port=None, source=None, socat_pid=None)
    manager = SessionManager(**parts)

    await manager.reconcile()

    assert manager.state.state is State.CLOSED
    assert parts["pc1"].calls == []
    assert parts["notifier"].sent == []


async def test_a_corrupt_state_file_is_treated_as_closed(parts):
    parts["config"].state_path.parent.mkdir(parents=True, exist_ok=True)
    parts["config"].state_path.write_text("{ this is not json")

    manager = SessionManager(**parts)

    assert manager.state.state is State.CLOSED
```

- [ ] **Step 3: Run both files and confirm they fail**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_session_timers.py tests/test_session_reconcile.py -v'`
Expected: FAIL, `AttributeError: 'SessionManager' object has no attribute 'tick'`.

- [ ] **Step 4: Add `tick` and `reconcile` to `SessionManager`**

Append these methods to the class in `bot/session.py`:

```python
    # -- timers ----------------------------------------------------------

    async def tick(self) -> None:
        """Advance the session's timers. Called every poll_interval_seconds.

        Runs on the event loop independently of Telegram, so a Telegram outage
        delays notifications but never the teardown itself.
        """
        if self.state.state is not State.OPEN:
            return

        port = self.state.port
        pid = self.state.socat_pid
        if port is None:
            return

        if pid is not None and not self._forwarder.is_alive(pid, port):
            log.error("socat died unexpectedly on port %s", port)
            await self._close_and_notify("the forwarder exited unexpectedly")
            return

        try:
            if await self._forwarder.established_count(port) > 0:
                self.state.saw_connection = True
                self.state.last_connection_at = self._clock.now()
                self._save()
        except ForwarderError as exc:
            log.warning("could not sample connections: %s", exc)

        now = self._clock.now()
        opened_at = self.state.opened_at or now
        age = now - opened_at

        if age >= self._config.hard_cap_seconds:
            await self._close_and_notify(
                f"maximum session length of {self._config.hard_cap_seconds // 3600}h reached"
            )
            return

        warn_at = self._config.hard_cap_seconds - self._config.hard_cap_warning_seconds
        if age >= warn_at and not self.state.hard_cap_warned:
            self.state.hard_cap_warned = True
            self._save()
            await self._notifier.send(
                f"Heads up: this session hits its maximum length in "
                f"{self._config.hard_cap_warning_seconds // 60} min and will close."
            )

        if not self.state.saw_connection:
            if age >= self._config.connect_grace_seconds:
                await self._close_and_notify(
                    f"no connection arrived within "
                    f"{self._config.connect_grace_seconds // 60} min"
                )
            return

        last = self.state.last_connection_at or opened_at
        if now - last >= self._config.idle_timeout_seconds:
            await self._close_and_notify(
                f"idle for {self._config.idle_timeout_seconds // 60} min"
            )

    async def _close_and_notify(self, reason: str) -> None:
        await self._notifier.send(await self.close(reason))

    # -- startup ---------------------------------------------------------

    async def reconcile(self) -> None:
        """Make reality and the state file agree after a restart.

        The file is evidence, not truth: an OPEN record whose socat is gone means
        a half-open session, which is torn down rather than trusted.
        """
        if self.state.state is State.CLOSED:
            return

        port, pid = self.state.port, self.state.socat_pid
        if (self.state.state is State.OPEN and port is not None
                and pid is not None and self._forwarder.is_alive(pid, port)):
            log.info("adopted a live session on port %s", port)
            await self._notifier.send(
                f"Bot restarted; resumed tracking the open session on "
                f"`{self._config.vds_public_ip}:{port}`."
            )
            return

        log.warning("stale %s state on startup, tearing down", self.state.state.value)
        await self._close_and_notify("cleanup after a bot restart")
```

- [ ] **Step 5: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/ -v'`
Expected: all tests pass (roughly 73).

- [ ] **Step 6: Commit**

```bash
git add bot/session.py tests/test_session_timers.py tests/test_session_reconcile.py
git commit -m "feat: idle, grace and hard-cap timers plus crash reconciliation"
```

---

### Task 10: Telegram wiring

**Files:**
- Create: `bot/notify.py`, `bot/main.py`
- Test: `tests/test_handlers.py`

**Interfaces:**
- Consumes: `Config`, `SessionManager`, `parse_source`, `InvalidSource`.
- Produces:
  - `class TelegramNotifier(bot: Bot, chat_id: int)` implementing `async send(text: str) -> None`
  - `class AuthMiddleware(allowed_user_id: int)` — drops every update from another sender, logging one line
  - `async handle_rdp_on(message, manager) -> str`, `async handle_rdp_off(message, manager) -> str`, `def handle_status(manager) -> str`, `def handle_help() -> str` — pure enough to test without a Telegram server
  - `async main() -> None`

- [ ] **Step 1: Write the failing test**

`tests/test_handlers.py`:

```python
import logging
from dataclasses import dataclass

import pytest

from bot.main import AuthMiddleware, handle_help, handle_rdp_off, handle_rdp_on, handle_status


@dataclass
class FakeUser:
    id: int


@dataclass
class FakeMessage:
    text: str
    from_user: FakeUser


async def test_rdp_on_opens_a_session_for_a_valid_address(manager, parts):
    reply = await handle_rdp_on("/rdp_on 203.0.113.9", manager)
    assert parts["forwarder"].started[0][1] == "203.0.113.9/32"
    assert "198.51.100.7" in reply


async def test_rdp_on_without_an_argument_explains_the_usage(manager, parts):
    reply = await handle_rdp_on("/rdp_on", manager)
    assert parts["forwarder"].started == []
    assert "/rdp_on" in reply and "any" in reply


async def test_rdp_on_rejects_a_hostile_argument_before_reaching_the_session(manager, parts):
    reply = await handle_rdp_on("/rdp_on 203.0.113.9; id", manager)
    assert parts["forwarder"].started == []
    assert parts["pc1"].calls == []
    assert "not" in reply.lower()


async def test_rdp_on_any_is_accepted_and_warned_about(manager, parts):
    reply = await handle_rdp_on("/rdp_on any", manager)
    assert parts["forwarder"].started[0][1] == "any"
    assert "any" in reply


async def test_rdp_off_closes_an_open_session(manager, parts):
    await handle_rdp_on("/rdp_on 203.0.113.9", manager)
    reply = await handle_rdp_off(manager)
    assert parts["forwarder"].stopped
    assert "closed" in reply.lower()


async def test_status_reports_closed_when_nothing_is_open(manager):
    assert "closed" in handle_status(manager).lower()


async def test_status_reports_the_port_when_open(manager, parts):
    await handle_rdp_on("/rdp_on 203.0.113.9", manager)
    port = parts["forwarder"].started[0][0]
    assert str(port) in handle_status(manager)


def test_help_lists_every_command():
    text = handle_help()
    for command in ("/rdp_on", "/rdp_off", "/status", "/help"):
        assert command in text


async def test_the_allowed_user_passes_through_the_middleware():
    middleware = AuthMiddleware(allowed_user_id=42)
    seen = []

    async def handler(event, data):
        seen.append(event)
        return "handled"

    message = FakeMessage(text="/status", from_user=FakeUser(id=42))
    assert await middleware(handler, message, {}) == "handled"
    assert seen == [message]


async def test_an_unknown_user_gets_no_reply_and_one_log_line(caplog):
    middleware = AuthMiddleware(allowed_user_id=42)

    async def handler(event, data):
        raise AssertionError("the handler must never run for an unknown user")

    message = FakeMessage(text="/rdp_on 203.0.113.9", from_user=FakeUser(id=9999))
    with caplog.at_level(logging.WARNING):
        assert await middleware(handler, message, {}) is None

    assert len([r for r in caplog.records if "9999" in r.getMessage()]) == 1
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/test_handlers.py -v'`
Expected: FAIL, `ModuleNotFoundError: No module named 'bot.main'`.

- [ ] **Step 3: Implement `bot/notify.py`**

```python
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class TelegramNotifier:
    """Sends unsolicited messages — timer expiries, warnings, restart notices.

    Failures are logged and swallowed: a Telegram outage must never stop a
    teardown that is already in progress.
    """

    def __init__(self, bot, chat_id: int) -> None:
        self._bot = bot
        self._chat_id = chat_id

    async def send(self, text: str) -> None:
        try:
            await self._bot.send_message(self._chat_id, text, parse_mode="Markdown")
        except Exception:
            log.exception("could not deliver a notification to Telegram")
```

- [ ] **Step 4: Implement `bot/main.py`**

```python
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message

from bot.config import load_config
from bot.forwarder import Forwarder
from bot.notify import TelegramNotifier
from bot.pc1 import PC1Client
from bot.session import SessionManager
from bot.validation import InvalidSource, parse_source

log = logging.getLogger(__name__)

CONFIG_PATH = Path(os.environ.get("SAFE_CONNECT_CONFIG", "/etc/safe-connect/config.toml"))

USAGE = (
    "Usage: `/rdp_on <your public IP>`\n"
    "For example `/rdp_on 203.0.113.9`.\n\n"
    "`/rdp_on any` opens the port to every source address. "
    "That drops the IP restriction entirely — only the random port and your "
    "Windows password stand between the internet and PC1."
)


class AuthMiddleware:
    """Drops every update that did not come from the configured operator.

    There is no refusal message on purpose: replying would confirm the bot
    exists to anyone who stumbles across it.
    """

    def __init__(self, allowed_user_id: int) -> None:
        self._allowed = allowed_user_id

    async def __call__(self, handler, event, data):
        user = getattr(event, "from_user", None)
        if user is None or user.id != self._allowed:
            log.warning(
                "ignored a message from unauthorised Telegram user %s",
                getattr(user, "id", "unknown"),
            )
            return None
        return await handler(event, data)


async def handle_rdp_on(text: str, manager: SessionManager) -> str:
    parts = text.split()
    if len(parts) != 2:
        return USAGE
    try:
        source = parse_source(parts[1])
    except InvalidSource as exc:
        return f"That is not a usable source address: {exc}\n\n{USAGE}"
    reply = await manager.open(source)
    if source == "any":
        reply += "\n\nOpened to *any* source address."
    return reply


async def handle_rdp_off(manager: SessionManager) -> str:
    return await manager.close("operator request")


def handle_status(manager: SessionManager) -> str:
    return manager.describe()


def handle_help() -> str:
    return (
        "*Safe Connect*\n"
        "`/rdp_on <ip>` — enable RDP on PC1 and open a port for that address\n"
        "`/rdp_off` — close the port and disable RDP\n"
        "`/status` — current state and time remaining\n"
        "`/help` — this message"
    )


async def _tick_loop(manager: SessionManager, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await manager.tick()
        except Exception:
            log.exception("tick failed; the loop continues")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    config = load_config(CONFIG_PATH)

    bot = Bot(token=config.telegram_token.get_secret_value())
    notifier = TelegramNotifier(bot, config.telegram_user_id)
    manager = SessionManager(
        config=config,
        forwarder=Forwarder(config),
        pc1=PC1Client(config),
        notifier=notifier,
    )

    dispatcher = Dispatcher()
    dispatcher.message.middleware(AuthMiddleware(config.telegram_user_id))

    @dispatcher.message(Command("rdp_on"))
    async def _on(message: Message) -> None:
        await message.answer(await handle_rdp_on(message.text or "", manager), parse_mode="Markdown")

    @dispatcher.message(Command("rdp_off"))
    async def _off(message: Message) -> None:
        await message.answer(await handle_rdp_off(manager), parse_mode="Markdown")

    @dispatcher.message(Command("status"))
    async def _status(message: Message) -> None:
        await message.answer(handle_status(manager), parse_mode="Markdown")

    @dispatcher.message(Command("help", "start"))
    async def _help(message: Message) -> None:
        await message.answer(handle_help(), parse_mode="Markdown")

    await manager.reconcile()
    asyncio.create_task(_tick_loop(manager, config.poll_interval_seconds))
    log.info("safe-connect started")
    await dispatcher.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 5: Run tests, confirm they pass**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/ -v'`
Expected: all pass (roughly 83).

- [ ] **Step 6: Commit**

```bash
git add bot/notify.py bot/main.py tests/test_handlers.py
git commit -m "feat: Telegram handlers behind an allow-list middleware"
```

---

### Task 11: VDS installer, systemd unit, sudoers

**Files:**
- Create: `deploy/install-vds.sh`, `deploy/safe-connect.service`, `deploy/sudoers.safe-connect`

**Interfaces:**
- Consumes: `deploy/ufw-port`, `deploy/config.example.toml`, the `bot/` package.
- Produces: a running `safe-connect.service` on the VDS, a `safeconnect` system user, `/etc/safe-connect/{config.toml,env}`, `/var/lib/safe-connect/`, and `/usr/local/lib/safe-connect/ufw-port`.

Note the deliberate absence of `NoNewPrivileges=yes` — it is incompatible with the sudo grant chosen in the spec, and this is recorded in the unit file so nobody "fixes" it later and breaks the forwarder.

- [ ] **Step 1: Write `deploy/safe-connect.service`**

```ini
[Unit]
Description=Safe Connect — on-demand RDP access broker
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=safeconnect
Group=safeconnect
WorkingDirectory=/opt/safe-connect
Environment=SAFE_CONNECT_CONFIG=/etc/safe-connect/config.toml
EnvironmentFile=/etc/safe-connect/env
ExecStart=/opt/safe-connect/.venv/bin/python -m bot.main
Restart=always
RestartSec=5

# NoNewPrivileges is deliberately absent: it would block the sudo call to
# ufw-port, which is how per-session firewall rules are applied. See
# docs/SECURITY.md. Do not add it without also removing the sudo grant.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
ReadWritePaths=/var/lib/safe-connect

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write `deploy/sudoers.safe-connect`**

```
# The bot's only privileged capability. The wrapper validates the port range and
# the source CIDR before it calls ufw; a bare grant on /usr/sbin/ufw would let a
# compromised bot write arbitrary rules, including deleting the SSH allow rule.
#
# Never add env_keep here: ufw-port reads SAFE_CONNECT_* overrides that exist for
# its test suite, and sudo's default env_reset is what keeps them unreachable.
safeconnect ALL=(root) NOPASSWD: /usr/local/lib/safe-connect/ufw-port
```

- [ ] **Step 3: Write `deploy/install-vds.sh`**

```bash
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
install -o root -g root -m 0440 "$REPO/deploy/sudoers.safe-connect" /etc/sudoers.d/safe-connect
visudo -cf /etc/sudoers.d/safe-connect

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
ufw --force enable
ufw allow OpenSSH

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
```

- [ ] **Step 4: Check the scripts for syntax errors**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && bash -n deploy/install-vds.sh && bash -n deploy/ufw-port && echo "syntax ok"'`
Expected: `syntax ok`.

- [ ] **Step 5: Check the unit file parses**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && systemd-analyze verify deploy/safe-connect.service 2>&1 | grep -v "Unit .* not found" || true'`
Expected: no syntax complaints. Warnings about units absent from WSL (`tailscaled.service`) are expected and fine.

- [ ] **Step 6: Commit**

```bash
git add deploy/install-vds.sh deploy/safe-connect.service deploy/sudoers.safe-connect
git commit -m "feat: idempotent VDS installer with a hardened unit and narrow sudo grant"
```

---

### Task 12: PC1 installer and tailnet ACL

**Files:**
- Create: `agent/install-pc1.ps1`, `deploy/tailnet-acl.json`

**Interfaces:**
- Consumes: `agent/agent.ps1`, the public key printed by `install-vds.sh`.
- Produces: OpenSSH Server running on PC1, `C:\ProgramData\SafeConnect\{agent.ps1,agent.config.json}`, a forced-command entry in `administrators_authorized_keys`, and RDP left disabled.

- [ ] **Step 1: Write `deploy/tailnet-acl.json`**

```json
{
  "tagOwners": {
    "tag:vds": ["autogroup:admin"],
    "tag:pc1": ["autogroup:admin"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:vds"],
      "dst": ["tag:pc1:22,3389"]
    }
  ],
  "ssh": []
}
```

Paste this into the Access Controls page of the Tailscale admin console. It replaces the default `accept everything` rule: after this, the only permitted flow anywhere on the tailnet is the VDS reaching PC1 on those two ports. `"ssh": []` disables Tailscale SSH, which would otherwise be a second way onto PC1 that ignores the forced-command key.

- [ ] **Step 2: Write `agent/install-pc1.ps1`**

```powershell
<#
  PC1 bootstrap. Run once from an elevated PowerShell prompt:

    .\install-pc1.ps1 -VdsPublicKey "ssh-ed25519 AAAA... safe-connect" -VdsTailnetIp 100.64.0.5

  Leaves RDP disabled. The bot enables it per session.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$VdsPublicKey,
    [Parameter(Mandatory = $true)][string]$VdsTailnetIp,
    [string]$InstallDir = 'C:\ProgramData\SafeConnect'
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell prompt.'
}

Write-Output '==> OpenSSH Server'
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

Write-Output '==> agent'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'agent.ps1') -Destination $InstallDir -Force
@{ vds_tailnet_ip = $VdsTailnetIp } | ConvertTo-Json |
    Set-Content -Path (Join-Path $InstallDir 'agent.config.json') -Encoding ASCII

Write-Output '==> locking down the agent so a low-privilege foothold cannot rewrite it'
icacls $InstallDir /inheritance:r /grant 'SYSTEM:(OI)(CI)F' /grant 'Administrators:(OI)(CI)F' | Out-Null

Write-Output '==> forced-command key'
$sshdVersion = (& ssh -V) 2>&1
$restrict = if ($sshdVersion -match 'OpenSSH_(\d+)\.(\d+)' -and
                ([int]$Matches[1] -gt 7 -or ([int]$Matches[1] -eq 7 -and [int]$Matches[2] -ge 2))) {
    'restrict'
} else {
    'no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding'
}

$agentPath = Join-Path $InstallDir 'agent.ps1'
$forced = "$restrict,command=`"powershell.exe -NoProfile -ExecutionPolicy Bypass -File $agentPath`" $VdsPublicKey"

$keyFile = 'C:\ProgramData\ssh\administrators_authorized_keys'
$existing = if (Test-Path $keyFile) { Get-Content $keyFile } else { @() }
$keyBody = ($VdsPublicKey -split '\s+')[1]
$kept = $existing | Where-Object { $_ -notmatch [regex]::Escape($keyBody) }
Set-Content -Path $keyFile -Value ($kept + $forced) -Encoding ASCII

icacls $keyFile /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null

Write-Output '==> making sure RDP starts disabled'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name 'fDenyTSConnections' -Value 1 -Type DWord
$rule = Get-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -ErrorAction SilentlyContinue
if ($rule) { Set-NetFirewallRule -DisplayName 'SafeConnect-RDP-In' -Enabled False | Out-Null }

Write-Output '==> requiring NLA'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name 'UserAuthentication' -Value 1 -Type DWord

Write-Output '==> account lockout policy (5 attempts, 15 minutes)'
& net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null

Write-Output '==> enabling logon auditing so /rdp_off can report sessions'
& auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null

Restart-Service sshd
Write-Output ''
Write-Output 'Done. RDP is disabled; the bot will enable it per session.'
Write-Output 'Verify from the VDS with:'
Write-Output "  sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1-tailnet-ip> status"
```

- [ ] **Step 3: Verify both PowerShell files parse**

Run:
```bash
powershell -NoProfile -Command "foreach ($f in 'agent\agent.ps1','agent\install-pc1.ps1') { $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path \"C:\projects\safe-connect\$f\"), [ref]$null, [ref]$e); if ($e) { $e; exit 1 } }; 'parse ok'"
```
Expected: `parse ok`.

- [ ] **Step 4: Verify the ACL is valid JSON**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && python3 -c "import json;json.load(open(\"deploy/tailnet-acl.json\"));print(\"acl ok\")"'`
Expected: `acl ok`.

- [ ] **Step 5: Commit**

```bash
git add agent/install-pc1.ps1 deploy/tailnet-acl.json
git commit -m "feat: PC1 bootstrap and default-deny tailnet ACL"
```

---

### Task 13: Runbook and threat model

**Files:**
- Create: `docs/RUNBOOK.md`, `docs/SECURITY.md`, `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: no code. This is the deliverable the operator actually follows.

- [ ] **Step 1: Write `docs/RUNBOOK.md`**

Sections, in execution order. Every step ends with a verification command whose expected output is stated, so a failure surfaces where it happens rather than at first use.

1. **Prerequisites** — a Telegram account, a Tailscale account, root on the VDS, an admin account on PC1.
2. **Tailscale** — install on PC1 (`winget install tailscale.tailscale`) and on the VDS (`curl -fsSL https://tailscale.com/install.sh | sh`); join both; tag them `tag:pc1` and `tag:vds`; paste `deploy/tailnet-acl.json` into Access Controls; disable key expiry on the VDS node; enable device approval and tailnet lock. *Verify:* `tailscale status` lists both, and `tailscale ping <pc1>` succeeds from the VDS.
3. **PC1** — run `agent/install-pc1.ps1` elevated. *Verify:* `Get-Service sshd` is Running; `fDenyTSConnections` is 1.
4. **VDS** — clone the repo, run `sudo deploy/install-vds.sh`, edit `/etc/safe-connect/config.toml`, put the token in `/etc/safe-connect/env`, paste the printed public key into PC1's `administrators_authorized_keys` (the installer already wrote a forced-command line; replace its key portion), accept PC1's host key once. *Verify:* `sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1> status` prints `{"ok":true,"rdp_enabled":false}`.
5. **BotFather** — create the bot, disable group privacy, obtain the numeric user ID from `@userinfobot`. *Verify:* `/help` gets a reply.
6. **First smoke test** — `systemctl start safe-connect`; `journalctl -u safe-connect -f`; send `/status` (expect closed), `/rdp_on <your IP>`, connect with `mstsc`, `/status` (expect a live connection), `/rdp_off`. *Verify:* `ss -ltn` on the VDS shows the port during the session and nothing after; `sudo ufw status` likewise.
7. **Verify the forced command actually restricts the key** — from the VDS run `sudo -u safeconnect ssh -i /var/lib/safe-connect/id_ed25519 <user>@<pc1> "whoami"`. *Expect:* `{"ok":false,"error":"unknown verb: whoami"}`. If a username comes back instead, the forced command is not in effect — stop and fix it before using the system.
8. **Run the socat tests on the VDS** — `pytest tests/test_forwarder_integration.py`, which is where they exercise the real kernel and real ufw environment.
9. **Troubleshooting** — PC1 unreachable, socat cannot bind, `sudo: a password is required` (a broken sudoers file), a stale state file, Telegram not polling.
10. **Appendix A: pinning PC1's RDP certificate on PC2** — export the certificate from PC1's `Remote Desktop\Certificates` store, import it into PC2's Trusted Root, and save an `.rdp` file containing `authentication level:i:2`. Closes the on-path-VDS credential-harvesting path described in `SECURITY.md`.
11. **Appendix B: adding a TOTP factor to `/rdp_on`** — what it defends (Telegram account takeover), what it does not (a compromised VDS holds the seed), and the code change required.

- [ ] **Step 2: Write `docs/SECURITY.md`**

Port the threat model from the spec verbatim, structured as: the trust boundary statement (the VDS is untrusted); the six channels that reach PC1 and their mitigations; the ranked residual-risk table; and an *Accepted risks* section recording, with reasons, that RDP runs as an administrative account, that certificate pinning is optional, and that `/rdp_on` has no second factor. Each accepted risk names the runbook appendix that would close it.

- [ ] **Step 3: Write `README.md`**

Ten lines: what it does, the topology diagram from the spec, a pointer to `RUNBOOK.md` for setup and `SECURITY.md` for the threat model, and the command table.

- [ ] **Step 4: Run the whole suite one last time**

Run: `wsl -d Ubuntu -- bash -lc 'cd /mnt/c/projects/safe-connect && .venv/bin/pytest tests/ -v'`
Expected: every test passes, none skipped (socat must be installed).

- [ ] **Step 5: Commit**

```bash
git add docs/RUNBOOK.md docs/SECURITY.md README.md
git commit -m "docs: operator runbook and threat model"
```

---

## Deployment

The operator runs the deployment; this project never connects to their hosts. After Task 13, hand over `docs/RUNBOOK.md` and work through it together, starting at step 2. Step 7 is the one that must not be skipped — it is the only check that proves the forced command is really in force, and everything else in the security model rests on it.
