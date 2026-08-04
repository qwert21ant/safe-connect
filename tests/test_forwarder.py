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
