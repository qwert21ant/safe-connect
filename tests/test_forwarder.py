import asyncio
import signal
from pathlib import Path

import pytest

from bot.config import Config
from bot.forwarder import _REAP_TIMEOUT, Forwarder, ForwarderError
from bot.proc import ProcTimeout, Result


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


class TimingOutRunner:
    """Simulates proc.run() timing out and raising ProcTimeout."""

    async def __call__(self, argv, timeout=30.0):
        raise ProcTimeout(f"timed out after {timeout}s: {argv[0]}")


class FakeStderr:
    """Stands in for asyncio.StreamReader: one bounded .read(), then EOF."""

    def __init__(self, data: bytes = b""):
        self._data = data
        self._sent = False

    async def read(self, n=-1):
        if self._sent:
            return b""
        self._sent = True
        return self._data


class FakeProcess:
    def __init__(self, pid=4242, returncode=None, stderr_data: bytes = b""):
        self.pid = pid
        self.returncode = returncode
        self.stderr = FakeStderr(stderr_data)

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


async def test_socat_exiting_immediately_surfaces_its_stderr_text():
    """FINDING 6: socat's own diagnostic text was discarded entirely on the

    failure path, leaving /rdp_on failures diagnostically blind -- only a
    bare exit code reached the operator. This pins that the drained stderr
    text is folded into the ForwarderError message.
    """
    runner = FakeRunner([Result(0, "", "")])   # ufw open succeeds

    async def spawn(*argv, **kwargs):
        return FakeProcess(
            returncode=1,
            stderr_data=b"2026/08/08 socat[123] E bind(5, ...): Address already in use\n",
        )

    fwd = Forwarder(make_config(), runner=runner, spawn=spawn)
    with pytest.raises(ForwarderError, match="Address already in use"):
        await fwd.start(40017, "203.0.113.9/32")


async def test_start_raises_when_ufw_refuses():
    runner = FakeRunner([Result(2, "", "ufw-port: port 22 is outside the permitted range")])

    async def spawn(*argv, **kwargs):
        raise AssertionError("socat must not be spawned when ufw failed")

    with pytest.raises(ForwarderError, match="outside the permitted range"):
        await Forwarder(make_config(), runner=runner, spawn=spawn).start(40017, "any")


async def test_start_raises_forwarder_error_not_proctimeout_when_ufw_times_out():
    """A wedged ufw-port helper must surface as ForwarderError, the vocabulary

    session.py catches -- not as the runner's bare ProcTimeout, which nothing
    in bot/ catches and which would otherwise escape start().
    """

    async def spawn(*argv, **kwargs):
        raise AssertionError("socat must not be spawned when ufw timed out")

    with pytest.raises(ForwarderError):
        await Forwarder(make_config(), runner=TimingOutRunner(), spawn=spawn).start(40017, "any")


async def test_stop_kills_socat_before_closing_ufw():
    """Order matters: the public listener must die first.

    Both events are recorded into ONE shared, ordered list so the test
    actually discriminates the sequencing: if stop() were reordered to
    close the ufw rule before killing socat, `events` would come out as
    ["ufw-close", "kill"] and this test would fail.
    """
    events: list[str] = []
    killed = []

    class OrderTrackingRunner(FakeRunner):
        async def __call__(self, argv, timeout=30.0):
            result = await super().__call__(argv, timeout=timeout)
            if list(argv)[-3:] == ["close", "40017", "203.0.113.9/32"]:
                events.append("ufw-close")
            return result

    runner = OrderTrackingRunner()
    fwd = Forwarder(make_config(), runner=runner, spawn=None)

    def fake_terminate(pid):
        killed.append(pid)
        events.append("kill")

    fwd._terminate = fake_terminate   # noqa: SLF001

    await fwd.stop(4242, 40017, "203.0.113.9/32")

    assert killed == [4242]
    assert events == ["kill", "ufw-close"]
    assert runner.calls[0][-3:] == ["close", "40017", "203.0.113.9/32"]


async def test_stop_still_closes_ufw_when_pid_is_unknown():
    runner = FakeRunner()
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    await fwd.stop(None, 40017, "any")
    assert runner.calls[0][-3:] == ["close", "40017", "any"]


async def test_stop_closes_ufw_even_if_the_reaped_process_never_exits():
    """FINDING 6: process.wait() after signalling must be bounded -- otherwise

    a process that never actually exits after being signalled (stuck in
    uninterruptible sleep, or just very slow) would delay the ufw close
    indefinitely, contradicting stop()'s own comment that the close must run
    on every path through here.
    """
    runner = FakeRunner()
    fwd = Forwarder(make_config(), runner=runner, spawn=None)
    fwd._terminate = lambda pid: None  # noqa: SLF001 -- pretend signalling succeeded

    class HangingProcess:
        async def wait(self):
            await asyncio.Event().wait()  # never resolves

    fwd._processes[4242] = HangingProcess()

    # If the reap is unbounded, this whole call hangs and the outer
    # wait_for is what actually fails the test (not a graceful assertion).
    await asyncio.wait_for(fwd.stop(4242, 40017, "any"), timeout=_REAP_TIMEOUT + 5)

    assert runner.calls[0][-3:] == ["close", "40017", "any"]


async def test_stop_still_closes_ufw_when_terminate_fails():
    """A failed kill must not leave the public port open."""
    runner = FakeRunner()
    fwd = Forwarder(make_config(), runner=runner, spawn=None)

    def failing_terminate(pid):
        raise ForwarderError(f"not permitted to signal pid {pid}")

    fwd._terminate = failing_terminate   # noqa: SLF001

    with pytest.raises(ForwarderError):
        await fwd.stop(4242, 40017, "203.0.113.9/32")

    assert runner.calls[0][-3:] == ["close", "40017", "203.0.113.9/32"]


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


async def test_established_count_raises_forwarder_error_not_proctimeout_when_ss_times_out():
    fwd = Forwarder(make_config(), runner=TimingOutRunner(), spawn=None)
    with pytest.raises(ForwarderError):
        await fwd.established_count(40017)


async def test_start_raises_forwarder_error_when_listen_check_times_out():
    """_is_listening() must also wrap ProcTimeout, not just _ufw()."""

    class OpenThenTimingOutRunner:
        async def __call__(self, argv, timeout=30.0):
            if argv[0] == "/usr/bin/sudo":
                return Result(0, "", "")  # ufw open succeeds
            raise ProcTimeout("ss timed out")  # the listen-check (ss) never answers

    async def spawn(*argv, **kwargs):
        return FakeProcess()

    with pytest.raises(ForwarderError):
        await Forwarder(make_config(), runner=OpenThenTimingOutRunner(), spawn=spawn).start(40017, "any")


async def test_spawned_process_is_terminated_when_the_listen_poll_raises():
    """FINDING 4: an exception escaping the poll loop (e.g. ProcTimeout from ss,

    wrapped as ForwarderError by _is_listening) must not leak the socat
    process _spawn_socat already spawned. Before the fix, only the "did not
    listen within 2s" branch terminated and reaped the process; any OTHER
    exception -- like the one this test raises -- propagated straight out of
    the poll loop, leaving an unsupervised socat holding a port with nothing
    tracking it in state.json.
    """

    class OpenThenTimingOutRunner:
        async def __call__(self, argv, timeout=30.0):
            if argv[0] == "/usr/bin/sudo":
                return Result(0, "", "")  # ufw open succeeds
            raise ProcTimeout("ss wedged")  # the listen-check never answers

    terminated = []
    process = FakeProcess(pid=777)

    async def spawn(*argv, **kwargs):
        return process

    fwd = Forwarder(make_config(), runner=OpenThenTimingOutRunner(), spawn=spawn)
    fwd._terminate = lambda pid: terminated.append(pid)  # noqa: SLF001

    with pytest.raises(ForwarderError):
        await fwd.start(40017, "any")

    assert terminated == [777], "the spawned process must be terminated, not leaked"
    assert 777 not in fwd._processes, "a leaked process must not stay tracked either"


def test_is_alive_is_false_for_a_pid_that_does_not_exist():
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    assert fwd.is_alive(999999, 40017) is False


def test_terminate_skips_sigkill_when_sigterm_is_enough(monkeypatch):
    """No liveness recheck between signals risks SIGKILL hitting a recycled group."""
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    signals_sent = []
    alive = True

    def fake_killpg(pgid, sig):
        nonlocal alive
        if sig == signal.SIGTERM:
            signals_sent.append(sig)
            alive = False
        elif sig == 0:
            if not alive:
                raise ProcessLookupError
        else:
            signals_sent.append(sig)

    monkeypatch.setattr("bot.forwarder.os.killpg", fake_killpg)
    monkeypatch.setattr("bot.forwarder.time.sleep", lambda seconds: None)
    monkeypatch.setattr(Forwarder, "_is_socat", staticmethod(lambda pid: True))

    fwd._terminate(4242)

    assert signals_sent == [signal.SIGTERM]


def test_terminate_escalates_to_sigkill_when_group_survives_sigterm(monkeypatch):
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    signals_sent = []

    def fake_killpg(pgid, sig):
        # The group never reports as gone via the signal-0 liveness probe.
        if sig != 0:
            signals_sent.append(sig)

    monkeypatch.setattr("bot.forwarder.os.killpg", fake_killpg)
    monkeypatch.setattr("bot.forwarder.time.sleep", lambda seconds: None)
    monkeypatch.setattr(Forwarder, "_is_socat", staticmethod(lambda pid: True))

    fwd._terminate(4242)

    assert signals_sent == [signal.SIGTERM, signal.SIGKILL]


def test_terminate_signals_the_group_not_just_the_listener(monkeypatch):
    """socat forks a child per connection; only killpg reaches those children."""
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    group_signals = []

    monkeypatch.setattr("bot.forwarder.os.killpg",
                        lambda pgid, sig: group_signals.append((pgid, sig)))
    monkeypatch.setattr("bot.forwarder.os.kill",
                        lambda pid, sig: pytest.fail("must not signal a single pid"))
    monkeypatch.setattr("bot.forwarder.time.sleep", lambda seconds: None)
    monkeypatch.setattr(Forwarder, "_is_socat", staticmethod(lambda pid: True))

    fwd._terminate(4242)

    assert group_signals[0] == (4242, signal.SIGTERM)


def test_terminate_refuses_to_signal_a_group_whose_leader_is_not_socat(monkeypatch):
    """Guards against the pid having been recycled by an unrelated process.

    This is the genuine pid-reuse case: this pid's cmdline is a real,
    non-empty argv and it is not socat. That is the only situation
    _terminate may refuse to signal -- see the test below for the
    pid-vanished/zombie case, which must NOT refuse.
    """
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)

    monkeypatch.setattr("bot.forwarder.os.killpg",
                        lambda pgid, sig: pytest.fail("signalled a recycled pid's group"))
    monkeypatch.setattr(Forwarder, "_is_socat", staticmethod(lambda pid: False))
    monkeypatch.setattr(Forwarder, "_cmdline_is_empty", staticmethod(lambda pid: False))

    fwd._terminate(4242)


def test_terminate_signals_the_group_when_listener_pid_is_gone_but_group_survives(monkeypatch):
    """A dead listener whose forked children are still relaying must still be reaped.

    socat runs with `fork`: killing only the listener leaves an in-flight
    connection's forked child relaying forever if the listener has already
    exited on its own (e.g. crashed) by the time _terminate runs. Linux will
    not recycle a pid number while any live task -- including one of socat's
    own forked children, or the dead listener itself sitting as an unreaped
    zombie -- still references it as its process-group id, so a non-empty
    group behind a vanished or zombified leader pid can only be our own
    orphaned children, never an unrelated process. This is the defect the
    earlier `if not self._is_socat(pid): return` guard reintroduced: it
    treated "listener is gone" the same as "pid was recycled by something
    else" and refused to signal either. cmdline_is_empty=True covers both
    the zombie case (cmdline reads back b"") and the fully-reaped case
    (/proc/<pid> gone entirely) identically, since both are safe to treat as
    "still ours" -- see _cmdline_is_empty's docstring.
    """
    fwd = Forwarder(make_config(), runner=FakeRunner(), spawn=None)
    group_signals = []

    monkeypatch.setattr("bot.forwarder.os.killpg",
                        lambda pgid, sig: group_signals.append((pgid, sig)))
    monkeypatch.setattr("bot.forwarder.time.sleep", lambda seconds: None)
    monkeypatch.setattr(Forwarder, "_is_socat", staticmethod(lambda pid: False))
    monkeypatch.setattr(Forwarder, "_cmdline_is_empty", staticmethod(lambda pid: True))

    fwd._terminate(4242)

    assert group_signals[0] == (4242, signal.SIGTERM)


def test_cmdline_is_empty_is_true_for_a_zombies_empty_cmdline(monkeypatch):
    """A zombie's /proc/<pid>/cmdline reads back as b"", not an OSError."""
    monkeypatch.setattr("bot.forwarder.Path.read_bytes", lambda self: b"")
    assert Forwarder._cmdline_is_empty(4242) is True


def test_cmdline_is_empty_is_true_for_a_pid_that_no_longer_exists():
    assert Forwarder._cmdline_is_empty(999999) is True


def test_cmdline_is_empty_is_false_for_a_real_cmdline(monkeypatch):
    monkeypatch.setattr("bot.forwarder.Path.read_bytes", lambda self: b"/usr/bin/ss\x00-Hltn\x00")
    assert Forwarder._cmdline_is_empty(4242) is False


async def test_spawn_puts_socat_in_its_own_session(monkeypatch):
    """Without start_new_session, killpg would target the bot's own group."""
    runner = FakeRunner([Result(0, "", ""), Result(0, "LISTEN 0 5 *:40017 *:*\n", "")])
    captured = {}

    async def spawn(*argv, **kwargs):
        captured.update(kwargs)
        return FakeProcess()

    await Forwarder(make_config(), runner=runner, spawn=spawn).start(40017, "any")

    assert captured.get("start_new_session") is True
