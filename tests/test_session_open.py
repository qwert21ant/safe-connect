import json

import pytest

from bot.pc1 import PC1Client, PC1Error
from bot.proc import ProcTimeout
from bot.session import SessionManager, State


class TimingOutRunner:
    """Simulates proc.run() timing out and raising ProcTimeout."""

    async def __call__(self, argv, timeout=30.0):
        raise ProcTimeout(f"timed out after {timeout}s: {argv[0]}")


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


async def test_pc1_prep_happens_strictly_before_forwarder_start(manager, parts):
    """Order matters: PC1 must be ready before any public port exists.

    Both events are recorded into ONE shared, ordered list so this test
    actually discriminates the sequencing: if open() started the forwarder
    before finishing PC1 prep, `events` would come out as
    ["forwarder-start", "pc1-probe"] and this test would fail. (Checking
    pc1.calls and forwarder.started separately, as the other test in this
    file does, cannot catch that: those are two independent lists with no
    relative ordering between them.)
    """
    events: list[str] = []

    orig_probe = parts["pc1"].probe_rdp

    async def probe_rdp(timeout: float = 5.0) -> bool:
        result = await orig_probe(timeout)
        events.append("pc1-probe")
        return result

    parts["pc1"].probe_rdp = probe_rdp

    orig_start = parts["forwarder"].start

    async def start(port: int, source: str) -> int:
        result = await orig_start(port, source)
        events.append("forwarder-start")
        return result

    parts["forwarder"].start = start

    await manager.open("203.0.113.9/32")

    assert events == ["pc1-probe", "forwarder-start"]


async def test_port_is_persisted_before_the_forwarder_start_attempt_is_made(manager, parts):
    """FINDING 5: forwarder.start() opens the ufw rule before it spawns socat.

    If the port is only recorded in state.json AFTER forwarder.start()
    returns, a hard crash between the ufw open succeeding and that save
    leaves the rule up with nothing on disk pointing at it -- reconcile()'s
    stale-OPENING teardown hits `if port is not None and source is not None`
    and skips forwarder.stop() entirely, since port was never saved. This
    pins that the port (and source) actually on disk match what's about to
    be attempted BEFORE forwarder.start() is even called, i.e. a crash at
    that exact instant is still recoverable.
    """
    seen = {}

    async def spying_start(port, source):
        import json
        saved = json.loads(parts["config"].state_path.read_text())
        seen["port"] = saved["port"]
        seen["source"] = saved["source"]
        seen["state"] = saved["state"]
        return 4242

    parts["forwarder"].start = spying_start

    await manager.open("203.0.113.9/32")

    assert seen["port"] == manager.state.port
    assert seen["source"] == "203.0.113.9/32"
    # Not yet OPEN at that point -- reconcile() must still tear it down via
    # the "stuck in opening" path if a crash happens right there.
    assert seen["state"] == "opening"


async def test_each_retry_attempts_port_is_persisted_before_that_attempt(manager, parts):
    """Every bind retry gets a fresh random port -- each one individually

    must be on disk before forwarder.start() is called with it, not just the
    first attempt, so a crash mid-retry is recoverable too.
    """
    import json

    seen_pairs = []
    orig_start = parts["forwarder"].start

    async def spying_start(port, source):
        saved = json.loads(parts["config"].state_path.read_text())
        seen_pairs.append((port, saved["port"]))
        return await orig_start(port, source)

    parts["forwarder"].start = spying_start
    parts["forwarder"].start_failures = 2

    await manager.open("any")

    assert len(seen_pairs) == 3
    assert all(attempted == persisted for attempted, persisted in seen_pairs)


async def test_open_recovers_to_closed_when_pc1_enable_times_out(parts):
    """A hung SSH during enable() must not leave state.json stuck at OPENING.

    Uses a real PC1Client (not FakePC1) with a runner that raises ProcTimeout,
    so this exercises the actual boundary-wrapping fix in bot/pc1.py, not just
    a fake that happens to raise the "convenient" exception type.
    """
    parts["pc1"] = PC1Client(parts["config"], runner=TimingOutRunner())
    manager = SessionManager(**parts)

    await manager.open("203.0.113.9/32")

    assert manager.state.state is State.CLOSED
    saved = json.loads(parts["config"].state_path.read_text())
    assert saved["state"] == "closed"
