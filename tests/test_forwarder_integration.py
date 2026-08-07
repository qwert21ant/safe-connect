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
        # Hold the connection open briefly after echoing: closing immediately
        # races the established_count() check in
        # test_traffic_flows_and_stop_leaves_no_process -- socat tears the
        # whole relay down on EOF from this side fast enough (reproduced with
        # plain socat + ss outside of this codebase, see task-5-report.md)
        # that the ESTAB row can vanish before the assertion runs.
        await asyncio.sleep(0.3)
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
    # TCP4-LISTEN, not the dual-stack TCP-LISTEN: real socat 1.8.0 rejects a
    # bare "range=<ipv4>/<bits>" filter on a dual-stack listener with a
    # syntax error (reproduced independent of this codebase; see
    # task-5-report.md). bot.forwarder.Forwarder._socat_argv was fixed the
    # same way; this fixture bypasses that method, so it needs the same fix.
    monkeypatch.setattr(fwd, "_socat_argv", lambda port, source: [
        "socat",
        f"TCP4-LISTEN:{port},fork,reuseaddr" + ("" if source == "any" else f",range={source}"),
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


@pytest.fixture
async def holding_server():
    """Accepts connections and holds them open, like a live RDP session would.

    The echo_server above closes shortly after replying, so it cannot show
    whether stop() actually severs an in-flight session.
    """

    async def handle(reader, writer):
        try:
            await reader.read()          # block until the peer disappears
        except OSError:
            pass
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


@pytest.fixture
def holding_forwarder(holding_server, monkeypatch):
    fwd = Forwarder(make_config(pc1_tailnet_ip="127.0.0.1"))

    async def no_ufw(action, port, source):
        return None

    monkeypatch.setattr(fwd, "_ufw", no_ufw)
    monkeypatch.setattr(fwd, "_socat_argv", lambda port, source: [
        "socat",
        f"TCP4-LISTEN:{port},fork,reuseaddr" + ("" if source == "any" else f",range={source}"),
        f"TCP:127.0.0.1:{holding_server}",
    ])
    return fwd


async def test_stop_severs_an_already_established_session(holding_forwarder):
    """/rdp_off must cut a live session, not merely stop accepting new ones.

    socat is spawned with `fork`, so it forks a child per accepted connection.
    Killing only the listener pid leaves that child relaying an in-flight RDP
    session indefinitely -- the public port stops accepting, but whoever is
    already connected keeps working.
    """
    port = free_port()
    pid = await holding_forwarder.start(port, "any")

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"in-session")
    await writer.drain()
    assert await holding_forwarder.established_count(port) >= 1

    await holding_forwarder.stop(pid, port, "any")
    await asyncio.sleep(0.5)

    # EOF means the relay really is gone. A hang means the forked child lives on.
    assert await asyncio.wait_for(reader.read(1), timeout=5) == b""
    assert await holding_forwarder.established_count(port) == 0
    writer.close()


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
