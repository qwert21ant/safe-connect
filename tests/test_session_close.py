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


async def test_forwarder_stop_happens_strictly_before_pc1_disable(manager, parts):
    """Order matters: the public listener must die before PC1 cleanup is attempted.

    Both events are recorded into ONE shared, ordered list so this test
    actually discriminates the sequencing: if close() disabled PC1 before
    stopping the forwarder, `events` would come out as
    ["pc1-disable", "forwarder-stop"] and this test would fail. (Checking
    forwarder.stopped and pc1.calls separately, as the other tests in this
    file do, cannot catch that: those are two independent lists with no
    relative ordering between them.)
    """
    await manager.open("203.0.113.9/32")

    events: list[str] = []

    orig_stop = parts["forwarder"].stop

    async def stop(pid, port, source) -> None:
        await orig_stop(pid, port, source)
        events.append("forwarder-stop")

    parts["forwarder"].stop = stop

    orig_disable = parts["pc1"].disable

    async def disable() -> None:
        await orig_disable()
        events.append("pc1-disable")

    parts["pc1"].disable = disable

    await manager.close("operator request")

    assert events == ["forwarder-stop", "pc1-disable"]


async def test_close_still_attempts_pc1_disable_when_forwarder_stop_raises_unexpectedly(manager, parts):
    """The fail-forward guarantee is "pc1.disable() is always attempted once

    listener teardown has been tried" -- an exception type nobody anticipated
    coming out of forwarder.stop() must not be able to skip it.
    """
    await manager.open("203.0.113.9/32")
    parts["pc1"].calls.clear()

    async def stop(pid, port, source):
        raise RuntimeError("unexpected failure unrelated to ForwarderError")

    parts["forwarder"].stop = stop

    await manager.close("operator request")

    assert "disable" in parts["pc1"].calls
    assert manager.state.state is State.CLOSED
