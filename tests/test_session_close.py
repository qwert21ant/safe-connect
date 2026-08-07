from bot.forwarder import ForwarderError
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


async def test_retrying_rdp_off_after_a_failed_pc1_cleanup_actually_retries(manager, parts):
    """FINDING 2: the old code called self._reset() before composing the

    "Retry with /rdp_off" message, so a retry always hit the CLOSED guard's
    "Session is not open." and never touched PC1 again -- the operator's
    only instruction was a no-op, and PC1 stayed enabled toward the
    untrusted VDS indefinitely. This pins that the retry actually calls
    pc1.disable() again, and that it can succeed.
    """
    await manager.open("203.0.113.9/32")
    parts["pc1"].disable_error = PC1Error("agent refused")

    first = await manager.close("operator request")
    assert "FAILED" in first
    assert manager.state.state is State.CLOSED
    assert manager.state.pc1_dirty is True, "outstanding PC1 cleanup must be persisted"

    parts["pc1"].calls.clear()
    parts["pc1"].disable_error = None

    retry = await manager.close("operator request")

    assert "disable" in parts["pc1"].calls, "the retry must actually call pc1.disable() again"
    assert manager.state.state is State.CLOSED
    assert manager.state.pc1_dirty is False
    assert "disabled" in retry.lower() or "completed" in retry.lower()


async def test_retrying_rdp_off_can_fail_again_and_stays_marked_dirty(manager, parts):
    await manager.open("203.0.113.9/32")
    parts["pc1"].disable_error = PC1Error("agent refused")
    await manager.close("operator request")

    parts["pc1"].calls.clear()
    # disable_error is still set -- the retry fails too.
    retry = await manager.close("operator request")

    assert "disable" in parts["pc1"].calls
    assert manager.state.pc1_dirty is True
    assert manager.state.state is State.CLOSED
    assert "outstanding" in retry.lower() or "still" in retry.lower()


async def test_describe_reports_outstanding_pc1_cleanup_instead_of_bare_closed(manager, parts):
    await manager.open("203.0.113.9/32")
    parts["pc1"].disable_error = PC1Error("agent refused")
    await manager.close("operator request")

    description = manager.describe()

    assert "closed" in description.lower()
    assert description != "Closed. No public port, RDP disabled on PC1."
    assert "rdp_off" in description.lower() or "retry" in description.lower()


async def test_close_reports_when_the_forwarder_fails_to_stop(manager, parts):
    """FINDING 3: a failed forwarder.stop() must be surfaced, naming the port,

    so the operator can remove the leftover ufw rule by hand -- previously
    the broad except around forwarder.stop() only logged, pc1_ok tracked
    nothing about the forwarder, and _reset() discarded the port before the
    message was composed, leaving the operator with no way to even know
    which port to clean up.
    """
    await manager.open("203.0.113.9/32")
    port = manager.state.port

    async def failing_stop(pid, port, source):
        raise ForwarderError("ufw-port close failed: '/etc/ufw/user.rules' is not writable")

    parts["forwarder"].stop = failing_stop

    message = await manager.close("operator request")

    assert manager.state.state is State.CLOSED
    assert "disable" in parts["pc1"].calls, "PC1 cleanup must still be attempted"
    assert "FAILED" in message
    assert str(port) in message, "the port must be named so it can be cleaned up manually"


async def test_close_reports_both_failures_when_forwarder_and_pc1_both_fail(manager, parts):
    await manager.open("203.0.113.9/32")
    port = manager.state.port
    parts["pc1"].disable_error = PC1Error("agent refused")

    async def failing_stop(pid, port, source):
        raise ForwarderError("boom")

    parts["forwarder"].stop = failing_stop

    message = await manager.close("operator request")

    assert manager.state.state is State.CLOSED
    assert manager.state.pc1_dirty is True
    assert str(port) in message
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
