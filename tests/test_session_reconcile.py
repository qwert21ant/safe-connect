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
