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
