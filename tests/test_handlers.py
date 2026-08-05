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
