import logging
from dataclasses import dataclass, field

import pytest

from bot.main import (
    USAGE,
    AuthMiddleware,
    _reply,
    handle_help,
    handle_rdp_off,
    handle_rdp_on,
    handle_status,
)


@dataclass
class FakeUser:
    id: int


@dataclass
class FakeMessage:
    text: str
    from_user: FakeUser


@dataclass
class FakeAnswerMessage:
    """A message that records what was actually handed to Telegram's send call."""

    text: str
    from_user: FakeUser
    sent: list = field(default_factory=list)

    async def answer(self, text, **kwargs):
        self.sent.append((text, kwargs))


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


async def test_rdp_on_rejects_underscored_input_that_would_break_markdown(manager, parts):
    # repr() of the raw argument lands in the reply un-escaped. An odd number
    # of "_" is enough to make Telegram's Markdown parser choke on the
    # message if it were ever sent with parse_mode="Markdown" -- the send
    # would then fail with a 400 and the operator would get nothing at all,
    # indistinguishable from being locked out by the auth middleware. This
    # pins that handle_rdp_on still produces a real, non-empty rejection
    # reply for such input; test_reply_never_sets_a_parse_mode below pins the
    # other half: that the reply is actually delivered regardless of its
    # content.
    reply = await handle_rdp_on("/rdp_on 1_2", manager)
    assert parts["forwarder"].started == []
    assert "not" in reply.lower()
    assert "1_2" in reply


async def test_reply_never_sets_a_parse_mode():
    # _reply is the single choke point every handler's text passes through
    # before Telegram sees it. Plain text (no parse_mode) can never fail to
    # parse -- there are no entities to balance -- so this is the property
    # that guarantees a reply is always delivered, no matter what a handler
    # embedded in it.
    message = FakeAnswerMessage(text="/rdp_on 1_2", from_user=FakeUser(id=1))
    await _reply(message, "unbalanced *markdown_ entities `here")
    assert message.sent == [("unbalanced *markdown_ entities `here", {})]


async def test_a_markdown_breaking_rdp_on_reply_still_reaches_the_operator(manager, parts):
    message = FakeAnswerMessage(text="/rdp_on 1_2", from_user=FakeUser(id=1))
    reply = await handle_rdp_on(message.text, manager)
    await _reply(message, reply)
    assert message.sent, "the operator must receive something, never silence"
    sent_text, kwargs = message.sent[0]
    assert sent_text == reply
    assert "parse_mode" not in kwargs


@pytest.mark.parametrize(
    "label",
    ["USAGE", "handle_help()", "manager.open(...) success", "manager.describe() while open"],
)
async def test_reply_producing_text_has_no_markdown_markup(manager, parts, label):
    # Every send site was switched to plain text (no parse_mode) so an
    # unescaped interpolated value can never make a send fail. That only
    # holds if the strings themselves stop assuming Markdown rendering --
    # otherwise the operator sees raw backticks and asterisks in ordinary,
    # successful replies. This pins that none of the hand-written literals
    # that make up a reply still carry markup, across both bot/main.py and
    # bot/session.py (manager.open/describe live in the latter).
    if label == "USAGE":
        text = USAGE
    elif label == "handle_help()":
        text = handle_help()
    elif label == "manager.open(...) success":
        text = await manager.open("203.0.113.9/32")
    else:
        await manager.open("203.0.113.9/32")
        text = manager.describe()

    assert "`" not in text, f"{label} still contains a backtick: {text!r}"
    assert "*" not in text, f"{label} still contains an asterisk: {text!r}"


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
