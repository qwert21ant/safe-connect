import logging

from bot.notify import TelegramNotifier


class FakeBot:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[int, str, dict]] = []
        self._error = error

    async def send_message(self, chat_id, text, **kwargs):
        if self._error is not None:
            raise self._error
        self.calls.append((chat_id, text, kwargs))


async def test_send_delivers_plain_text_with_no_parse_mode():
    # Notifications can embed PC1 audit-log usernames and operator-chosen
    # source strings -- values this codebase does not promise are free of
    # Markdown metacharacters. parse_mode="Markdown" would risk the same
    # silent-vanish failure mode as the handler replies: a 400 from Telegram
    # swallowed by this method's own except clause, so a teardown
    # notification would disappear with no trace. Plain text has no entities
    # to fail to parse.
    bot = FakeBot()
    notifier = TelegramNotifier(bot, chat_id=555)

    await notifier.send("session closed after 5m (idle for 10 min). user_name from 203.0.113.9")

    assert bot.calls == [
        (555, "session closed after 5m (idle for 10 min). user_name from 203.0.113.9", {})
    ]


async def test_send_swallows_a_delivery_failure_and_logs_it(caplog):
    bot = FakeBot(error=RuntimeError("network down"))
    notifier = TelegramNotifier(bot, chat_id=555)

    with caplog.at_level(logging.ERROR):
        await notifier.send("this must not raise")  # would raise if not swallowed

    assert any("could not deliver" in r.getMessage() for r in caplog.records)
