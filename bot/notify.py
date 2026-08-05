from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class TelegramNotifier:
    """Sends unsolicited messages — timer expiries, warnings, restart notices.

    Failures are logged and swallowed: a Telegram outage must never stop a
    teardown that is already in progress.

    Sent as plain text, deliberately without parse_mode="Markdown": these
    messages can embed PC1 audit-log usernames and operator-chosen source
    strings that are not guaranteed to contain balanced Markdown entities.
    A malformed entity makes Telegram reject the send with a 400, which this
    method's own except clause then swallows -- so a Markdown-mode send can
    make a notification vanish with no trace at all. Plain text has no
    entities to fail to parse, so that failure mode cannot happen here.
    """

    def __init__(self, bot, chat_id: int) -> None:
        self._bot = bot
        self._chat_id = chat_id

    async def send(self, text: str) -> None:
        try:
            await self._bot.send_message(self._chat_id, text)
        except Exception:
            log.exception("could not deliver a notification to Telegram")
