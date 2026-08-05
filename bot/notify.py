from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class TelegramNotifier:
    """Sends unsolicited messages — timer expiries, warnings, restart notices.

    Failures are logged and swallowed: a Telegram outage must never stop a
    teardown that is already in progress.
    """

    def __init__(self, bot, chat_id: int) -> None:
        self._bot = bot
        self._chat_id = chat_id

    async def send(self, text: str) -> None:
        try:
            await self._bot.send_message(self._chat_id, text, parse_mode="Markdown")
        except Exception:
            log.exception("could not deliver a notification to Telegram")
