from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.filters import Command
from aiogram.types import Message

from bot.config import load_config
from bot.forwarder import Forwarder
from bot.notify import TelegramNotifier
from bot.pc1 import PC1Client
from bot.session import SessionManager
from bot.validation import InvalidSource, parse_source

log = logging.getLogger(__name__)

CONFIG_PATH = Path(os.environ.get("SAFE_CONNECT_CONFIG", "/etc/safe-connect/config.toml"))

USAGE = (
    "Usage: `/rdp_on <your public IP>`\n"
    "For example `/rdp_on 203.0.113.9`.\n\n"
    "`/rdp_on any` opens the port to every source address. "
    "That drops the IP restriction entirely — only the random port and your "
    "Windows password stand between the internet and PC1."
)


class AuthMiddleware:
    """Drops every update that did not come from the configured operator.

    There is no refusal message on purpose: replying would confirm the bot
    exists to anyone who stumbles across it.
    """

    def __init__(self, allowed_user_id: int) -> None:
        self._allowed = allowed_user_id

    async def __call__(self, handler, event, data):
        user = getattr(event, "from_user", None)
        if user is None or user.id != self._allowed:
            log.warning(
                "ignored a message from unauthorised Telegram user %s",
                getattr(user, "id", "unknown"),
            )
            return None
        return await handler(event, data)


async def handle_rdp_on(text: str, manager: SessionManager) -> str:
    # maxsplit=1: the argument is everything after the command, as one token.
    # A plain .split() would silently drop extra whitespace-separated junk
    # (e.g. "203.0.113.9; id" becomes three tokens) into the USAGE branch
    # instead of routing it through parse_source, where a hostile argument
    # needs to land so it is rejected with a reason rather than ignored.
    parts = text.split(maxsplit=1)
    if len(parts) != 2:
        return USAGE
    try:
        source = parse_source(parts[1])
    except InvalidSource as exc:
        return f"That is not a usable source address: {exc}\n\n{USAGE}"
    reply = await manager.open(source)
    if source == "any":
        reply += "\n\nOpened to *any* source address."
    return reply


async def handle_rdp_off(manager: SessionManager) -> str:
    return await manager.close("operator request")


def handle_status(manager: SessionManager) -> str:
    return manager.describe()


def handle_help() -> str:
    return (
        "*Safe Connect*\n"
        "`/rdp_on <ip>` — enable RDP on PC1 and open a port for that address\n"
        "`/rdp_off` — close the port and disable RDP\n"
        "`/status` — current state and time remaining\n"
        "`/help` — this message"
    )


async def _tick_loop(manager: SessionManager, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await manager.tick()
        except Exception:
            log.exception("tick failed; the loop continues")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    config = load_config(CONFIG_PATH)

    bot = Bot(token=config.telegram_token.get_secret_value())
    notifier = TelegramNotifier(bot, config.telegram_user_id)
    manager = SessionManager(
        config=config,
        forwarder=Forwarder(config),
        pc1=PC1Client(config),
        notifier=notifier,
    )

    dispatcher = Dispatcher()
    dispatcher.message.middleware(AuthMiddleware(config.telegram_user_id))

    @dispatcher.message(Command("rdp_on"))
    async def _on(message: Message) -> None:
        await message.answer(await handle_rdp_on(message.text or "", manager), parse_mode="Markdown")

    @dispatcher.message(Command("rdp_off"))
    async def _off(message: Message) -> None:
        await message.answer(await handle_rdp_off(manager), parse_mode="Markdown")

    @dispatcher.message(Command("status"))
    async def _status(message: Message) -> None:
        await message.answer(handle_status(manager), parse_mode="Markdown")

    @dispatcher.message(Command("help", "start"))
    async def _help(message: Message) -> None:
        await message.answer(handle_help(), parse_mode="Markdown")

    try:
        await manager.reconcile()
    except Exception:
        # A failure here means we cannot tell whether a public port is open —
        # crashing loudly under systemd's Restart=always is the right default.
        # But dying silently would leave the operator staring at an
        # unresponsive bot with no clue why, so we get one notification out
        # (best effort — TelegramNotifier.send swallows its own failures)
        # before re-raising to preserve the crash-loud behaviour.
        log.exception("reconcile failed at startup; the bot cannot confirm session state")
        await notifier.send(
            "Safe Connect failed to reconcile session state on startup and is "
            "restarting. If a public port was open, it may still be open — check manually."
        )
        raise

    asyncio.create_task(_tick_loop(manager, config.poll_interval_seconds))
    log.info("safe-connect started")
    await dispatcher.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
