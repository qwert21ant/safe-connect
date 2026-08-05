from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Protocol

from bot.config import Config
from bot.forwarder import ForwarderError
from bot.pc1 import AuditReport, PC1Error

log = logging.getLogger(__name__)

BIND_ATTEMPTS = 3


class State(str, Enum):
    CLOSED = "closed"
    OPENING = "opening"
    OPEN = "open"
    CLOSING = "closing"


class Clock(Protocol):
    def now(self) -> float: ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class Notifier(Protocol):
    async def send(self, text: str) -> None: ...


@dataclass
class SessionState:
    state: State = State.CLOSED
    port: int | None = None
    source: str | None = None
    socat_pid: int | None = None
    opened_at: float | None = None
    last_connection_at: float | None = None
    saw_connection: bool = False
    hard_cap_warned: bool = False

    def to_dict(self) -> dict:
        data = asdict(self)
        data["state"] = self.state.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "SessionState":
        data = dict(data)
        data["state"] = State(data.get("state", State.CLOSED.value))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


class SessionManager:
    """Owns the single session's lifecycle.

    Ordering is the safety property here: PC1 is prepared before a public port
    exists, and the public port dies before PC1 cleanup is attempted.
    """

    def __init__(self, config: Config, forwarder, pc1, notifier,
                 clock: Clock | None = None, rng: random.Random | None = None) -> None:
        self._config = config
        self._forwarder = forwarder
        self._pc1 = pc1
        self._notifier = notifier
        self._clock = clock or SystemClock()
        self._rng = rng or random.Random()
        self.state = self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> SessionState:
        path = self._config.state_path
        if not path.exists():
            return SessionState()
        try:
            return SessionState.from_dict(json.loads(path.read_text()))
        except (OSError, ValueError):
            log.warning("state file unreadable, assuming closed", exc_info=True)
            return SessionState()

    def _save(self) -> None:
        path = self._config.state_path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state.to_dict(), indent=2))
        tmp.replace(path)

    # -- opening ---------------------------------------------------------

    async def open(self, source: str) -> str:
        if self.state.state is not State.CLOSED:
            return (f"Session is already {self.state.state.value} "
                    f"on port {self.state.port} for {self.state.source}. Use /rdp_off first.")

        self.state = SessionState(state=State.OPENING)
        self._save()

        try:
            await self._pc1.enable()
        except PC1Error as exc:
            log.warning("enabling RDP on PC1 failed: %s", exc)
            self._reset()
            return f"PC1 unreachable — is it powered on and on the tailnet?\n\n`{exc}`"

        if not await self._pc1.probe_rdp():
            log.warning("RDP probe failed after enable")
            await self._rollback_pc1()
            self._reset()
            return "RDP was enabled on PC1 but port 3389 did not answer over the tailnet. Nothing was opened."

        port, pid = await self._start_forwarder(source)
        if port is None:
            await self._rollback_pc1()
            self._reset()
            return "Could not open a public port after three attempts. Nothing was opened."

        now = self._clock.now()
        self.state = SessionState(
            state=State.OPEN, port=port, source=source, socat_pid=pid, opened_at=now
        )
        self._save()

        log.info("session open on %s for %s", port, source)
        return (f"RDP open at `{self._config.vds_public_ip}:{port}`\n"
                f"Source: `{source}`\n"
                f"Closes after {self._config.idle_timeout_seconds // 60} min idle, "
                f"or {self._config.hard_cap_seconds // 3600} h maximum.")

    async def _start_forwarder(self, source: str) -> tuple[int | None, int | None]:
        for _ in range(BIND_ATTEMPTS):
            port = self._rng.randint(self._config.port_range_start, self._config.port_range_end)
            try:
                return port, await self._forwarder.start(port, source)
            except ForwarderError as exc:
                log.warning("could not start forwarder on %s: %s", port, exc)
        return None, None

    async def _rollback_pc1(self) -> None:
        try:
            await self._pc1.disable()
        except PC1Error as exc:
            log.error("rollback of PC1 failed: %s", exc)

    def _reset(self) -> None:
        self.state = SessionState()
        self._save()

    # -- closing ---------------------------------------------------------

    async def close(self, reason: str) -> str:
        if self.state.state is State.CLOSED:
            return "Session is not open."

        opened_at = self.state.opened_at or self._clock.now()
        port, source, pid = self.state.port, self.state.source, self.state.socat_pid
        self.state.state = State.CLOSING
        self._save()

        if port is not None and source is not None:
            try:
                await self._forwarder.stop(pid, port, source)
            except Exception as exc:  # noqa: BLE001 -- fail-forward: pc1.disable()
                # below must always be attempted once teardown has been tried,
                # so an exception type we didn't anticipate must not skip it.
                log.error("stopping the forwarder failed: %s", exc, exc_info=True)

        pc1_ok = True
        try:
            await self._pc1.disable()
        except PC1Error as exc:
            pc1_ok = False
            log.error("disabling RDP on PC1 failed: %s", exc)

        audit_line = await self._audit_line(opened_at)
        self._reset()

        elapsed = int((self._clock.now() - opened_at) // 60)
        header = f"Session closed after {elapsed}m ({reason})."
        if not pc1_ok:
            header = (f"Public port closed after {elapsed}m ({reason}).\n"
                      f"PC1 cleanup FAILED — RDP may still be enabled on PC1. "
                      f"Retry with /rdp_off.")
        return f"{header}\n{audit_line}"

    async def _audit_line(self, since: float) -> str:
        try:
            report: AuditReport = await self._pc1.audit(since)
        except PC1Error as exc:
            log.warning("audit fetch failed: %s", exc)
            return "Logon audit unavailable."
        detail = ""
        if report.successes:
            who = ", ".join(f"{e.user} from {e.source_ip}" for e in report.successes)
            detail = f" ({who})"
        return (f"Logons: {len(report.successes)} success"
                f"{'es' if len(report.successes) != 1 else ''}{detail}, "
                f"{len(report.failures)} failures.")

    # -- reporting -------------------------------------------------------

    def describe(self) -> str:
        if self.state.state is State.CLOSED:
            return "Closed. No public port, RDP disabled on PC1."
        if self.state.state is not State.OPEN:
            return f"{self.state.state.value.capitalize()}…"
        now = self._clock.now()
        opened_at = self.state.opened_at or now
        hard_left = int((self._config.hard_cap_seconds - (now - opened_at)) // 60)
        if self.state.saw_connection and self.state.last_connection_at:
            idle_left = int(
                (self._config.idle_timeout_seconds - (now - self.state.last_connection_at)) // 60
            )
            idle_line = f"Idle timeout in {max(idle_left, 0)}m."
        else:
            grace_left = int((self._config.connect_grace_seconds - (now - opened_at)) // 60)
            idle_line = f"No connection yet; closes in {max(grace_left, 0)}m if none arrives."
        return (f"Open at `{self._config.vds_public_ip}:{self.state.port}`\n"
                f"Source: `{self.state.source}`\n"
                f"{idle_line}\nHard cap in {max(hard_left, 0)}m.")
