from __future__ import annotations

import asyncio
import json
import math
from dataclasses import dataclass

from bot import proc
from bot.config import Config
from bot.proc import ProcTimeout

RDP_PORT = 3389


class PC1Error(RuntimeError):
    """PC1 was unreachable, or its agent refused or failed the request."""


@dataclass(frozen=True)
class LogonEvent:
    time: str
    user: str
    source_ip: str


@dataclass(frozen=True)
class AuditReport:
    successes: list[LogonEvent]
    failures: list[LogonEvent]


class PC1Client:
    """Speaks to the forced-command agent on PC1.

    The SSH key is pinned to agent.ps1 on PC1's side, so the strings sent here
    are the complete vocabulary available to this process — and to anyone who
    steals the key.
    """

    def __init__(self, config: Config, runner=proc.run) -> None:
        self._config = config
        self._run = runner

    async def enable(self) -> None:
        await self._call("enable")

    async def disable(self) -> None:
        await self._call("disable")

    async def status(self) -> bool:
        return bool((await self._call("status")).get("rdp_enabled", False))

    async def audit(self, since_epoch: float) -> AuditReport:
        if not math.isfinite(since_epoch):
            raise PC1Error(f"audit epoch must be finite, got {since_epoch}")
        payload = await self._call(f"audit {int(since_epoch)}")
        return AuditReport(
            successes=[LogonEvent(**item) for item in payload.get("successes", [])],
            failures=[LogonEvent(**item) for item in payload.get("failures", [])],
        )

    async def probe_rdp(self, timeout: float = 5.0) -> bool:
        """Confirm 3389 accepts connections over the tailnet before opening a public port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._config.pc1_tailnet_ip, RDP_PORT), timeout
            )
        except (OSError, asyncio.TimeoutError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True

    # -- internals -------------------------------------------------------

    def _ssh_argv(self, remote_command: str) -> list[str]:
        return [
            str(self._config.ssh_path),
            "-i", str(self._config.pc1_ssh_key_path),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10",
            "-o", "IdentitiesOnly=yes",
            f"{self._config.pc1_ssh_user}@{self._config.pc1_tailnet_ip}",
            remote_command,
        ]

    async def _call(self, remote_command: str) -> dict:
        try:
            result = await self._run(self._ssh_argv(remote_command))
        except ProcTimeout as exc:
            raise PC1Error(f"ssh to PC1 timed out: {exc}") from exc
        if not result.ok:
            raise PC1Error(f"ssh to PC1 failed ({result.returncode}): {result.stderr.strip()}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PC1Error(f"unparseable agent response: {result.stdout[:200]!r}") from exc
        if not isinstance(payload, dict):
            raise PC1Error(f"unparseable agent response: expected dict, got {type(payload).__name__}")
        if not payload.get("ok"):
            raise PC1Error(f"agent refused: {payload.get('error', 'no reason given')}")
        return payload
