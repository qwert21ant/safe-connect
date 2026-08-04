from __future__ import annotations

import asyncio
import os
import signal
from pathlib import Path

from bot import proc
from bot.config import Config

RDP_PORT = 3389
_LISTEN_POLL_INTERVAL = 0.1
_LISTEN_POLL_ATTEMPTS = 20


class ForwarderError(RuntimeError):
    """The public listener or its firewall rule could not be brought up or down."""


class Forwarder:
    """Owns the per-session public listener and its ufw rule.

    Deliberately holds no session state: the pid comes from persisted state, so
    the forwarder can be driven correctly after a bot restart.
    """

    def __init__(self, config: Config, runner=proc.run, spawn=asyncio.create_subprocess_exec) -> None:
        self._config = config
        self._run = runner
        self._spawn = spawn
        self._processes: dict[int, object] = {}

    async def start(self, port: int, source: str) -> int:
        await self._ufw("open", port, source)
        try:
            return await self._spawn_socat(port, source)
        except Exception:
            await self._ufw("close", port, source)
            raise

    async def stop(self, pid: int | None, port: int, source: str) -> None:
        if pid is not None:
            self._terminate(pid)
            process = self._processes.pop(pid, None)
            if process is not None:
                # Reap it here, while our event loop is still open: otherwise
                # asyncio's subprocess transport finalizes itself later via
                # __del__, which can fire after the loop has closed and print
                # "Exception ignored ... Event loop is closed" noise.
                await process.wait()
        await self._ufw("close", port, source)

    def is_alive(self, pid: int, port: int) -> bool:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False
        return b"socat" in cmdline and f"TCP4-LISTEN:{port}".encode() in cmdline

    async def established_count(self, port: int) -> int:
        result = await self._run(
            [str(self._config.ss_path), "-Htn", "state", "established", f"( sport = :{port} )"]
        )
        if not result.ok:
            raise ForwarderError(f"ss failed: {result.stderr.strip()}")
        return len([line for line in result.stdout.splitlines() if line.strip()])

    # -- internals -------------------------------------------------------

    async def _ufw(self, action: str, port: int, source: str) -> None:
        result = await self._run([
            str(self._config.sudo_path), "-n", str(self._config.ufw_port_helper),
            action, str(port), source,
        ])
        if not result.ok:
            raise ForwarderError(f"ufw-port {action} failed: {result.stderr.strip()}")

    def _socat_argv(self, port: int, source: str) -> list[str]:
        # TCP4-LISTEN, not the dual-stack TCP-LISTEN: (a) real socat 1.8.0
        # rejects a bare "range=<ipv4>/<bits>" filter on a dual-stack listener
        # with "syntax error ... of unspecified address family" -- reproduced
        # independent of this code, see task-5-report.md; (b) dual-stack would
        # also bind IPv6, which the ufw rule (IPv4-only) does not cover.
        listen = f"TCP4-LISTEN:{port},fork,reuseaddr"
        if source != "any":
            listen += f",range={source}"
        return [
            str(self._config.socat_path),
            listen,
            f"TCP:{self._config.pc1_tailnet_ip}:{RDP_PORT}",
        ]

    async def _spawn_socat(self, port: int, source: str) -> int:
        process = await self._spawn(
            *self._socat_argv(port, source),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        for _ in range(_LISTEN_POLL_ATTEMPTS):
            await asyncio.sleep(_LISTEN_POLL_INTERVAL)
            if process.returncode is not None:
                raise ForwarderError(f"socat exited immediately with {process.returncode}")
            if await self._is_listening(port):
                self._processes[process.pid] = process
                return process.pid
        self._terminate(process.pid)
        await process.wait()  # reap it now; see stop()'s comment on why
        raise ForwarderError(f"socat did not listen on {port} within 2s")

    async def _is_listening(self, port: int) -> bool:
        result = await self._run(
            [str(self._config.ss_path), "-Hltn", f"( sport = :{port} )"]
        )
        return result.ok and bool(result.stdout.strip())

    def _terminate(self, pid: int) -> None:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                return
            except PermissionError:
                raise ForwarderError(f"not permitted to signal pid {pid}")
