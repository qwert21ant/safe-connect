from __future__ import annotations

import asyncio
import os
import signal
import time
from pathlib import Path

from bot import proc
from bot.config import Config
from bot.proc import ProcTimeout

RDP_PORT = 3389
_LISTEN_POLL_INTERVAL = 0.1
_LISTEN_POLL_ATTEMPTS = 20
_TERMINATE_POLL_INTERVAL = 0.05
_TERMINATE_POLL_ATTEMPTS = 10  # ~0.5s of grace after SIGTERM before SIGKILL


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
        # The ufw close must run on every path through here, even if
        # _terminate() raises (e.g. PermissionError signalling the pid) --
        # otherwise a failed kill would leave the public port open. We stash
        # the error and re-raise it only after the close has run.
        terminate_error: Exception | None = None
        if pid is not None:
            try:
                self._terminate(pid)
            except Exception as exc:  # noqa: BLE001 -- re-raised below, never swallowed
                terminate_error = exc
            else:
                process = self._processes.pop(pid, None)
                if process is not None:
                    # Reap it here, while our event loop is still open: otherwise
                    # asyncio's subprocess transport finalizes itself later via
                    # __del__, which can fire after the loop has closed and print
                    # "Exception ignored ... Event loop is closed" noise.
                    await process.wait()
        await self._ufw("close", port, source)
        if terminate_error is not None:
            raise terminate_error

    def is_alive(self, pid: int, port: int) -> bool:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False
        return b"socat" in cmdline and f"TCP4-LISTEN:{port}".encode() in cmdline

    async def established_count(self, port: int) -> int:
        try:
            result = await self._run(
                [str(self._config.ss_path), "-Htn", "state", "established", f"( sport = :{port} )"]
            )
        except ProcTimeout as exc:
            raise ForwarderError(f"ss timed out: {exc}") from exc
        if not result.ok:
            raise ForwarderError(f"ss failed: {result.stderr.strip()}")
        return len([line for line in result.stdout.splitlines() if line.strip()])

    # -- internals -------------------------------------------------------

    async def _ufw(self, action: str, port: int, source: str) -> None:
        try:
            result = await self._run([
                str(self._config.sudo_path), "-n", str(self._config.ufw_port_helper),
                action, str(port), source,
            ])
        except ProcTimeout as exc:
            raise ForwarderError(f"ufw-port {action} timed out: {exc}") from exc
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
            # Put socat in its own session, making its pid the leader of a fresh
            # process group. _terminate() kills that whole group so the children
            # socat forks per connection die with it; without the new session
            # socat would share the bot's group and killing it would kill us.
            start_new_session=True,
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
        try:
            result = await self._run(
                [str(self._config.ss_path), "-Hltn", f"( sport = :{port} )"]
            )
        except ProcTimeout as exc:
            raise ForwarderError(f"ss timed out: {exc}") from exc
        return result.ok and bool(result.stdout.strip())

    def _terminate(self, pid: int) -> None:
        # Signal the whole process GROUP, not just this pid. socat runs with
        # `fork`, so it forks a child per accepted connection; killing only the
        # listener leaves that child relaying an in-flight RDP session
        # indefinitely -- the port stops accepting while whoever is already
        # connected keeps working, which would make /rdp_off a no-op against an
        # active attacker. _spawn_socat starts socat in its own session, so its
        # pid is also its process-group id and the group cannot reach the bot.
        #
        # SIGTERM first, then poll for the group to drain before escalating to
        # SIGKILL, so the KILL cannot land on a group the OS rebuilt under a
        # recycled pid.
        if not self._is_socat(pid):
            # Already gone, or the pid now belongs to something else entirely.
            # Signalling a whole group on a recycled pid is not a risk worth
            # taking; a dead listener has already stopped relaying.
            return
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except PermissionError:
            raise ForwarderError(f"not permitted to signal process group {pid}")

        for _ in range(_TERMINATE_POLL_ATTEMPTS):
            if not self._group_exists(pid):
                return
            time.sleep(_TERMINATE_POLL_INTERVAL)

        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            raise ForwarderError(f"not permitted to signal process group {pid}")

    @staticmethod
    def _is_socat(pid: int) -> bool:
        """Confirm this pid is still our relay before signalling its group."""
        try:
            return b"socat" in Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return False

    @staticmethod
    def _group_exists(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # Exists but we can't probe it -- treat as still alive so we
            # don't escalate to SIGKILL prematurely.
            return True
        return True
