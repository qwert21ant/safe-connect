from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

from bot import proc
from bot.config import Config
from bot.proc import ProcTimeout

log = logging.getLogger(__name__)

RDP_PORT = 3389
_LISTEN_POLL_INTERVAL = 0.1
_LISTEN_POLL_ATTEMPTS = 20
_TERMINATE_POLL_INTERVAL = 0.05
_TERMINATE_POLL_ATTEMPTS = 10  # ~0.5s of grace after SIGTERM before SIGKILL
_REAP_TIMEOUT = 5.0  # bound on waiting for a signalled socat to actually exit
_STDERR_TAIL_BYTES = 4096


async def _drain_stderr(stream: asyncio.StreamReader) -> bytes:
    """Keep socat's stderr pipe from filling and blocking it, for as long as it runs.

    stderr=PIPE with nobody reading it risks a chatty socat blocking on a
    full pipe once the kernel buffer fills. This drains it continuously and
    keeps only the last _STDERR_TAIL_BYTES, which _finish_drain() surfaces
    for diagnostics if socat exits unexpectedly -- previously that text was
    discarded entirely, leaving /rdp_on failures with only a bare exit code.
    Cancellation (the normal way this is stopped, once the process is
    reaped) is caught and turned into a normal return rather than left to
    propagate, so callers always get a result instead of having to handle
    CancelledError themselves.
    """
    tail = bytearray()
    try:
        while True:
            chunk = await stream.read(_STDERR_TAIL_BYTES)
            if not chunk:
                return bytes(tail[-_STDERR_TAIL_BYTES:])
            tail.extend(chunk)
            del tail[:-_STDERR_TAIL_BYTES]
    except asyncio.CancelledError:
        return bytes(tail[-_STDERR_TAIL_BYTES:])


async def _finish_drain(drain: "asyncio.Task[bytes]") -> bytes:
    """Stop a drain task and collect what it saw. Never raises."""
    if not drain.done():
        drain.cancel()
    try:
        return await drain
    except asyncio.CancelledError:
        return b""


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
        self._stderr_drains: dict[int, "asyncio.Task[bytes]"] = {}

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
                    #
                    # Bounded: this sits between _terminate() (which already
                    # signalled the group, up to and including SIGKILL) and
                    # the ufw close below, which the comment above promises
                    # runs on every path. An unbounded wait() here would
                    # silently break that promise if the process ever failed
                    # to actually exit after SIGKILL (e.g. stuck in
                    # uninterruptible sleep) -- the ufw close must not be
                    # held hostage by that.
                    try:
                        await asyncio.wait_for(process.wait(), _REAP_TIMEOUT)
                    except asyncio.TimeoutError:
                        log.warning(
                            "socat pid %s did not exit within %ss of being "
                            "signalled; closing the ufw rule anyway", pid, _REAP_TIMEOUT,
                        )
                drain = self._stderr_drains.pop(pid, None)
                if drain is not None:
                    await _finish_drain(drain)
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
        # Drains stderr for socat's whole life so a chatty socat can never
        # block on a full pipe (stderr=PIPE with nobody reading it). Started
        # unconditionally, right after spawn, so it is also there to capture
        # socat's own diagnostic text if it exits immediately below.
        drain = asyncio.ensure_future(_drain_stderr(process.stderr))
        try:
            for _ in range(_LISTEN_POLL_ATTEMPTS):
                await asyncio.sleep(_LISTEN_POLL_INTERVAL)
                if process.returncode is not None:
                    detail = (await _finish_drain(drain)).decode(errors="replace").strip()
                    suffix = f": {detail}" if detail else ""
                    raise ForwarderError(f"socat exited immediately with {process.returncode}{suffix}")
                if await self._is_listening(port):
                    self._processes[process.pid] = process
                    self._stderr_drains[process.pid] = drain
                    return process.pid
            raise ForwarderError(f"socat did not listen on {port} within 2s")
        except Exception:
            # Whatever raised -- "did not listen", "exited immediately", or
            # something escaping _is_listening() (e.g. a ForwarderError
            # wrapping ProcTimeout from a wedged ss) -- the process this
            # function already spawned must not outlive this function.
            # Without this, only the "did not listen" path used to clean up;
            # any other exception left an unsupervised socat holding a port
            # in the configured range with nothing in state.json pointing at
            # it, invisible to reconcile() and every timer.
            self._terminate(process.pid)
            await process.wait()  # reap it now; see stop()'s comment on why
            await _finish_drain(drain)
            raise

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
        #
        # The refusal below must fire ONLY for genuine pid reuse: a real,
        # different process -- with actual argv -- sits at this pid. It must
        # NOT fire just because the listener itself is gone or has died but
        # not yet been reaped -- socat runs with `fork`, so a listener that
        # already exited (crashed, was SIGKILLed by something else) can
        # still have live forked children relaying an in-flight connection,
        # and is_alive()/tick()/reconcile() have no other path to reach them
        # than this one. Linux will not recycle a pid number while any live
        # task -- including one of those orphaned children, or the dead
        # listener itself sitting as an unreaped zombie -- still references
        # it as its process-group id, so a non-empty group behind a vanished
        # or zombified leader pid can only be our own children, never an
        # unrelated process that reused the number. Treating "gone" the same
        # as "reused" (as `if not self._is_socat(pid): return` used to) is
        # exactly the pid-reuse guard defeating the fix it exists to guard.
        #
        # An earlier version of this fix distinguished "gone" from "reused"
        # by separately checking /proc/<pid>/stat's state field for zombie
        # status. That raced: a listener we just SIGKILLed can have its
        # cmdline already cleared (read #1, via _is_socat, sees "empty" --
        # looks gone) while /proc/<pid>/stat still transiently reports a
        # non-zombie state a few microseconds longer (read #2 sees "live"),
        # because the kernel does not clear a dying task's mm and flip its
        # exit state atomically. Two DIFFERENT proc files, read at two
        # different instants, described two different moments of the same
        # death and together looked exactly like "pid already reused by a
        # live process" -- reproduced empirically via
        # test_stop_reaps_forked_children_when_the_listener_died_first in
        # tests/test_forwarder_integration.py, which hung on exactly this
        # under real socat. cmdline alone does not have that problem:
        # emptiness is monotonic for a single
        # process's lifetime (it goes non-empty -> empty exactly once, never
        # back), so reading it twice (once for identity, once for
        # emptiness) cannot disagree with itself the way stat-vs-cmdline did.
        if not self._is_socat(pid) and not self._cmdline_is_empty(pid):
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
    def _cmdline_is_empty(pid: int) -> bool:
        """True once this pid's argv is gone -- zombie, fully reaped, or gone.

        A zombie's /proc/<pid>/cmdline reads back as empty bytes, the same as
        a fully-reaped pid raising OSError; both are treated identically
        here (and both are safe to treat as "still ours, proceed") since
        pid reuse cannot happen until a zombie is actually reaped.
        """
        try:
            return not Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return True

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
