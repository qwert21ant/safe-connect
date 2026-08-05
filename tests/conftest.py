import pytest

from bot.forwarder import ForwarderError
from bot.pc1 import AuditReport, PC1Error
from tests.test_forwarder import make_config


class FakeClock:
    def __init__(self, start: float = 1_785_000_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeForwarder:
    def __init__(self) -> None:
        self.started: list[tuple[int, str]] = []
        self.stopped: list[tuple[int | None, int, str]] = []
        self.alive = True
        self.connections = 0
        self.start_failures = 0
        self.next_pid = 4242

    async def start(self, port: int, source: str) -> int:
        if self.start_failures > 0:
            self.start_failures -= 1
            raise ForwarderError(f"could not bind {port}")
        self.started.append((port, source))
        return self.next_pid

    async def stop(self, pid, port, source) -> None:
        self.stopped.append((pid, port, source))
        self.alive = False

    def is_alive(self, pid, port) -> bool:
        return self.alive

    async def established_count(self, port) -> int:
        return self.connections


class FakePC1:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.enable_error: Exception | None = None
        self.disable_error: Exception | None = None
        self.rdp_reachable = True
        self.report = AuditReport(successes=[], failures=[])

    async def enable(self) -> None:
        self.calls.append("enable")
        if self.enable_error:
            raise self.enable_error

    async def disable(self) -> None:
        self.calls.append("disable")
        if self.disable_error:
            raise self.disable_error

    async def probe_rdp(self, timeout: float = 5.0) -> bool:
        self.calls.append("probe")
        return self.rdp_reachable

    async def audit(self, since_epoch: float) -> AuditReport:
        self.calls.append("audit")
        return self.report


class FakeNotifier:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, text: str) -> None:
        self.sent.append(text)


@pytest.fixture
def parts(tmp_path):
    """Everything a SessionManager needs, with a state file under tmp_path."""
    return {
        "config": make_config(state_path=tmp_path / "state.json"),
        "forwarder": FakeForwarder(),
        "pc1": FakePC1(),
        "notifier": FakeNotifier(),
        "clock": FakeClock(),
    }


@pytest.fixture
def manager(parts):
    from bot.session import SessionManager

    return SessionManager(**parts)
