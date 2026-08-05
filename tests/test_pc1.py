import json

import pytest

from bot.pc1 import AuditReport, PC1Client, PC1Error
from bot.proc import Result
from tests.test_forwarder import FakeRunner, make_config


def ssh_argv(verb: str) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-i", "/tmp/key",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-o", "IdentitiesOnly=yes",
        "rdpadmin@100.101.102.103",
        verb,
    ]


async def test_enable_sends_only_the_verb():
    runner = FakeRunner([Result(0, json.dumps({"ok": True}), "")])
    await PC1Client(make_config(), runner=runner).enable()
    assert runner.calls[0] == ssh_argv("enable")


async def test_disable_sends_only_the_verb():
    runner = FakeRunner([Result(0, json.dumps({"ok": True}), "")])
    await PC1Client(make_config(), runner=runner).disable()
    assert runner.calls[0] == ssh_argv("disable")


async def test_status_reports_whether_rdp_is_enabled():
    runner = FakeRunner([Result(0, json.dumps({"ok": True, "rdp_enabled": True}), "")])
    assert await PC1Client(make_config(), runner=runner).status() is True


async def test_ssh_failure_raises_pc1_error():
    runner = FakeRunner([Result(255, "", "ssh: connect to host ... No route to host")])
    with pytest.raises(PC1Error, match="No route to host"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_agent_reporting_failure_raises_pc1_error():
    runner = FakeRunner([Result(0, json.dumps({"ok": False, "error": "access denied"}), "")])
    with pytest.raises(PC1Error, match="access denied"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_unparseable_agent_output_raises_pc1_error():
    runner = FakeRunner([Result(0, "not json at all", "")])
    with pytest.raises(PC1Error, match="unparseable"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_audit_parses_logon_events():
    payload = {
        "ok": True,
        "successes": [{"time": "2026-08-04T18:02:11", "user": "rdpuser", "source_ip": "203.0.113.9"}],
        "failures": [{"time": "2026-08-04T18:01:40", "user": "administrator", "source_ip": "203.0.113.9"}],
    }
    runner = FakeRunner([Result(0, json.dumps(payload), "")])
    report = await PC1Client(make_config(), runner=runner).audit(1785000000.0)

    assert isinstance(report, AuditReport)
    assert len(report.successes) == 1 and len(report.failures) == 1
    assert report.successes[0].user == "rdpuser"
    assert report.failures[0].source_ip == "203.0.113.9"
    assert runner.calls[0][-1] == "audit 1785000000"


async def test_probe_rdp_is_false_when_nothing_listens():
    client = PC1Client(make_config(pc1_tailnet_ip="127.0.0.1"), runner=FakeRunner())
    assert await client.probe_rdp(timeout=0.3) is False


@pytest.mark.parametrize(
    "invalid_json",
    ["null", "3", "[1,2,3]", '"hello"'],
)
async def test_non_dict_json_response_raises_pc1_error(invalid_json: str):
    runner = FakeRunner([Result(0, invalid_json, "")])
    with pytest.raises(PC1Error, match="unparseable"):
        await PC1Client(make_config(), runner=runner).enable()


async def test_audit_rejects_nan_epoch():
    client = PC1Client(make_config(), runner=FakeRunner())
    with pytest.raises(PC1Error):
        await client.audit(float("nan"))


async def test_audit_rejects_infinity_epoch():
    client = PC1Client(make_config(), runner=FakeRunner())
    with pytest.raises(PC1Error):
        await client.audit(float("inf"))
