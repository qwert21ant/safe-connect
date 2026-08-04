import os
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "deploy" / "ufw-port"


@pytest.fixture
def fake_ufw(tmp_path):
    """A stand-in for ufw that records the argv it was called with."""
    log = tmp_path / "calls.log"
    recorder = tmp_path / "ufw"
    recorder.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$UFW_LOG"\nexit 0\n')
    recorder.chmod(0o755)
    return recorder, log


def run_wrapper(fake_ufw, *args):
    recorder, log = fake_ufw
    env = {**os.environ, "SAFE_CONNECT_UFW": str(recorder), "UFW_LOG": str(log)}
    result = subprocess.run(
        ["/bin/bash", str(WRAPPER), *args], capture_output=True, text=True, env=env
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return result, calls


def test_open_with_single_host_builds_the_expected_ufw_rule(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "open", "40017", "203.0.113.9/32")
    assert result.returncode == 0, result.stderr
    assert calls == ["allow from 203.0.113.9 to any port 40017 proto tcp"]


def test_close_deletes_the_same_rule(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "close", "40017", "203.0.113.9/32")
    assert result.returncode == 0, result.stderr
    assert calls == ["delete allow from 203.0.113.9 to any port 40017 proto tcp"]


def test_any_opens_the_port_to_all_sources(fake_ufw):
    result, calls = run_wrapper(fake_ufw, "open", "40017", "any")
    assert result.returncode == 0, result.stderr
    assert calls == ["allow 40017/tcp"]


@pytest.mark.parametrize(
    "args",
    [
        ("open", "39999", "203.0.113.9/32"),          # below the range
        ("open", "40101", "203.0.113.9/32"),          # above the range
        ("open", "22", "203.0.113.9/32"),             # the SSH port
        ("open", "abc", "203.0.113.9/32"),
        ("open", "40017", "203.0.113.0/24"),          # whole subnets are not allowed
        ("open", "40017", "203.0.113.9"),             # must be an explicit /32
        ("open", "40017", "999.1.1.1/32"),
        ("open", "40017", "203.0.113.9/32; id"),
        ("open", "40017", "-anything"),
        ("flush", "40017", "203.0.113.9/32"),         # unknown action
        ("open", "40017"),                            # too few arguments
        ("open", "40017", "203.0.113.9/32", "extra"),  # too many
        ("open", "40017", "203.008.1.1/32"),          # leading-zero octet (ambiguous octal)
        ("open", "40017", "203.000.1.1/32"),          # leading-zero octet, all zeros
        ("open", "40017", "203.09.1.1/32"),           # leading-zero octet, two digits
    ],
)
def test_invalid_input_is_refused_without_touching_ufw(fake_ufw, args):
    result, calls = run_wrapper(fake_ufw, *args)
    assert result.returncode == 2, f"expected refusal, got {result.returncode}"
    assert calls == []
