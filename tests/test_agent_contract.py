"""Guards the agent's side of the JSON contract without a Windows host.

These assertions are deliberately about the script's text: they catch the
mistakes that would silently break PC1Client — a renamed verb, a dropped
whitelist, a stray Write-Host that corrupts stdout.
"""
import re
from pathlib import Path

import pytest

AGENT = Path(__file__).resolve().parents[1] / "agent" / "agent.ps1"


@pytest.fixture(scope="module")
def source() -> str:
    return AGENT.read_text(encoding="utf-8")


def test_every_verb_the_client_sends_is_handled(source):
    for verb in ("enable", "disable", "status", "audit"):
        assert re.search(rf"^\s*'{verb}'", source, re.MULTILINE), f"no branch for {verb}"


def test_unknown_verbs_fall_through_to_a_refusal(source):
    assert "default" in source
    assert "unknown verb" in source


def test_the_command_is_matched_against_a_whitelist_not_invoked(source):
    """A stolen key must not be able to reach Invoke-Expression."""
    assert "Invoke-Expression" not in source
    assert "iex " not in source
    assert "SSH_ORIGINAL_COMMAND" in source


def test_it_creates_a_scoped_rule_and_never_enables_the_builtin_group(source):
    assert "SafeConnect-RDP-In" in source
    # Split into independent assertions (equivalent to `or` -> `and`) so this
    # genuinely discriminates: the reference implementation never calls
    # Enable-NetFirewallRule at all (it uses New-/Set-NetFirewallRule with
    # -Enabled True on our own scoped rule), so a stray call to the cmdlet
    # that is capable of switching on the built-in group is caught outright,
    # not just the case where both substrings happen to co-occur.
    assert "Enable-NetFirewallRule" not in source
    assert "RemoteDesktop" not in source


def test_the_firewall_rule_is_scoped_to_the_vds_address(source):
    assert "RemoteAddress" in source


def test_nothing_writes_to_stdout_except_the_json_reply(source):
    """Write-Host would corrupt the response PC1Client parses."""
    assert "Write-Host" not in source
    assert source.count("ConvertTo-Json") >= 1
