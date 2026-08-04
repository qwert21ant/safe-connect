from pathlib import Path

import pytest

from bot import proc


async def test_captures_stdout_and_returncode():
    result = await proc.run(["/bin/echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"


async def test_nonzero_exit_is_reported_not_raised():
    result = await proc.run(["/bin/false"])
    assert not result.ok
    assert result.returncode != 0


async def test_shell_metacharacters_stay_literal():
    """The whole point of argv lists: this must print the text, not run `id`."""
    result = await proc.run(["/bin/echo", "; id && rm -rf /"])
    assert result.stdout.strip() == "; id && rm -rf /"


async def test_timeout_kills_the_child():
    with pytest.raises(proc.ProcTimeout):
        await proc.run(["/bin/sleep", "5"], timeout=0.2)


async def test_empty_argv_is_rejected():
    with pytest.raises(ValueError):
        await proc.run([])


def test_no_module_in_bot_uses_shell_true():
    """A standing guard, not a one-off check. Re-run for the life of the project."""
    root = Path(__file__).resolve().parents[1] / "bot"
    offenders = [p.name for p in root.rglob("*.py") if "shell=True" in p.read_text()]
    assert offenders == []
