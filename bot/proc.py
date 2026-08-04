from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class ProcTimeout(RuntimeError):
    """The child did not finish within the allotted time and was killed."""


async def run(argv: Sequence[str], timeout: float = 30.0) -> Result:
    """Run argv with no shell involved.

    There is deliberately no `shell` parameter. Every argument reaches the child
    verbatim, so operator-supplied text cannot become syntax.
    """
    if not argv:
        raise ValueError("argv must not be empty")
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.wait()
        raise ProcTimeout(f"timed out after {timeout}s: {argv[0]}") from exc
    return Result(
        returncode=process.returncode or 0,
        stdout=out.decode(errors="replace"),
        stderr=err.decode(errors="replace"),
    )
