from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    """Runtime settings.

    Everything except the bot token comes from config.toml. The token comes from
    the environment (SAFE_CONNECT_TELEGRAM_TOKEN) so it never lands in a file
    that could be committed.
    """

    model_config = SettingsConfigDict(env_prefix="SAFE_CONNECT_", extra="forbid")

    telegram_token: SecretStr
    telegram_user_id: int

    vds_public_ip: str
    pc1_tailnet_ip: str
    pc1_ssh_user: str
    pc1_ssh_key_path: Path

    port_range_start: int = 40000
    port_range_end: int = 40100

    connect_grace_seconds: int = 300
    idle_timeout_seconds: int = 600
    hard_cap_seconds: int = 28800
    poll_interval_seconds: int = 30
    hard_cap_warning_seconds: int = 300

    state_path: Path = Path("/var/lib/safe-connect/state.json")
    ufw_port_helper: Path = Path("/usr/local/lib/safe-connect/ufw-port")
    sudo_path: Path = Path("/usr/bin/sudo")
    socat_path: Path = Path("/usr/bin/socat")
    ssh_path: Path = Path("/usr/bin/ssh")
    ss_path: Path = Path("/usr/bin/ss")

    @model_validator(mode="after")
    def _check_port_range(self) -> "Config":
        if self.port_range_start >= self.port_range_end:
            raise ValueError("port_range_start must be below port_range_end")
        if self.port_range_start < 1024:
            raise ValueError("port_range_start must be above 1023 so no privileges are needed")
        return self


def load_config(path: Path) -> Config:
    data = tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    # The token is env-only (SAFE_CONNECT_TELEGRAM_TOKEN): init kwargs take
    # precedence over env vars in pydantic-settings, so a stray key here would
    # silently override the environment. Drop it rather than let that happen.
    data.pop("telegram_token", None)
    return Config(**data)
