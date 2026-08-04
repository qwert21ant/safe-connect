from pathlib import Path

import pytest

from bot.config import Config, load_config

MINIMAL = """
telegram_user_id = 12345
vds_public_ip = "198.51.100.7"
pc1_tailnet_ip = "100.101.102.103"
pc1_ssh_user = "rdpadmin"
pc1_ssh_key_path = "/var/lib/safe-connect/id_ed25519"
"""


def write_cfg(tmp_path: Path, body: str = MINIMAL) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def test_loads_toml_and_takes_token_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert cfg.telegram_user_id == 12345
    assert cfg.telegram_token.get_secret_value() == "123:ABC"


def test_defaults_match_the_spec(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert (cfg.port_range_start, cfg.port_range_end) == (40000, 40100)
    assert cfg.connect_grace_seconds == 300
    assert cfg.idle_timeout_seconds == 600
    assert cfg.hard_cap_seconds == 28800
    assert cfg.poll_interval_seconds == 30


def test_token_is_not_exposed_by_repr(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    cfg = load_config(write_cfg(tmp_path))
    assert "123:ABC" not in repr(cfg)


def test_rejects_inverted_port_range(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    body = MINIMAL + "\nport_range_start = 40100\nport_range_end = 40000\n"
    with pytest.raises(ValueError, match="port_range_start"):
        load_config(write_cfg(tmp_path, body))


def test_rejects_unknown_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "123:ABC")
    with pytest.raises(ValueError):
        load_config(write_cfg(tmp_path, MINIMAL + '\nnonsense = "x"\n'))


def test_a_token_in_the_toml_file_cannot_override_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFE_CONNECT_TELEGRAM_TOKEN", "from-env")
    body = MINIMAL + '\ntelegram_token = "from-toml"\n'
    cfg = load_config(write_cfg(tmp_path, body))
    assert cfg.telegram_token.get_secret_value() == "from-env"
