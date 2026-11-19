"""common/config.py: defaults, config.json, command-line overrides."""

import json

from common.config import Config, build_arg_parser, load_config


def write_config(tmp_path, data) -> str:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_defaults_when_the_file_is_missing(tmp_path):
    cfg = load_config(["--config", str(tmp_path / "missing.json")])
    assert cfg == Config()
    assert cfg.port == 5555 and cfg.max_clock_skew == 60


def test_file_values_and_unknown_keys(tmp_path):
    path = write_config(tmp_path, {"port": 6000, "session_timeout": 99, "not_a_setting": True})
    cfg = load_config(["--config", path])
    assert cfg.port == 6000 and cfg.session_timeout == 99
    assert not hasattr(cfg, "not_a_setting")             # unknown keys are ignored, not an error


def test_host_flag_depends_on_the_role(tmp_path):
    path = write_config(tmp_path, {})
    assert load_config(["--config", path, "--host", "10.0.0.5"], role="server").server_host == "10.0.0.5"
    client = load_config(["--config", path, "--host", "10.0.0.5"], role="client")
    assert client.client_host == "10.0.0.5" and client.server_host == "0.0.0.0"


def test_port_flag_overrides_the_file_and_other_flags_are_ignored(tmp_path):
    path = write_config(tmp_path, {"port": 6000})
    cfg = load_config(["--config", path, "--port", "7000", "--quiet", "--show-bodies"])
    assert cfg.port == 7000


def test_to_dict_and_parser():
    assert Config().to_dict()["port"] == 5555
    args = build_arg_parser("x").parse_args(["--host", "h", "--port", "1"])
    assert (args.host, args.port) == ("h", 1)
