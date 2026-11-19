"""Shared pytest fixtures."""

import pytest

from common.config import Config
from server.security_log import SecurityLog
from server.server import ChatServer


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A real ChatServer on a random free port, with its own temporary keys, database and logs."""
    tmp = tmp_path_factory.mktemp("server")
    srv = ChatServer(Config(server_host="127.0.0.1", port=0), keys_dir=tmp / "keys",
                     db_path=tmp / "server.db", log=SecurityLog(tmp / "logs", console=False),
                     passphrase="test-passphrase")
    srv.start_in_background()
    yield srv
    srv.stop()
