"""
The network benchmark runs end to end on a tiny workload (real servers in a child process,
worker processes for the scalability test) and produces its CSVs and graphs in a temp folder.
"""

import json
import socket

import pytest

from performance import benchmark_network as bench
from security_demo.insecure_chat import InsecureServer

TINY = {"iterations": 5, "warmup": 1, "burst": 20, "seconds": 0.3, "file_repeats": 1, "connects": 2}


def _plain_client(port, name):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    return sock, sock.makefile("r", encoding="utf-8")


def _send(sock, **message):
    sock.sendall((json.dumps(message) + "\n").encode())


def test_insecure_server_routes_by_name_and_still_broadcasts():
    server = InsecureServer(0, host="127.0.0.1", verbose=False).start_in_background()
    try:
        alice, alice_in = _plain_client(server.port, "alice")
        bob, bob_in = _plain_client(server.port, "bob")
        _send(bob, **{"from": "bob", "to": "bob", "id": "hello"})          # bob registers his name
        assert json.loads(bob_in.readline())["id"] == "hello"
        _send(alice, **{"from": "alice", "to": "alice", "id": "self"})     # addressed: only to alice
        assert json.loads(alice_in.readline())["id"] == "self"
        _send(alice, **{"from": "alice", "text": "everyone"})              # no "to": everybody else
        assert json.loads(bob_in.readline())["text"] == "everyone"
        alice.close()
        bob.close()
    finally:
        server.stop()


@pytest.fixture
def tiny(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(bench, "GRAPHS", tmp_path / "graphs")
    monkeypatch.setattr(bench, "TEXT_SIZES", [16, 1024])
    monkeypatch.setattr(bench, "THROUGHPUT_SIZES", [1024])
    monkeypatch.setattr(bench, "CLIENT_COUNTS", [1, 3])
    monkeypatch.setattr(bench, "FILE_SIZES_MB", [1])
    monkeypatch.setattr(bench, "WORKER_PROCESSES", 2)
    return tmp_path


def test_full_pipeline_on_localhost(tiny, capsys):
    proc, ports = bench.start_local_servers()
    try:
        server_env = bench.server_stats("127.0.0.1", ports["stats"])["env"]
        bench.run("127.0.0.1", ports, "localhost", TINY, server_env)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert "SUMMARY" in capsys.readouterr().out

    results = tiny / "results"
    for kind in ("connect", "latency", "throughput", "scalability", "files"):
        assert (results / f"network_localhost_{kind}.csv").exists()
    latency = bench.read_csv("network_localhost_latency.csv", results)
    assert {r["system"] for r in latency} == {"secure", "plain"}
    assert all(r["mean_ms"] > 0 for r in latency)
    scaling = bench.read_csv("network_localhost_scalability.csv", results)
    assert [r["clients"] for r in scaling] == [1, 1, 3, 3]
    assert all(r["messages"] > 0 for r in scaling)

    graphs = bench.make_graphs("localhost")
    assert len(graphs) == 4                                  # no LAN run yet -> no comparison graph
    assert all(p.exists() and p.stat().st_size > 10_000 for p in graphs)
