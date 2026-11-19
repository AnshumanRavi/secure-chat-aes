"""
The crypto benchmark runs end to end on a tiny workload and produces its CSVs and graphs.
(The real results in performance/results are not touched - everything goes to a temp folder.)
"""

import csv

import pytest

from performance import benchmark_crypto as bench


@pytest.fixture
def tiny(tmp_path, monkeypatch):
    monkeypatch.setattr(bench, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(bench, "GRAPHS", tmp_path / "graphs")
    monkeypatch.setattr(bench, "SIZES", [16, 1024])
    monkeypatch.setattr(bench, "PBKDF2_ROUNDS", [1_000, bench.CHOSEN_ROUNDS])
    return tmp_path


def test_measure_reports_mean_and_std():
    result = bench.measure(lambda: sum(range(1000)), iterations=50, warmup=5)
    assert result["mean"] > 0 and result["std"] >= 0
    assert result["rss_mb"] > 0


def test_overhead_matches_each_mode(tiny):
    rows = bench.bench_aes(iterations=3, warmup=1)
    assert len(rows) == len(bench.MODES) * len(bench.KEY_BITS) * 2
    at_1kb = {r["mode"]: r["overhead_bytes"] for r in rows if r["size_bytes"] == 1024 and r["key_bits"] == 256}
    # 1 KB is block-aligned, so PKCS#7 adds a whole 16-byte block
    assert at_1kb == {"GCM": 12 + 16, "CBC+HMAC": 16 + 16 + 32, "CTR": 8, "ECB": 16}


def test_full_pipeline_writes_csvs_and_graphs(tiny, capsys):
    aes = bench.bench_aes(iterations=3, warmup=1)
    handshake = bench.bench_handshake(iterations=3)
    pbkdf2 = bench.bench_pbkdf2(quick=True)
    resources = bench.bench_resources(0.05)
    for name, rows in (("aes_modes.csv", aes), ("handshake.csv", handshake),
                       ("pbkdf2.csv", pbkdf2), ("resources.csv", resources)):
        bench.write_csv(name, rows)
    bench.print_summary(aes, handshake, pbkdf2, resources)
    assert "SUMMARY" in capsys.readouterr().out

    graphs = bench.make_graphs()
    assert len(graphs) == 7
    assert all(p.exists() and p.stat().st_size > 10_000 for p in graphs)

    with open(tiny / "results" / "pbkdf2.csv", encoding="utf-8") as f:
        rounds = [int(r["rounds"]) for r in csv.DictReader(f)]
    assert rounds == [1_000, bench.CHOSEN_ROUNDS]
