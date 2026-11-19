"""
The performance report is built only from saved results - with or without a two-PC run.
Uses copies of the real results in a temp folder, so performance/ is not touched.
"""

import shutil

import pytest

from performance import make_report

REAL_RESULTS = make_report.RESULTS
NEEDED = ["aes_modes.csv", "handshake.csv", "pbkdf2.csv", "resources.csv", "environment.json"]
NETWORK = ["connect", "latency", "throughput", "scalability", "files"]


@pytest.fixture
def results(tmp_path, monkeypatch):
    if not all((REAL_RESULTS / name).exists() for name in NEEDED + ["network_localhost_latency.csv"]):
        pytest.skip("run the benchmarks first")
    folder = tmp_path / "results"
    folder.mkdir()
    for path in REAL_RESULTS.iterdir():
        if path.suffix in (".csv", ".json") and not path.name.startswith("network_lan_"):
            shutil.copy(path, folder / path.name)
    monkeypatch.setattr(make_report, "RESULTS", folder)
    return folder


def test_report_without_lan_says_so(results):
    report = make_report.build()
    for heading in ("## 1. Objective", "## 2. Test environment", "## 3. Methodology", "## 4. Results",
                    "## 5. Analysis", "## 6. Limitations", "## 7. Conclusion"):
        assert heading in report
    assert "Two PCs over the LAN - not run yet" in report
    assert "No two-PC results yet" in report
    assert "graphs/network_localhost_latency.png" in report
    assert "network_localhost_vs_lan.png" not in report


def test_report_with_lan_includes_it(results):
    for kind in NETWORK:       # stand-in LAN data: the same files under the LAN name
        shutil.copy(results / f"network_localhost_{kind}.csv", results / f"network_lan_{kind}.csv")
    shutil.copy(results / "network_localhost_environment.json", results / "network_lan_environment.json")
    report = make_report.build()
    assert "### 4.8 Network: two PCs over the LAN" in report
    assert "graphs/network_localhost_vs_lan.png" in report
    assert "not run yet" not in report


def test_every_embedded_graph_exists(results):
    report = make_report.build()
    graphs = [line.split("](")[1].rstrip(")") for line in report.splitlines() if line.startswith("![")]
    assert graphs
    for graph in graphs:
        assert (make_report.ROOT / graph).exists(), graph
