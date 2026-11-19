"""
Network benchmarks: SecureChat (encrypted) vs the deliberately insecure plaintext chat.

On one PC - both servers are started automatically in a separate process:
    python -m performance.benchmark_network              # full run (~2 minutes)
    python -m performance.benchmark_network --quick      # ~30 seconds

Across two PCs on the same Wi-Fi / LAN:
    PC 1 (server):  python -m performance.benchmark_network --serve
    PC 2 (client):  python -m performance.benchmark_network --remote 192.168.1.20

    python -m performance.benchmark_network --graphs-only    # redraw graphs from the saved CSVs

How it is measured
------------------
Every simulated user sends messages to ITSELF, so each measurement is one complete trip
client → server → client, timed on one clock (no need to synchronise two PCs' clocks).

* SecureChat:  the real ChatServer and ChatClient. On the way the message is AES-256-GCM
  encrypted by the client, decrypted + checked (tag, sequence number, timestamp) by the
  server, re-encrypted for the recipient and decrypted again - plus the ACK/DELIVERED receipts.
* Plaintext:   the insecure demo chat (security_demo/insecure_chat.py) - one JSON line per
  message, relayed as-is. Same TCP, same JSON, same base64 file chunks - just no security.

Tests: round-trip latency per message size, throughput (messages/s, MB/s), scalability with
1-50 concurrent clients (latency + server CPU), file transfer speed, and connection set-up time.
Results: performance/results/network_<localhost|lan>_*.csv   Graphs: performance/graphs/network_*.png
"""

import argparse
import base64
import hashlib
import json
import multiprocessing
import os
import random
import shutil
import socket
import statistics
import string
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional

import psutil

from client.network import ChatClient
from common.config import PROJECT_ROOT, Config
from common.protocol import client_handshake
from performance import environment
from performance import plot_style as ps
from performance.benchmark_crypto import read_csv, write_csv

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
GRAPHS = ROOT / "graphs"

DEFAULT_PORT = 5600                       # --serve listens on 5600 (secure), 5601 (plain), 5602 (stats)
TEXT_SIZES = [16, 64, 256, 1024, 4096, 8192]    # characters per chat message (server limit: 10,000)
THROUGHPUT_SIZES = [64, 1024, 8192]
CLIENT_COUNTS = [1, 5, 10, 25, 50]
FILE_SIZES_MB = [1, 10, 25]               # 25 MB is SecureChat's maximum file size
SYSTEMS = ["secure", "plain"]
PASSWORD = "BenchPassw0rd!"
MB = 2 ** 20
CHUNK = 64 * 1024                         # same chunk size as SecureChat's file transfer
WORKER_PROCESSES = 8                      # simulated clients are spread over this many processes

FULL = {"iterations": 500, "warmup": 20, "burst": 2000, "seconds": 3.0, "file_repeats": 3, "connects": 20}
QUICK = {"iterations": 50, "warmup": 5, "burst": 300, "seconds": 1.0, "file_repeats": 1, "connects": 5}

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")


# ======================================================================= server side
class StatsServer:
    """Tells the benchmark the server process's CPU time and memory (so server CPU % can be
    measured from the other PC too). Every connection gets one JSON reply and is closed."""

    def __init__(self, host: str, port: int):
        self.listener = socket.create_server((host, port))
        self.port = self.listener.getsockname()[1]
        self.process = psutil.Process()
        self.env = environment.collect()

    def start(self) -> "StatsServer":
        threading.Thread(target=self._loop, daemon=True).start()
        return self

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                cpu = self.process.cpu_times()
                conn.sendall(json.dumps({"cpu_s": cpu.user + cpu.system, "wall": time.perf_counter(),
                                         "rss_mb": self.process.memory_info().rss / MB,
                                         "cores": psutil.cpu_count(), "env": self.env}).encode())


def serve(bind: str, base_port: int) -> None:
    """Run the SecureChat server, the plaintext server and the stats server until Ctrl+C."""
    from security_demo.insecure_chat import InsecureServer
    from server.security_log import SecurityLog
    from server.server import ChatServer, get_lan_ips

    ports = [0, 0, 0] if base_port == 0 else [base_port, base_port + 1, base_port + 2]
    folder = Path(tempfile.mkdtemp(prefix="securechat-bench-"))     # throwaway keys + database
    log = SecurityLog(folder / "logs", console=False, show_traffic=False)
    secure = ChatServer(Config(server_host=bind, port=ports[0], session_timeout=3600),
                        keys_dir=folder / "keys", db_path=folder / "server.db", log=log, passphrase="benchmark")
    secure.start_in_background()
    plain = InsecureServer(ports[1], host=bind, verbose=False).start_in_background()
    stats = StatsServer(bind, ports[2]).start()

    if base_port:
        print("SecureChat network benchmark - SERVER side")
        print(f"  SecureChat server (AES-256-GCM)  port {secure.port}")
        print(f"  Plaintext server  (insecure)     port {plain.port}")
        print(f"  Stats (CPU / memory)             port {stats.port}")
        ips = get_lan_ips() if bind == "0.0.0.0" else [bind]
        for ip in ips:
            print(f"  On the other PC run:  python -m performance.benchmark_network --remote {ip}"
                  + ("" if base_port == DEFAULT_PORT else f" --port {base_port}"))
        print("  (Allow Python through the Windows firewall if asked. Ctrl+C to stop.)")
    print("READY " + json.dumps({"secure": secure.port, "plain": plain.port, "stats": stats.port}), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        plain.stop()
        secure.stop()
        shutil.rmtree(folder, ignore_errors=True)


def start_local_servers():
    """Start the servers in a child process, so the server's CPU use is measured on its own."""
    proc = subprocess.Popen([sys.executable, "-u", "-m", "performance.benchmark_network", "--serve",
                             "--bind", "127.0.0.1", "--port", "0"],
                            cwd=PROJECT_ROOT, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        if line.startswith("READY "):
            return proc, json.loads(line[6:])
    raise RuntimeError("The benchmark servers did not start")


def server_stats(host: str, port: int) -> dict:
    with socket.create_connection((host, port), timeout=10) as sock:
        data = b"".join(iter(lambda: sock.recv(65536), b""))
    return json.loads(data)


# ======================================================================= simulated users
class Endpoint:
    """One simulated user. Its receiver thread records when each of its messages comes back."""
    system = ""

    def __init__(self, host: str, port: int, folder: Path):
        self.host, self.port, self.folder = host, port, folder
        self.name = ""
        self.errors: Dict[str, str] = {}
        self._cond = threading.Condition()
        self._arrived: Dict[str, float] = {}

    def _arrive(self, key: str) -> None:
        now = time.perf_counter()
        with self._cond:
            self._arrived[key] = now
            self._cond.notify_all()

    def wait(self, key: str, timeout: float = 120) -> float:
        """Block until message `key` is back; returns its arrival time (perf_counter)."""
        with self._cond:
            if not self._cond.wait_for(lambda: key in self._arrived, timeout):
                raise TimeoutError(f"{self.system}: message {key} did not come back within {timeout} s")
            return self._arrived.pop(key)

    def wait_count(self, count: int, timeout: float = 300) -> float:
        """Block until `count` messages are back; returns when the last one arrived."""
        with self._cond:
            if not self._cond.wait_for(lambda: len(self._arrived) >= count, timeout):
                raise TimeoutError(f"{self.system}: only {len(self._arrived)}/{count} messages came back")
            last = max(self._arrived.values())
            self._arrived.clear()
            return last

    def roundtrip(self, msg_id: str, text: str) -> float:
        start = time.perf_counter()
        self.send(msg_id, text)
        return self.wait(msg_id) - start

    def send_file_and_wait(self, path: Path) -> float:
        file_id = uuid.uuid4().hex
        start = time.perf_counter()
        self.send_file(path, file_id)
        elapsed = self.wait(file_id) - start
        if file_id in self.errors:
            raise RuntimeError(f"{self.system} file transfer failed: {self.errors[file_id]}")
        return elapsed


class SecureEndpoint(Endpoint):
    """A real SecureChat client (TCP + RSA/HKDF handshake + AES-256-GCM for every packet)."""
    system = "secure"

    def open(self, name: Optional[str] = None) -> "SecureEndpoint":
        self.client = ChatClient(self.host, self.port, heartbeat_interval=0, timeout=60)
        self.client.download_dir = self.folder
        self.client.on("message", lambda message: self._arrive(message["id"]))
        self.client.on("file_done", self._file_done)
        self.client.connect()
        self.client.register(name or f"b_{uuid.uuid4().hex[:8]}", PASSWORD)
        self.name = self.client.username
        return self

    def _file_done(self, result: dict) -> None:
        if result["ok"]:
            Path(result["path"]).unlink(missing_ok=True)
        else:
            self.errors[result["id"]] = result["error"]
        self._arrive(result["id"])

    def send(self, msg_id: str, text: str) -> None:
        self.client.send_message(self.name, text, msg_id)

    def send_file(self, path: Path, file_id: str) -> None:
        self.client.send_file(path, to=self.name, kind="document", msg_id=file_id)

    def close(self) -> None:
        self.client.logout()


class PlainEndpoint(Endpoint):
    """A client of the insecure chat: JSON lines over plain TCP. Files are sent like SecureChat
    sends them (SHA-256, 64 KB base64 chunks, verified on arrival) - only without encryption."""
    system = "plain"

    def open(self, name: Optional[str] = None) -> "PlainEndpoint":
        self.name = name or f"p_{uuid.uuid4().hex[:8]}"
        self.sock = socket.create_connection((self.host, self.port), timeout=60)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(None)
        self._incoming: Dict[str, dict] = {}
        threading.Thread(target=self._reader, daemon=True).start()
        return self

    def _line(self, message: dict) -> None:
        self.sock.sendall((json.dumps(dict(message, **{"from": self.name, "to": self.name})) + "\n").encode())

    def send(self, msg_id: str, text: str) -> None:
        self._line({"id": msg_id, "text": text})

    def send_file(self, path: Path, file_id: str) -> None:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(MB), b""):
                sha256.update(block)
        self._line({"type": "file_start", "id": file_id, "size": path.stat().st_size, "sha256": sha256.hexdigest()})
        with open(path, "rb") as f:
            for index, data in enumerate(iter(lambda: f.read(CHUNK), b"")):
                self._line({"type": "file_chunk", "id": file_id, "index": index,
                            "data": base64.b64encode(data).decode("ascii")})
        self._line({"type": "file_end", "id": file_id})

    def _reader(self) -> None:
        try:
            for line in self.sock.makefile("rb"):
                message = json.loads(line)
                kind, msg_id = message.get("type"), message["id"]
                if kind is None:
                    self._arrive(msg_id)
                elif kind == "file_start":
                    part = self.folder / f"{msg_id}.part"
                    self._incoming[msg_id] = {"path": part, "handle": open(part, "wb"),
                                              "sha256": hashlib.sha256(), "expected": message["sha256"]}
                elif kind == "file_chunk":
                    state = self._incoming[msg_id]
                    data = base64.b64decode(message["data"])
                    state["handle"].write(data)
                    state["sha256"].update(data)
                elif kind == "file_end":
                    state = self._incoming.pop(msg_id)
                    state["handle"].close()
                    state["path"].unlink(missing_ok=True)
                    if state["sha256"].hexdigest() != state["expected"]:
                        self.errors[msg_id] = "SHA-256 mismatch"
                    self._arrive(msg_id)
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


ENDPOINTS = {"secure": SecureEndpoint, "plain": PlainEndpoint}


def text_of(size: int) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=size))


def describe(samples: List[float]) -> Dict[str, float]:
    ordered = sorted(samples)
    return {"mean_ms": statistics.fmean(samples) * 1e3,
            "std_ms": (statistics.stdev(samples) if len(samples) > 1 else 0.0) * 1e3,
            "median_ms": statistics.median(samples) * 1e3,
            "p95_ms": ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))] * 1e3}


# ======================================================================= tests
def test_connect(host: str, ports: dict, params: dict, folder: Path) -> List[Dict]:
    print(f"\n1/5  Connection set-up ({params['connects']} connections each)")
    # Sockets are opened WITHOUT a timeout here: on Windows a connect with a timeout waits in
    # select(), which randomly adds one 15.6 ms timer tick - noise that has nothing to do with security.
    user = SecureEndpoint(host, ports["secure"], folder).open()
    user.close()
    tcp, handshake, login = [], [], []
    for i in range(params["connects"] + 1):                # first round = warm-up, not recorded
        start = time.perf_counter()
        socket.create_connection((host, ports["plain"])).close()
        if i:
            tcp.append(time.perf_counter() - start)
    for i in range(params["connects"] + 1):
        start = time.perf_counter()
        sock = socket.create_connection((host, ports["secure"]))
        client_handshake(sock).close()
        if i:
            handshake.append(time.perf_counter() - start)
    for i in range(params["connects"] + 1):
        client = ChatClient(host, ports["secure"], heartbeat_interval=0, timeout=60)
        client.connect()
        start = time.perf_counter()
        client.login(user.name, PASSWORD)
        if i:
            login.append(time.perf_counter() - start)
        client.logout()
        time.sleep(0.05)                                   # let the server finish the logout
    rows = []
    for system, step, samples in (("plain", "TCP connect", tcp),
                                  ("secure", "TCP connect + RSA-OAEP/HKDF handshake", handshake),
                                  ("secure", "Login (PBKDF2 password check on the server)", login)):
        rows.append({"system": system, "step": step, "repeats": len(samples), **describe(samples)})
        print(f"  {step:<46} {rows[-1]['mean_ms']:8.2f} ms  ± {rows[-1]['std_ms']:.2f}   "
              f"(median {rows[-1]['median_ms']:.2f})")
    return rows


def test_latency(users: Dict[str, Endpoint], params: dict) -> List[Dict]:
    print(f"\n2/5  Round-trip latency client → server → client ({params['iterations']} messages per size)")
    rows = []
    for size in TEXT_SIZES:
        text = text_of(size)
        for system in SYSTEMS:                   # interleaved, so both see the same network conditions
            user = users[system]
            for i in range(params["warmup"]):
                user.roundtrip(f"w{size}-{i}", text)
            samples = [user.roundtrip(f"l{size}-{i}", text) for i in range(params["iterations"])]
            rows.append({"system": system, "size_bytes": size, "iterations": len(samples), **describe(samples)})
        secure, plain = rows[-2], rows[-1]
        print(f"  {ps.size_label(size):>6}   SecureChat {secure['mean_ms']:7.3f} ms ± {secure['std_ms']:.3f}   "
              f"plaintext {plain['mean_ms']:7.3f} ms ± {plain['std_ms']:.3f}   "
              f"(+{100 * (secure['mean_ms'] / plain['mean_ms'] - 1):.0f}%)")
    return rows


def test_throughput(users: Dict[str, Endpoint], params: dict) -> List[Dict]:
    count = params["burst"]
    print(f"\n3/5  Throughput: {count} messages sent as fast as possible")
    rows = []
    for size in THROUGHPUT_SIZES:
        text = text_of(size)
        for system in SYSTEMS:
            user = users[system]
            start = time.perf_counter()
            for i in range(count):
                user.send(f"t{size}-{i}", text)
            elapsed = user.wait_count(count) - start
            rows.append({"system": system, "size_bytes": size, "messages": count, "seconds": elapsed,
                         "messages_per_s": count / elapsed, "mb_per_s": count * size / elapsed / MB})
        secure, plain = rows[-2], rows[-1]
        print(f"  {ps.size_label(size):>6}   SecureChat {secure['messages_per_s']:8,.0f} msg/s {secure['mb_per_s']:6.1f} MB/s   "
              f"plaintext {plain['messages_per_s']:8,.0f} msg/s {plain['mb_per_s']:6.1f} MB/s")
    return rows


def _client_worker(system: str, host: str, port: int, count: int, seconds: float, barrier) -> List[float]:
    """Runs in a worker process: `count` users, each chatting non-stop for `seconds` after the barrier."""
    folder = Path(tempfile.mkdtemp(prefix="securechat-bench-worker-"))
    users: List[Endpoint] = []
    text = text_of(256)
    try:
        try:
            users = [ENDPOINTS[system](host, port, folder).open() for _ in range(count)]
            for user in users:
                for k in range(3):
                    user.roundtrip(f"w{k}", text)
        except BaseException:
            barrier.abort()                     # don't leave the others waiting
            raise
        barrier.wait(timeout=300)
        deadline = time.perf_counter() + seconds
        latencies: List[List[float]] = [[] for _ in users]

        def chat(i: int, user: Endpoint) -> None:
            k = 0
            while time.perf_counter() < deadline:
                latencies[i].append(user.roundtrip(f"s{k}", text))
                k += 1

        threads = [threading.Thread(target=chat, args=(i, u)) for i, u in enumerate(users)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return [s for per_user in latencies for s in per_user]
    finally:
        for user in users:
            user.close()
        shutil.rmtree(folder, ignore_errors=True)


def test_scalability(host: str, ports: dict, params: dict) -> List[Dict]:
    """
    N clients chat at the same time for a fixed window; every client sends its next message as
    soon as the previous one is back. The clients run in WORKER_PROCESSES separate processes
    (one Python process can only run Python code on one core at a time - with all 50 clients
    in one process, the CLIENTS would be the bottleneck instead of the server).
    """
    seconds = params["seconds"]
    print(f"\n4/5  Scalability: {', '.join(map(str, CLIENT_COUNTS))} clients chatting at once for "
          f"{seconds:g} s each ({WORKER_PROCESSES} client processes)")
    from performance import benchmark_network as module     # so workers can import the function
    rows = []
    with multiprocessing.Manager() as manager, ProcessPoolExecutor(max_workers=WORKER_PROCESSES) as pool:
        for clients in CLIENT_COUNTS:
            for system in SYSTEMS:
                workers = min(clients, WORKER_PROCESSES)
                shares = [clients // workers + (1 if i < clients % workers else 0) for i in range(workers)]
                barrier = manager.Barrier(workers + 1)
                futures = [pool.submit(module._client_worker, system, host, ports[system], n, seconds, barrier)
                           for n in shares]
                try:
                    barrier.wait(timeout=300)
                except threading.BrokenBarrierError:
                    for future in futures:
                        future.result()          # re-raises the worker's error
                    raise
                before = server_stats(host, ports["stats"])
                time.sleep(seconds)              # the server's CPU is measured over the chat window
                after = server_stats(host, ports["stats"])
                samples = [s for future in futures for s in future.result()]
                cpu = 100 * (after["cpu_s"] - before["cpu_s"]) / (after["wall"] - before["wall"])
                rows.append({"system": system, "clients": clients, "seconds": seconds, "messages": len(samples),
                             **describe(samples), "messages_per_s": len(samples) / seconds,
                             "server_cpu_percent_of_one_core": cpu,
                             "server_cpu_percent_of_machine": cpu / after["cores"],
                             "server_rss_mb": after["rss_mb"]})
            secure, plain = rows[-2], rows[-1]
            print(f"  {clients:>3} clients   SecureChat {secure['mean_ms']:7.2f} ms {secure['messages_per_s']:7,.0f} msg/s "
                  f"server CPU {secure['server_cpu_percent_of_one_core']:4.0f}%   plaintext {plain['mean_ms']:6.2f} ms "
                  f"{plain['messages_per_s']:7,.0f} msg/s server CPU {plain['server_cpu_percent_of_one_core']:4.0f}%")
    return rows


def test_files(users: Dict[str, Endpoint], params: dict, folder: Path) -> List[Dict]:
    repeats = params["file_repeats"]
    print(f"\n5/5  File transfer, sent and received back ({repeats}x each)")
    rows = []
    warmup = folder / "warmup.bin"
    warmup.write_bytes(os.urandom(MB))
    for system in SYSTEMS:
        users[system].send_file_and_wait(warmup)
    warmup.unlink()
    for size_mb in FILE_SIZES_MB:
        path = folder / f"benchmark_{size_mb}mb.bin"
        path.write_bytes(os.urandom(size_mb * MB))
        for system in SYSTEMS:
            samples = [users[system].send_file_and_wait(path) for _ in range(repeats)]
            mean = statistics.fmean(samples)
            rows.append({"system": system, "file_mb": size_mb, "repeats": repeats, "mean_s": mean,
                         "std_s": statistics.stdev(samples) if repeats > 1 else 0.0, "mb_per_s": size_mb / mean})
        path.unlink()
        secure, plain = rows[-2], rows[-1]
        print(f"  {size_mb:>3} MB   SecureChat {secure['mean_s']:6.2f} s ({secure['mb_per_s']:5.1f} MB/s)   "
              f"plaintext {plain['mean_s']:6.2f} s ({plain['mb_per_s']:5.1f} MB/s)")
    return rows


# ======================================================================= graphs
def make_graphs(label: str) -> List[Path]:
    import matplotlib.pyplot as plt
    from matplotlib.ticker import LogLocator
    ps.apply_style()
    where = "on one PC (localhost)" if label == "localhost" else "between two PCs (LAN)"
    load = lambda kind: read_csv(f"network_{label}_{kind}.csv", RESULTS)
    latency, throughput, scaling, files = load("latency"), load("throughput"), load("scalability"), load("files")
    rows_of = lambda rows, system: [r for r in rows if r["system"] == system]
    out = []

    # 1. latency vs message size
    fig, ax = plt.subplots(figsize=(9, 5))
    labels = []
    for system in SYSTEMS:
        rows = rows_of(latency, system)
        x, y = [r["size_bytes"] for r in rows], [r["mean_ms"] for r in rows]
        colour = ps.SYSTEM_COLOURS[system]
        ax.plot(x, y, color=colour, marker=ps.SYSTEM_MARKERS[system], label=ps.SYSTEM_LABELS[system])
        ax.fill_between(x, [max(0, r["mean_ms"] - r["std_ms"]) for r in rows],
                        [r["mean_ms"] + r["std_ms"] for r in rows], color=colour, alpha=0.12, linewidth=0)
        labels.append({"x": x[-1], "y": y[-1], "text": ps.SYSTEM_LABELS[system]})
    ps.use_size_axis(ax, TEXT_SIZES)
    ax.set_xlabel("Message size (log scale)")
    ax.set_ylim(bottom=0)
    ax.set_ylabel("Round-trip time (ms)")
    ax.set_title(f"Message round trip client → server → client, {where}\n"
                 f"mean of {latency[0]['iterations']} messages; band = ± 1 std dev", loc="left")
    ax.legend(loc="upper left")
    ps.label_line_ends(ax, labels, log_y=False)
    out.append(ps.save(fig, GRAPHS / f"network_{label}_latency.png"))

    # 2. encryption overhead %
    fig, ax = plt.subplots(figsize=(9, 4.6))
    secure, plain = rows_of(latency, "secure"), rows_of(latency, "plain")
    overhead = [100 * (s["mean_ms"] / p["mean_ms"] - 1) for s, p in zip(secure, plain)]
    bars = ax.bar([ps.size_label(r["size_bytes"]) for r in secure], overhead, color=ps.SINGLE, width=0.6,
                  edgecolor="white", linewidth=1.2)
    for bar, s, p, pct in zip(bars, secure, plain, overhead):
        ax.annotate(f"+{pct:.0f}%\n(+{s['mean_ms'] - p['mean_ms']:.3f} ms)",
                    (bar.get_x() + bar.get_width() / 2, max(0, bar.get_height())), xytext=(0, 4),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8.5, color=ps.INK_2)
    ax.axhline(0, color=ps.BASELINE, linewidth=0.8)
    ax.set_ylim(min(0, min(overhead) * 1.2), max(overhead) * 1.3)
    ax.grid(axis="x", visible=False)
    ax.set_xlabel("Message size")
    ax.set_ylabel("Extra round-trip time vs plaintext (%)")
    ps.plain_number_axis(ax)
    ax.set_title(f"Cost of security per message, {where}", loc="left")
    out.append(ps.save(fig, GRAPHS / f"network_{label}_overhead.png"))

    # 3. scalability: latency | server CPU (two panels, never two y-axes)
    fig, (left, right) = plt.subplots(1, 2, figsize=(12.5, 4.8))
    for ax, column, ylabel, title in (
            (left, "mean_ms", "Mean round-trip time (ms)", "Latency as more clients chat at once"),
            (right, "server_cpu_percent_of_one_core", "Server CPU (% of one core)", "Server CPU use")):
        labels = []
        for system in SYSTEMS:
            rows = rows_of(scaling, system)
            x, y = [r["clients"] for r in rows], [r[column] for r in rows]
            ax.plot(x, y, color=ps.SYSTEM_COLOURS[system], marker=ps.SYSTEM_MARKERS[system],
                    label=ps.SYSTEM_LABELS[system])
            labels.append({"x": x[-1], "y": y[-1], "text": "SecureChat" if system == "secure" else "Plaintext"})
        ax.set_xticks(CLIENT_COUNTS)
        ax.set_xlabel("Concurrent clients")
        ax.set_ylim(bottom=0)
        ax.set_ylabel(ylabel)
        ax.set_title(title, loc="left")
        ps.label_line_ends(ax, labels, log_y=False)
    left.legend(loc="upper left")
    fig.suptitle(f"Scalability {where}  (every client chats non-stop for {scaling[0]['seconds']:g} s)",
                 x=0.01, ha="left", fontsize=13, fontweight="semibold", color=ps.INK)
    fig.subplots_adjust(wspace=0.32, top=0.82)
    out.append(ps.save(fig, GRAPHS / f"network_{label}_scalability.png"))

    # 4. throughput: messages/s by message size | file transfer MB/s
    fig, (left, right) = plt.subplots(1, 2, figsize=(12.5, 4.8))
    width = 0.38
    for ax, rows, key, column, fmt, xlabel, ylabel, title in (
            (left, throughput, "size_bytes", "messages_per_s", "{:,.0f}", "Message size", "Messages per second",
             f"Chat messages ({throughput[0]['messages']} sent back-to-back)"),
            (right, files, "file_mb", "mb_per_s", "{:.1f}", "File size", "Transfer speed (MB/s)",
             "File transfer (sent and received back)")):
        keys = sorted({r[key] for r in rows})
        for i, system in enumerate(SYSTEMS):
            values = [next(r[column] for r in rows if r["system"] == system and r[key] == k) for k in keys]
            bars = ax.bar([j + (i - 0.5) * width for j in range(len(keys))], values, width,
                          color=ps.SYSTEM_COLOURS[system], edgecolor="white", linewidth=1.2,
                          label=ps.SYSTEM_LABELS[system])
            for bar, value in zip(bars, values):
                ax.annotate(fmt.format(value), (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                            xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8, color=ps.INK_2)
        ax.set_xticks(range(len(keys)),
                      [ps.size_label(k) if key == "size_bytes" else f"{k} MB" for k in keys])
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ps.plain_number_axis(ax)
        ax.set_title(title, loc="left")
        ax.set_ylim(0, ax.get_ylim()[1] * 1.15)
        ax.grid(axis="x", visible=False)
    left.legend(loc="upper right")
    fig.suptitle(f"Throughput {where}  (higher is better)", x=0.01, ha="left", fontsize=13,
                 fontweight="semibold", color=ps.INK)
    fig.subplots_adjust(wspace=0.28, top=0.82)
    out.append(ps.save(fig, GRAPHS / f"network_{label}_throughput.png"))

    # 5. localhost vs LAN, once both runs exist
    if all((RESULTS / f"network_{l}_latency.csv").exists() for l in ("localhost", "lan")):
        fig, ax = plt.subplots(figsize=(9, 5))
        labels = []
        for l, style in (("lan", "-"), ("localhost", "--")):
            rows = read_csv(f"network_{l}_latency.csv", RESULTS)
            for system in SYSTEMS:
                part = rows_of(rows, system)
                name = f"{'SecureChat' if system == 'secure' else 'Plaintext'}, {'LAN' if l == 'lan' else 'localhost'}"
                ax.plot([r["size_bytes"] for r in part], [r["mean_ms"] for r in part], style,
                        color=ps.SYSTEM_COLOURS[system], marker=ps.SYSTEM_MARKERS[system], label=name)
                labels.append({"x": part[-1]["size_bytes"], "y": part[-1]["mean_ms"], "text": name})
        ps.use_size_axis(ax, TEXT_SIZES)
        ax.set_yscale("log")
        ax.yaxis.set_major_locator(LogLocator(subs=(1, 2, 5)))
        ps.plain_number_axis(ax)
        ax.set_ylabel("Mean round-trip time (ms, log scale)")
        ax.set_title("Round-trip time on one PC (dashed) vs between two PCs (solid)", loc="left")
        ax.legend(loc="center left")
        ps.label_line_ends(ax, labels)
        out.append(ps.save(fig, GRAPHS / "network_localhost_vs_lan.png"))
    return out


# ======================================================================= summary
def print_summary(label: str, connect, latency, throughput, scaling, files) -> None:
    pick = lambda rows, system, **kw: next(r for r in rows if r["system"] == system
                                           and all(r[k] == v for k, v in kw.items()))
    print("\n" + "═" * 92)
    print(f"  SUMMARY  ({'one PC, localhost' if label == 'localhost' else 'two PCs over the LAN'})")
    print("═" * 92)
    print(f"  {'':<34}{'SecureChat':>16}{'Plaintext':>16}{'difference':>16}")
    lines = []
    for size in (TEXT_SIZES[0], 1024, TEXT_SIZES[-1]):
        s, p = pick(latency, "secure", size_bytes=size), pick(latency, "plain", size_bytes=size)
        lines.append((f"Round trip, {ps.size_label(size)} message", f"{s['mean_ms']:.3f} ms", f"{p['mean_ms']:.3f} ms",
                      f"+{s['mean_ms'] - p['mean_ms']:.3f} ms"))
    s, p = pick(throughput, "secure", size_bytes=1024), pick(throughput, "plain", size_bytes=1024)
    lines.append(("Throughput, 1 KB messages", f"{s['messages_per_s']:,.0f}/s", f"{p['messages_per_s']:,.0f}/s",
                  f"{100 * (s['messages_per_s'] / p['messages_per_s'] - 1):+.0f}%"))
    most = CLIENT_COUNTS[-1]
    s, p = pick(scaling, "secure", clients=most), pick(scaling, "plain", clients=most)
    lines.append((f"{most} clients: round trip", f"{s['mean_ms']:.2f} ms", f"{p['mean_ms']:.2f} ms",
                  f"+{s['mean_ms'] - p['mean_ms']:.2f} ms"))
    lines.append((f"{most} clients: server CPU (1 core)", f"{s['server_cpu_percent_of_one_core']:.0f}%",
                  f"{p['server_cpu_percent_of_one_core']:.0f}%", ""))
    big = FILE_SIZES_MB[-1]
    s, p = pick(files, "secure", file_mb=big), pick(files, "plain", file_mb=big)
    lines.append((f"{big} MB file", f"{s['mean_s']:.2f} s", f"{p['mean_s']:.2f} s",
                  f"{100 * (s['mean_s'] / p['mean_s'] - 1):+.0f}%"))
    handshake = next(r for r in connect if r["step"].startswith("TCP connect +"))
    tcp = next(r for r in connect if r["step"] == "TCP connect")
    lines.append(("Connection set-up (median)", f"{handshake['median_ms']:.2f} ms", f"{tcp['median_ms']:.2f} ms",
                  f"{handshake['median_ms'] - tcp['median_ms']:+.2f} ms"))
    for name, a, b, c in lines:
        print(f"  {name:<34}{a:>16}{b:>16}{c:>16}")
    print("═" * 92)


# ======================================================================= main
def run(host: str, ports: dict, label: str, params: dict, server_env: dict) -> None:
    folder = Path(tempfile.mkdtemp(prefix="securechat-bench-client-"))
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"network_{label}_environment.json").write_text(json.dumps(
        {"mode": label, "server_address": host, "client": environment.collect(), "server": server_env},
        indent=2), encoding="utf-8")
    started = time.perf_counter()
    try:
        connect = test_connect(host, ports, params, folder)
        users = {system: ENDPOINTS[system](host, ports[system], folder).open() for system in SYSTEMS}
        latency = test_latency(users, params)
        throughput = test_throughput(users, params)
        scaling = test_scalability(host, ports, params)
        files = test_files(users, params, folder)
        for user in users.values():
            user.close()
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    for kind, rows in (("connect", connect), ("latency", latency), ("throughput", throughput),
                       ("scalability", scaling), ("files", files)):
        write_csv(f"network_{label}_{kind}.csv", rows, RESULTS)
    print(f"\n  (benchmarks took {time.perf_counter() - started:.0f} s)")
    print_summary(label, connect, latency, throughput, scaling, files)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark SecureChat over the network vs a plaintext chat")
    parser.add_argument("--quick", action="store_true", help="fewer messages - a fast check (~30 s)")
    parser.add_argument("--remote", metavar="SERVER_IP", help="benchmark the servers on another PC "
                        "(started there with --serve)")
    parser.add_argument("--serve", action="store_true", help="run the benchmark servers for --remote")
    parser.add_argument("--bind", default="0.0.0.0", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"first of three ports for --serve / --remote (default {DEFAULT_PORT})")
    parser.add_argument("--graphs-only", action="store_true", help="redraw graphs from the saved CSV files")
    args = parser.parse_args(argv)

    if args.serve:
        serve(args.bind, args.port)
        return 0
    label = "lan" if args.remote else "localhost"
    if not args.graphs_only:
        params = QUICK if args.quick else FULL
        proc = None
        if args.remote:
            host = args.remote
            ports = {"secure": args.port, "plain": args.port + 1, "stats": args.port + 2}
        else:
            host = "127.0.0.1"
            proc, ports = start_local_servers()
        try:
            try:
                server_env = server_stats(host, ports["stats"])["env"]
            except OSError as exc:
                print(f"Can't reach the benchmark server at {host}:{ports['stats']} ({exc}).\n"
                      f"Start it on that PC with:  python -m performance.benchmark_network --serve")
                return 1
            print("SecureChat network benchmark - " +
                  ("one PC (localhost)" if not args.remote else f"two PCs, server at {host}"))
            print(f"  server: {server_env['cpu']}   client: {environment.cpu_name()}")
            run(host, ports, label, params, server_env)
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=10)

    for path in make_graphs(label):
        print(f"  saved {path.relative_to(ROOT.parent)}")
    print(f"  CSV results in {RESULTS.relative_to(ROOT.parent)}")
    print("  Update the report:  python -m performance.make_report")
    return 0


if __name__ == "__main__":
    sys.exit(main())
