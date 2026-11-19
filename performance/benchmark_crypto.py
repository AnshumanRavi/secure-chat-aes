"""
Cryptographic benchmarks for SecureChat.

    python -m performance.benchmark_crypto              # full run (1000 iterations each, ~2 minutes)
    python -m performance.benchmark_crypto --quick      # 100 iterations, ~20 seconds
    python -m performance.benchmark_crypto --graphs-only   # redraw graphs from the saved CSVs

What is measured
----------------
1. AES modes x key sizes x message sizes: GCM, CBC+HMAC, CTR and ECB (insecure baseline)
   with 128/192/256-bit keys on 16 B ... 1 MB messages. Encryption and decryption time
   (mean ± standard deviation over N timed runs after warm-up) and throughput.
   Each call is a complete per-message operation - new cipher object, fresh random
   nonce/IV, and for CBC the HMAC - exactly what the chat does for every message.
2. Ciphertext overhead per mode (nonce + tag + padding + MAC bytes).
3. The connection handshake: RSA-2048 key generation, RSA-OAEP encrypt/decrypt, HKDF and a
   complete handshake over a local socket - compared with the cost of one chat message.
4. PBKDF2-HMAC-SHA256 password hashing time for 1,000 ... 1,000,000 rounds.
5. CPU usage and memory (psutil) while encrypting continuously.

Results:  performance/results/*.csv     Graphs:  performance/graphs/*.png (300 DPI)
"""

import argparse
import csv
import os
import socket
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List

import psutil

from common import crypto_utils as cu
from common import e2e
from common.protocol import client_handshake, server_handshake
from performance import environment
from performance import plot_style as ps

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
GRAPHS = ROOT / "graphs"

SIZES = [16, 64, 256, 1024, 4096, 16384, 65536, 1048576]
MODES = ["GCM", "CBC+HMAC", "CTR", "ECB"]
KEY_BITS = [128, 192, 256]
PBKDF2_ROUNDS = [1_000, 10_000, 50_000, 100_000, 200_000, 500_000, 1_000_000]
CHOSEN_ROUNDS = cu.PBKDF2_ITERATIONS          # what SecureChat uses (200,000)
MB = 2 ** 20                                  # throughput is reported in MB/s with 1 MB = 1,048,576 bytes
PROCESS = psutil.Process()

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")


# ======================================================================= measuring
def measure(fn: Callable, iterations: int, warmup: int = 20) -> Dict[str, float]:
    """
    Time fn() `iterations` times with time.perf_counter (after `warmup` untimed calls that
    fill caches and let the CPU reach its normal clock). Also records the process's CPU
    use during the timed runs (CPU time / wall time, 100 % = one core busy) and memory.
    """
    for _ in range(warmup):
        fn()
    cpu_before = sum(PROCESS.cpu_times()[:2])
    wall_before = time.perf_counter()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    wall = time.perf_counter() - wall_before
    cpu = sum(PROCESS.cpu_times()[:2]) - cpu_before
    return {"mean": statistics.fmean(samples), "std": statistics.stdev(samples) if len(samples) > 1 else 0.0,
            "cpu_percent": 100 * cpu / wall if wall else 0.0, "rss_mb": PROCESS.memory_info().rss / MB}


def mode_functions(mode: str, key: bytes, mac_key: bytes):
    """(encrypt, decrypt) for one AES mode, using the helpers in common/crypto_utils.py."""
    if mode == "GCM":
        return (lambda p: cu.aes_encrypt(key, p)), (lambda c: cu.aes_decrypt(key, c))
    if mode == "CBC+HMAC":
        return (lambda p: cu.aes_cbc_encrypt(key, mac_key, p)), (lambda c: cu.aes_cbc_decrypt(key, mac_key, c))
    if mode == "CTR":
        return (lambda p: cu.aes_ctr_encrypt(key, p)), (lambda c: cu.aes_ctr_decrypt(key, c))
    if mode == "ECB":
        return (lambda p: cu.aes_ecb_encrypt(key, p)), (lambda c: cu.aes_ecb_decrypt(key, c))
    raise ValueError(mode)


def progress(done: int, total: int, label: str) -> None:
    bar = "█" * int(30 * done / total) + "·" * (30 - int(30 * done / total))
    print(f"\r  [{bar}] {done}/{total}  {label:<34}", end="", flush=True)


# ======================================================================= benchmarks
def bench_aes(iterations: int, warmup: int) -> List[Dict]:
    print(f"\n1/5  AES modes x key sizes x message sizes ({iterations} iterations each)")
    rows, total, done = [], len(KEY_BITS) * len(MODES) * len(SIZES), 0
    mac_key = cu.generate_aes_key()
    keys = {bits: cu.generate_aes_key(bits // 8) for bits in KEY_BITS}
    # The three key sizes are measured back to back for each (mode, size), so slow drift in the
    # CPU's turbo clock affects them equally instead of skewing the key-size comparison.
    for mode in MODES:
        for size in SIZES:
            plaintext = os.urandom(size)
            for bits in KEY_BITS:
                encrypt, decrypt = mode_functions(mode, keys[bits], mac_key)
                ciphertext = encrypt(plaintext)
                assert decrypt(ciphertext) == plaintext, f"{mode} round trip failed"
                enc = measure(lambda: encrypt(plaintext), iterations, warmup)
                dec = measure(lambda: decrypt(ciphertext), iterations, warmup)
                rows.append({
                    "mode": mode, "key_bits": bits, "size_bytes": size, "iterations": iterations,
                    "enc_mean_us": enc["mean"] * 1e6, "enc_std_us": enc["std"] * 1e6,
                    "dec_mean_us": dec["mean"] * 1e6, "dec_std_us": dec["std"] * 1e6,
                    "enc_mb_per_s": size / enc["mean"] / MB, "dec_mb_per_s": size / dec["mean"] / MB,
                    "ciphertext_bytes": len(ciphertext), "overhead_bytes": len(ciphertext) - size,
                    "overhead_percent": 100 * (len(ciphertext) - size) / size,
                    "cpu_percent": (enc["cpu_percent"] + dec["cpu_percent"]) / 2, "rss_mb": dec["rss_mb"],
                })
                done += 1
                progress(done, total, f"AES-{bits} {mode} {ps.size_label(size)}")
    print()
    return rows


def bench_handshake(iterations: int) -> List[Dict]:
    print("\n2/5  Connection handshake (RSA-2048 + HKDF) and end-to-end key agreement")
    rows = []

    def add(operation: str, who: str, fn: Callable, n: int, warmup: int = 3) -> None:
        result = measure(fn, n, warmup)
        rows.append({"operation": operation, "who": who, "iterations": n,
                     "mean_ms": result["mean"] * 1e3, "std_ms": result["std"] * 1e3})
        print(f"  {operation:<44} {result['mean'] * 1e3:10.3f} ms  ± {result['std'] * 1e3:.3f}")

    add("RSA-2048 key pair generation", "server, first start only", cu.generate_rsa_keypair,
        max(3, iterations // 100), warmup=0)
    private_key = cu.generate_rsa_keypair()
    public_key = private_key.publickey()
    secret = cu.generate_aes_key()
    sealed = cu.rsa_encrypt(public_key, secret)
    salt = cu.generate_salt()
    add("RSA-OAEP encrypt session secret", "client, per connection", lambda: cu.rsa_encrypt(public_key, secret), iterations)
    add("RSA-OAEP decrypt session secret", "server, per connection", lambda: cu.rsa_decrypt(private_key, sealed), iterations)
    add("HKDF-SHA256 session key derivation", "both, per connection", lambda: cu.derive_session_key(secret, salt), iterations)

    def full_handshake() -> None:
        a, b = socket.socketpair()
        thread = threading.Thread(target=server_handshake, args=(b, private_key))
        thread.start()
        client_handshake(a)
        thread.join()
        a.close()
        b.close()
    add("Complete handshake over a local socket", "both, per connection", full_handshake, max(20, iterations // 5))

    key = cu.generate_aes_key()
    message = os.urandom(1024)
    add("AES-256-GCM encrypt one 1 KB chat message", "reference", lambda: cu.aes_encrypt(key, message), iterations)

    alice, bob = e2e.generate_identity(), e2e.generate_identity()
    add("ECDH P-256 + HKDF end-to-end pair key", "client, once per contact",
        lambda: e2e.pair_key(alice, "alice", bob.public_key(), "bob"), max(20, iterations // 5))
    return rows


def bench_pbkdf2(quick: bool) -> List[Dict]:
    print("\n3/5  PBKDF2-HMAC-SHA256 password hashing")
    rows = []
    salt = cu.generate_salt()
    for rounds in PBKDF2_ROUNDS:
        repeats = 3 if quick else max(5, min(50, int(5_000_000 / rounds)))
        result = measure(lambda: cu.derive_key_from_password("correct horse battery", salt, iterations=rounds),
                         repeats, warmup=1)
        rows.append({"rounds": rounds, "repeats": repeats, "mean_ms": result["mean"] * 1e3,
                     "std_ms": result["std"] * 1e3, "guesses_per_second_per_core": 1 / result["mean"]})
        marker = "  ← SecureChat" if rounds == CHOSEN_ROUNDS else ""
        print(f"  {rounds:>9,} rounds  {result['mean'] * 1e3:9.2f} ms  ± {result['std'] * 1e3:.2f}"
              f"   → {1 / result['mean']:>10,.0f} guesses/s per core{marker}")
    return rows


def bench_resources(seconds: float) -> List[Dict]:
    """Encrypt 1 MB messages non-stop for a few seconds per mode; watch CPU and memory."""
    print(f"\n4/5  CPU and memory while encrypting continuously ({seconds:g} s per mode)")
    rows = []
    key, mac_key = cu.generate_aes_key(), cu.generate_aes_key()
    message = os.urandom(MB)
    for mode in MODES:
        encrypt, _ = mode_functions(mode, key, mac_key)
        baseline = PROCESS.memory_info().rss
        peak = [baseline]
        stop = threading.Event()

        def sample() -> None:
            while not stop.is_set():
                peak[0] = max(peak[0], PROCESS.memory_info().rss)
                time.sleep(0.01)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        cpu_before, start, count = sum(PROCESS.cpu_times()[:2]), time.perf_counter(), 0
        while time.perf_counter() - start < seconds:
            encrypt(message)
            count += 1
        wall = time.perf_counter() - start
        cpu = sum(PROCESS.cpu_times()[:2]) - cpu_before
        stop.set()
        sampler.join()
        rows.append({"mode": mode, "seconds": round(wall, 2), "messages": count,
                     "throughput_mb_per_s": count / wall, "cpu_percent_of_one_core": 100 * cpu / wall,
                     "cpu_percent_of_machine": 100 * cpu / wall / psutil.cpu_count(),
                     "baseline_rss_mb": baseline / MB, "peak_rss_mb": peak[0] / MB})
        print(f"  {ps.MODE_LABELS[mode]:<20} CPU {100 * cpu / wall:5.1f} % of one core   "
              f"peak memory {peak[0] / MB:6.1f} MB   {count / wall:8.1f} MB/s")
    return rows


# ======================================================================= saving
def write_csv(name: str, rows: List[Dict], folder: Path = None) -> Path:
    folder = folder or RESULTS
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in row.items()})
    return path


def read_csv(name: str, folder: Path = None) -> List[Dict]:
    with open((folder or RESULTS) / name, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        for k, v in row.items():
            try:
                row[k] = float(v) if any(c in v for c in ".e") else int(v)
            except ValueError:
                pass
    return rows


# ======================================================================= graphs
def make_graphs() -> List[Path]:
    import matplotlib.pyplot as plt
    ps.apply_style()
    aes = read_csv("aes_modes.csv")
    handshake = read_csv("handshake.csv")
    pbkdf2 = read_csv("pbkdf2.csv")
    resources = read_csv("resources.csv")
    out = []

    def series(mode, bits, column):
        rows = sorted((r for r in aes if r["mode"] == mode and r["key_bits"] == bits), key=lambda r: r["size_bytes"])
        return [r["size_bytes"] for r in rows], [r[column] for r in rows], rows

    # 1. throughput by mode (AES-256), encryption | decryption
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.8), sharey=True)
    for ax, column, title in ((axes[0], "enc_mb_per_s", "Encryption"), (axes[1], "dec_mb_per_s", "Decryption")):
        labels = []
        for mode in MODES:
            x, y, _ = series(mode, 256, column)
            ax.plot(x, y, color=ps.MODE_COLOURS[mode], marker=ps.MODE_MARKERS[mode], label=ps.MODE_LABELS[mode])
            labels.append({"x": x[-1], "y": y[-1], "text": ps.MODE_LABELS[mode]})
        ps.use_size_axis(ax, SIZES)
        ax.set_yscale("log")
        ps.plain_number_axis(ax)
        ax.set_title(title, loc="left")
        ps.label_line_ends(ax, labels)
    axes[0].set_ylabel("Throughput (MB/s, log scale)")
    axes[0].legend(loc="upper left")
    fig.suptitle("AES-256 throughput by mode and message size  (higher is better)", x=0.01, ha="left",
                 fontsize=14, fontweight="semibold", color=ps.INK)
    fig.subplots_adjust(wspace=0.32)
    out.append(ps.save(fig, GRAPHS / "aes_throughput_by_mode.png"))

    # 2. time per message (latency) by mode, with ± 1 standard deviation band
    fig, ax = plt.subplots(figsize=(9, 5))
    labels = []
    for mode in MODES:
        x, y, rows = series(mode, 256, "enc_mean_us")
        std = [r["enc_std_us"] for r in rows]
        colour = ps.MODE_COLOURS[mode]
        ax.plot(x, y, color=colour, marker=ps.MODE_MARKERS[mode], label=ps.MODE_LABELS[mode])
        ax.fill_between(x, [max(v - s, v * 0.05) for v, s in zip(y, std)], [v + s for v, s in zip(y, std)],
                        color=colour, alpha=0.12, linewidth=0)
        labels.append({"x": x[-1], "y": y[-1], "text": ps.MODE_LABELS[mode]})
    ps.use_size_axis(ax, SIZES)
    ax.set_yscale("log")
    ps.plain_number_axis(ax)
    ax.set_ylabel("Time to encrypt one message (µs, log scale)")
    ax.set_title("AES-256 encryption time per message  (lower is better; band = ± 1 std dev)", loc="left")
    ax.legend(loc="upper left")
    ps.label_line_ends(ax, labels)
    out.append(ps.save(fig, GRAPHS / "aes_latency_by_mode.png"))

    # 3. key sizes: grouped bars at 1 MB + GCM across message sizes
    fig, (left, right) = plt.subplots(1, 2, figsize=(13, 4.9), gridspec_kw={"width_ratios": [1.1, 1]})
    width = 0.26
    for i, bits in enumerate(KEY_BITS):
        values = [next(r["enc_mb_per_s"] for r in aes if r["mode"] == m and r["key_bits"] == bits
                       and r["size_bytes"] == SIZES[-1]) for m in MODES]
        left.bar([j + (i - 1) * width for j in range(len(MODES))], values, width, color=ps.KEY_COLOURS[bits],
                 edgecolor="white", linewidth=1.2, label=f"AES-{bits}")
    for j, mode in enumerate(MODES):
        v128 = next(r["enc_mb_per_s"] for r in aes if r["mode"] == mode and r["key_bits"] == 128 and r["size_bytes"] == SIZES[-1])
        v256 = next(r["enc_mb_per_s"] for r in aes if r["mode"] == mode and r["key_bits"] == 256 and r["size_bytes"] == SIZES[-1])
        top = max(r["enc_mb_per_s"] for r in aes if r["mode"] == mode and r["size_bytes"] == SIZES[-1])
        left.annotate(f"256 vs 128: {100 * (v256 / v128 - 1):+.0f}%", (j, top), xytext=(0, 6),
                      textcoords="offset points", ha="center", fontsize=8.5, color=ps.INK_2)
    left.set_xticks(range(len(MODES)), [ps.MODE_LABELS[m] for m in MODES])
    left.set_ylabel("Encryption throughput, 1 MB messages (MB/s)")
    left.set_title("Key size vs speed, by mode", loc="left")
    left.grid(axis="x", visible=False)
    left.legend(loc="upper right", ncols=3)
    left.set_ylim(0, left.get_ylim()[1] * 1.12)
    labels = []
    for bits in KEY_BITS:
        x, y, _ = series("GCM", bits, "enc_mb_per_s")
        right.plot(x, y, color=ps.KEY_COLOURS[bits], marker="o", label=f"AES-{bits}")
        labels.append({"x": x[-1], "y": y[-1], "text": f"AES-{bits}"})
    ps.use_size_axis(right, SIZES)
    right.set_yscale("log")
    ps.plain_number_axis(right)
    right.set_ylabel("Throughput (MB/s, log scale)")
    right.set_title("AES-GCM throughput by key size", loc="left")
    right.legend(loc="upper left")
    ps.label_line_ends(right, labels)
    fig.subplots_adjust(wspace=0.3)
    out.append(ps.save(fig, GRAPHS / "aes_key_sizes.png"))

    # 4. ciphertext overhead
    fig, (left, right) = plt.subplots(1, 2, figsize=(12.5, 4.8))
    one_kb = [next(r for r in aes if r["mode"] == m and r["key_bits"] == 256 and r["size_bytes"] == 1024) for m in MODES]
    bars = left.bar([ps.MODE_LABELS[m] for m in MODES], [r["overhead_bytes"] for r in one_kb],
                    color=[ps.MODE_COLOURS[m] for m in MODES], edgecolor="white", linewidth=1.2, width=0.6)
    parts = {"GCM": "12 nonce + 16 tag", "CBC+HMAC": "16 IV + 16 pad + 32 HMAC", "CTR": "8 nonce, no integrity",
             "ECB": "16 padding, no IV"}
    for bar, mode, row in zip(bars, MODES, one_kb):
        left.annotate(f"{row['overhead_bytes']:.0f} B\n{parts[mode]}", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                      xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontsize=8.5, color=ps.INK_2)
    left.set_ylim(0, max(r["overhead_bytes"] for r in one_kb) * 1.35)
    left.set_ylabel("Extra bytes added to a 1 KB message")
    left.set_title("Ciphertext overhead per message", loc="left")
    left.grid(axis="x", visible=False)
    labels = []
    for mode in MODES:
        x, y, _ = series(mode, 256, "overhead_percent")
        right.plot(x, y, color=ps.MODE_COLOURS[mode], marker=ps.MODE_MARKERS[mode], label=ps.MODE_LABELS[mode])
        labels.append({"x": x[-1], "y": y[-1], "text": ps.MODE_LABELS[mode]})
    ps.use_size_axis(right, SIZES)
    right.set_yscale("log")
    ps.plain_number_axis(right)
    right.set_ylabel("Overhead as % of message size (log scale)")
    right.set_title("Overhead shrinks as messages grow", loc="left")
    right.legend(loc="lower left")
    ps.label_line_ends(right, labels)
    fig.subplots_adjust(wspace=0.32)
    out.append(ps.save(fig, GRAPHS / "aes_overhead.png"))

    # 5. handshake cost (dot plot on a log scale - values span 5 orders of magnitude)
    fig, ax = plt.subplots(figsize=(10, 4.6))
    ordered = sorted(handshake, key=lambda r: r["mean_ms"])
    y = range(len(ordered))
    left_edge = min(r["mean_ms"] for r in ordered) / 3
    for i, row in enumerate(ordered):
        colour = ps.MUTED if row["who"] == "reference" else ps.SINGLE
        ax.hlines(i, left_edge, row["mean_ms"], color=ps.GRID, linewidth=1.2, zorder=1)
        ax.plot(row["mean_ms"], i, "o", color=colour, markersize=8, zorder=2)
        ax.annotate(f"{row['mean_ms']:.3g} ms", (row["mean_ms"], i), xytext=(8, 0), textcoords="offset points",
                    va="center", fontsize=8.5, color=ps.INK_2)
    ax.set_yticks(list(y), [f"{r['operation']}\n({r['who']})" for r in ordered], fontsize=8.5)
    ax.set_xscale("log")
    ps.plain_number_axis(ax, "x")
    ax.set_xlim(left_edge, max(r["mean_ms"] for r in ordered) * 6)
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Time (milliseconds, log scale)")
    ax.set_title("Cost of setting up a secure connection vs sending one message", loc="left")
    out.append(ps.save(fig, GRAPHS / "handshake_cost.png"))

    # 6. PBKDF2: time per hash | attacker guesses per second (two panels, no dual axis)
    fig, (left, right) = plt.subplots(1, 2, figsize=(12.5, 4.6))
    rounds = [r["rounds"] for r in pbkdf2]
    left.plot(rounds, [r["mean_ms"] for r in pbkdf2], color=ps.SINGLE, marker="o")
    right.plot(rounds, [r["guesses_per_second_per_core"] for r in pbkdf2], color=ps.SINGLE, marker="o")
    chosen = next(r for r in pbkdf2 if r["rounds"] == CHOSEN_ROUNDS)
    for ax, value, text in ((left, chosen["mean_ms"], f"SecureChat: 200,000 rounds\n= {chosen['mean_ms']:.0f} ms per login"),
                            (right, chosen["guesses_per_second_per_core"],
                             f"only {chosen['guesses_per_second_per_core']:.0f} guesses/s\nper CPU core")):
        ax.plot(CHOSEN_ROUNDS, value, "o", markersize=11, markerfacecolor="none", markeredgecolor=ps.INK, markeredgewidth=1.2)
        # rising line: text up-left of the point; falling line: text up-right - never across the line
        ax.annotate(text, (CHOSEN_ROUNDS, value), xytext=(-14, 14) if ax is left else (14, 14),
                    textcoords="offset points", fontsize=8.5, color=ps.INK_2, va="bottom",
                    ha="right" if ax is left else "left")
    for ax in (left, right):
        ax.set_xscale("log")
        ax.set_yscale("log")
        ps.plain_number_axis(ax, "x")
        ps.plain_number_axis(ax, "y")
        ax.set_xlabel("PBKDF2 rounds (log scale)")
    left.set_ylabel("Time to hash one password (ms, log scale)")
    left.set_title("Password hashing time grows linearly with rounds", loc="left")
    right.set_ylabel("Password guesses per second (log scale)")
    right.set_title("…so an attacker can try far fewer passwords", loc="left")
    fig.subplots_adjust(wspace=0.3)
    out.append(ps.save(fig, GRAPHS / "pbkdf2_rounds.png"))

    # 7. CPU and memory (two panels)
    fig, (left, right) = plt.subplots(1, 2, figsize=(12, 4.4))
    names = [ps.MODE_LABELS[r["mode"]] for r in resources]
    colours = [ps.MODE_COLOURS[r["mode"]] for r in resources]
    cores = psutil.cpu_count()
    for ax, column, ylabel, title, fmt in (
            (left, "cpu_percent_of_one_core", "CPU use (% of one core)",
             f"CPU while encrypting non-stop (1 of {cores} logical cores)", "{cpu_percent_of_one_core:.0f}%"),
            (right, "peak_rss_mb", "Peak memory of the process (MB)", "Memory while encrypting 1 MB messages",
             "{peak_rss_mb:.0f} MB\n(+{extra:.1f} MB)")):
        bars = ax.bar(names, [r[column] for r in resources], color=colours, edgecolor="white", linewidth=1.2, width=0.6)
        for bar, row in zip(bars, resources):
            ax.annotate(fmt.format(**row, extra=row["peak_rss_mb"] - row["baseline_rss_mb"]),
                        (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 4), textcoords="offset points", ha="center", fontsize=8.5, color=ps.INK_2)
        ax.set_ylabel(ylabel)
        ax.set_title(title, loc="left")
        ax.set_ylim(0, max(r[column] for r in resources) * 1.18)
        ax.grid(axis="x", visible=False)
        ax.tick_params(axis="x", labelsize=8.5)
    fig.subplots_adjust(wspace=0.3)
    out.append(ps.save(fig, GRAPHS / "cpu_memory.png"))
    return out


# ======================================================================= summary
def print_summary(aes: List[Dict], handshake: List[Dict], pbkdf2: List[Dict], resources: List[Dict]) -> None:
    print("\n" + "═" * 92)
    print("  SUMMARY  (AES-256 unless stated)")
    print("═" * 92)
    print(f"  {'Mode':<20}{'encrypt 1 KB':>15}{'decrypt 1 KB':>15}{'encrypt 1 MB':>15}{'overhead':>11}{'integrity':>14}")
    for mode in MODES:
        kb = next(r for r in aes if r["mode"] == mode and r["key_bits"] == 256 and r["size_bytes"] == 1024)
        big = next(r for r in aes if r["mode"] == mode and r["key_bits"] == 256 and r["size_bytes"] == SIZES[-1])
        integrity = "yes" if mode in ("GCM", "CBC+HMAC") else "NO"
        print(f"  {ps.MODE_LABELS[mode]:<20}{kb['enc_mean_us']:>11.1f} µs{kb['dec_mean_us']:>12.1f} µs"
              f"{big['enc_mb_per_s']:>10,.0f} MB/s{kb['overhead_bytes']:>9.0f} B{integrity:>14}")
    print()
    gcm = {bits: next(r for r in aes if r["mode"] == "GCM" and r["key_bits"] == bits and r["size_bytes"] == SIZES[-1])
           for bits in KEY_BITS}
    print("  AES-GCM, 1 MB: " + "   ".join(f"AES-{b}: {gcm[b]['enc_mb_per_s']:,.0f} MB/s" for b in KEY_BITS))
    full = next(r for r in handshake if r["operation"].startswith("Complete handshake"))
    message = next(r for r in handshake if r["who"] == "reference")
    print(f"  One handshake: {full['mean_ms']:.2f} ms  ≈ {full['mean_ms'] / message['mean_ms']:,.0f} chat messages "
          f"(paid once per connection)")
    chosen = next(r for r in pbkdf2 if r["rounds"] == CHOSEN_ROUNDS)
    print(f"  PBKDF2 at 200,000 rounds: {chosen['mean_ms']:.1f} ms per login → "
          f"{chosen['guesses_per_second_per_core']:,.0f} password guesses/s per core for an attacker")
    gcm_res = next(r for r in resources if r["mode"] == "GCM")
    print(f"  Continuous AES-GCM encryption: {gcm_res['cpu_percent_of_one_core']:.0f}% of one core "
          f"({gcm_res['cpu_percent_of_machine']:.1f}% of the whole machine), peak memory {gcm_res['peak_rss_mb']:.0f} MB")
    print("═" * 92)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark SecureChat's cryptography")
    parser.add_argument("--quick", action="store_true", help="100 iterations - a fast check (~20 s)")
    parser.add_argument("--iterations", type=int, help="timed runs per measurement (default 1000)")
    parser.add_argument("--graphs-only", action="store_true", help="redraw the graphs from the saved CSV files")
    args = parser.parse_args()

    if not args.graphs_only:
        iterations = args.iterations or (100 if args.quick else 1000)
        warmup = 10 if args.quick else 50
        RESULTS.mkdir(parents=True, exist_ok=True)
        info = environment.save(RESULTS / "environment.json")
        print("SecureChat cryptographic benchmark")
        print(f"  {info['cpu']} · {info['cpu_cores_logical']} logical cores · {info['ram_gb']} GB RAM · "
              f"Python {info['python']} · PyCryptodome {info['pycryptodome']}")
        started = time.perf_counter()
        aes = bench_aes(iterations, warmup)
        write_csv("aes_modes.csv", aes)
        handshake = bench_handshake(iterations)
        write_csv("handshake.csv", handshake)
        pbkdf2 = bench_pbkdf2(args.quick)
        write_csv("pbkdf2.csv", pbkdf2)
        resources = bench_resources(0.6 if args.quick else 3.0)
        write_csv("resources.csv", resources)
        print(f"\n5/5  Graphs   (benchmarks took {time.perf_counter() - started:.0f} s)")
        print_summary(aes, handshake, pbkdf2, resources)

    for path in make_graphs():
        print(f"  saved {path.relative_to(ROOT.parent)}")
    print(f"  CSV results in {RESULTS.relative_to(ROOT.parent)}")
    print("  Update the report:  python -m performance.make_report")


if __name__ == "__main__":
    main()
