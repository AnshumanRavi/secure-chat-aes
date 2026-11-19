"""
Write performance/PERFORMANCE_REPORT.md from the saved benchmark results.

    python -m performance.make_report

Every number in the report is read from performance/results (the CSV and JSON files the
benchmarks write) - nothing is typed in by hand, so re-running a benchmark and then this
script keeps the report true. The two-PC (LAN) section appears once
`python -m performance.benchmark_network --remote <ip>` has been run.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from performance import environment
from performance.benchmark_crypto import CHOSEN_ROUNDS, KEY_BITS, MODES, SIZES, read_csv
from performance.plot_style import MODE_LABELS, size_label

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
REPORT = ROOT / "PERFORMANCE_REPORT.md"
NET_LABELS = {"localhost": "one PC (localhost)", "lan": "two PCs over the LAN"}
NET_TITLES = {"localhost": "One PC (localhost)", "lan": "Two PCs over the LAN"}
PERCEPTION_MS = 100          # response-time limit for "instantaneous" (Nielsen 1993)


# ======================================================================= helpers
def table(headers: Sequence[str], rows: Sequence[Sequence], right_from: int = 1) -> List[str]:
    """Markdown table; columns from `right_from` on are right-aligned (numbers)."""
    align = ["---" if i < right_from else "---:" for i in range(len(headers))]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(align) + " |"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return lines + [""]


def pick(rows: List[Dict], **match) -> Dict:
    return next(r for r in rows if all(r[k] == v for k, v in match.items()))


def graph(name: str, alt: str) -> List[str]:
    return [f"![{alt}](graphs/{name})", ""]


def load_json(name: str) -> Optional[dict]:
    path = RESULTS / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def has(name: str) -> bool:
    return (RESULTS / name).exists()


def pct(new: float, old: float) -> str:
    return f"{100 * (new / old - 1):+.0f}%"


# ======================================================================= sections
def section_environment(env: dict, net: Dict[str, dict]) -> List[str]:
    out = ["## 2. Test environment", "",
           "Recorded automatically by `performance/environment.py` every time a benchmark runs "
           "(saved to `performance/results/environment.json` and `network_*_environment.json`).", ""]
    rows = [("CPU", env["cpu"]),
            ("Cores", f"{env['cpu_cores_physical']} physical / {env['cpu_cores_logical']} logical"),
            ("RAM", f"{env['ram_gb']} GB"), ("Operating system", env["os"]),
            ("Python", env["python"]), ("PyCryptodome", env["pycryptodome"]),
            ("matplotlib / PySide6", f"{env['matplotlib']} / {env['pyside6']}"),
            ("Crypto benchmark run", env["date"])]
    out += table(["Item", "Value"], rows, right_from=2)
    for label, info in net.items():
        if label == "lan":
            out += [f"**Two-PC run:** client `{info['client']['cpu']}` ({info['client']['os']}) → server at "
                    f"`{info['server_address']}`: `{info['server']['cpu']}` ({info['server']['os']}), "
                    f"run {info['client']['date']}.", ""]
        else:
            out += [f"**Network benchmark, {NET_LABELS[label]}:** run {info['client']['date']} on the same machine.", ""]
    return out


def section_method(aes: List[Dict], handshake: List[Dict], pbkdf2: List[Dict], resources: List[Dict],
                   net_params: Dict[str, dict]) -> List[str]:
    iterations = aes[0]["iterations"]
    handshakes = pick(handshake, operation="Complete handshake over a local socket")["iterations"]
    repeats = [r["repeats"] for r in pbkdf2]
    out = ["## 3. Methodology", "",
           "### 3.1 Cryptographic benchmark (`performance/benchmark_crypto.py`)", "",
           "* **What one operation is.** One call is one complete per-message operation, exactly as the chat "
           "performs it: a new cipher object, a fresh random nonce/IV and, for CBC, the HMAC. The functions "
           "timed are the ones in `common/crypto_utils.py` that the application uses.",
           f"* **Matrix.** {len(MODES)} modes (GCM, CBC + HMAC-SHA256, CTR, ECB) × {len(KEY_BITS)} key sizes "
           f"(128/192/256-bit) × {len(SIZES)} message sizes ({size_label(SIZES[0])} … {size_label(SIZES[-1])}).",
           f"* **Timing.** `time.perf_counter()` around every single call, {iterations:,} timed calls per "
           f"measurement after untimed warm-up calls (50 in a full run); reported as **mean ± standard deviation**. "
           f"Throughput = message size ÷ mean time, with 1 MB = 1,048,576 bytes.",
           "* **Correctness first.** Before timing, every mode's ciphertext is decrypted and compared with the "
           "original, so only working round trips are measured.",
           "* **Fair key-size comparison.** For each mode and size, the three key sizes are measured back to "
           "back, so slow changes in the laptop CPU's turbo clock affect all three equally.",
           f"* **CPU and memory.** `psutil`: process CPU time ÷ wall time (100 % = one core fully busy) and "
           f"resident memory (RSS) sampled every 10 ms while encrypting 1 MB messages non-stop for "
           f"{resources[0]['seconds']:g} s per mode.",
           f"* **Handshake and PBKDF2.** The real `server_handshake`/`client_handshake` over a local socket pair "
           f"({handshakes:,} runs); PBKDF2-HMAC-SHA256 for {pbkdf2[0]['rounds']:,} … {pbkdf2[-1]['rounds']:,} rounds "
           f"({min(repeats)}-{max(repeats)} runs each).", ""]
    out += ["### 3.2 Network benchmark (`performance/benchmark_network.py`)", "",
            "* **The two systems.** *SecureChat* = the real `ChatServer` and `ChatClient` (RSA-2048 handshake, "
            "AES-256-GCM on every packet, sequence numbers, timestamps, receipts). *Plaintext* = the deliberately "
            "insecure demo chat (`security_demo/insecure_chat.py`): the same TCP, the same JSON and the same "
            "base64 file chunks, but no encryption, no authentication and no checks.",
            "* **One clock.** Every simulated user sends messages to *itself*, so each sample is a full trip "
            "client → server → client timed on one computer, with no need to synchronise two PCs' clocks.",
            "* **Server measured on its own.** The servers run in a separate process; a small stats endpoint "
            "reports that process's CPU time and memory, which also works when the server is on another PC.",
            "* **Interleaving.** For each message size SecureChat and plaintext are measured one after the "
            "other, so both see the same machine and network conditions.",
            "* **Scalability.** N clients (1-50) chat non-stop for a fixed window. The clients are spread over 8 "
            "worker processes, because one Python process runs Python code on only one core at a time - with "
            "all clients in one process, the *benchmark* would be the bottleneck instead of the server.", ""]
    rows = []
    for label, p in net_params.items():
        rows.append((NET_LABELS[label], f"{p['iterations']:,}", f"{p['burst']:,}", f"{p['seconds']:g} s",
                     f"{p['file_repeats']}"))
    if rows:
        out += table(["Network run", "Messages per size (latency)", "Burst (throughput)",
                      "Window per client count", "Repeats per file"], rows)
    return out


def section_aes(aes: List[Dict]) -> List[str]:
    out = ["## 4. Results", "", "### 4.1 AES modes (AES-256)", "",
           "Time for one complete encryption / decryption (mean ± std dev) and throughput:", ""]
    rows = []
    for mode in MODES:
        cells = [MODE_LABELS[mode]]
        for size in (16, 1024, 65536):
            r = pick(aes, mode=mode, key_bits=256, size_bytes=size)
            cells.append(f"{r['enc_mean_us']:.1f} ± {r['enc_std_us']:.1f} µs")
        big = pick(aes, mode=mode, key_bits=256, size_bytes=SIZES[-1])
        cells += [f"{big['enc_mb_per_s']:,.0f} MB/s", f"{big['dec_mb_per_s']:,.0f} MB/s",
                  "yes" if mode in ("GCM", "CBC+HMAC") else "**no**"]
        rows.append(cells)
    out += table(["Mode", "Encrypt 16 B", "Encrypt 1 KB", "Encrypt 64 KB", "Encrypt 1 MB", "Decrypt 1 MB",
                  "Detects tampering"], rows)
    out += graph("aes_throughput_by_mode.png", "AES throughput by mode and message size")
    out += graph("aes_latency_by_mode.png", "AES encryption time per message")

    out += ["### 4.2 Key sizes (1 MB messages)", ""]
    rows = []
    for mode in MODES:
        values = {b: pick(aes, mode=mode, key_bits=b, size_bytes=SIZES[-1])["enc_mb_per_s"] for b in KEY_BITS}
        rows.append([MODE_LABELS[mode]] + [f"{values[b]:,.0f} MB/s" for b in KEY_BITS] + [pct(values[256], values[128])])
    out += table(["Mode"] + [f"AES-{b}" for b in KEY_BITS] + ["AES-256 vs AES-128"], rows)
    out += graph("aes_key_sizes.png", "Throughput by key size")

    out += ["### 4.3 Ciphertext overhead", ""]
    parts = {"GCM": "12-byte nonce + 16-byte tag", "CBC+HMAC": "16-byte IV + 1-16 bytes padding + 32-byte HMAC",
             "CTR": "8-byte nonce", "ECB": "1-16 bytes padding"}
    rows = []
    for mode in MODES:
        small = pick(aes, mode=mode, key_bits=256, size_bytes=16)
        kb = pick(aes, mode=mode, key_bits=256, size_bytes=1024)
        rows.append((MODE_LABELS[mode], parts[mode], f"{small['overhead_bytes']:.0f} B ({small['overhead_percent']:.0f}%)",
                     f"{kb['overhead_bytes']:.0f} B ({kb['overhead_percent']:.1f}%)"))
    out += table(["Mode", "Made of", "On a 16 B message", "On a 1 KB message"], rows, right_from=2)
    out += ["(16 B and 1 KB are multiples of the 16-byte block, so PKCS#7 adds a whole extra block for CBC and ECB.)", ""]
    out += graph("aes_overhead.png", "Ciphertext overhead per mode")
    return out


def section_handshake(handshake: List[Dict], pbkdf2: List[Dict], resources: List[Dict]) -> List[str]:
    out = ["### 4.4 Connection handshake and key agreement", ""]
    rows = [(r["operation"], r["who"], f"{r['mean_ms']:.3f} ± {r['std_ms']:.3f} ms", f"{r['iterations']:,}")
            for r in sorted(handshake, key=lambda r: -r["mean_ms"])]
    out += table(["Operation", "Who / how often", "Time", "Runs"], rows, right_from=2)
    out += graph("handshake_cost.png", "Cost of the handshake compared with one message")

    out += ["### 4.5 PBKDF2-HMAC-SHA256 password hashing", ""]
    rows = [(f"{r['rounds']:,}" + (" ← SecureChat" if r["rounds"] == CHOSEN_ROUNDS else ""),
             f"{r['mean_ms']:.2f} ± {r['std_ms']:.2f} ms", f"{r['guesses_per_second_per_core']:,.0f}")
            for r in pbkdf2]
    out += table(["Rounds", "Time per password", "Guesses per second per CPU core"], rows)
    out += graph("pbkdf2_rounds.png", "PBKDF2 time and guesses per second")

    out += ["### 4.6 CPU and memory while encrypting", ""]
    rows = [(MODE_LABELS[r["mode"]], f"{r['throughput_mb_per_s']:,.0f} MB/s", f"{r['cpu_percent_of_one_core']:.0f}%",
             f"{r['cpu_percent_of_machine']:.1f}%", f"{r['peak_rss_mb']:.1f} MB (+{r['peak_rss_mb'] - r['baseline_rss_mb']:.1f} MB)")
            for r in resources]
    out += table(["Mode", "Throughput", "CPU (one core)", "CPU (whole machine)", "Peak memory (extra)"], rows)
    out += graph("cpu_memory.png", "CPU and memory while encrypting")
    return out


def section_network(label: str, number: str) -> List[str]:
    load = lambda kind: read_csv(f"network_{label}_{kind}.csv", RESULTS)
    connect, latency, throughput, scaling, files = (load(k) for k in
                                                    ("connect", "latency", "throughput", "scalability", "files"))
    out = [f"### {number} Network: {NET_LABELS[label]}", "", "**Connection set-up** (median):", ""]
    out += table(["Step", "System", "Median", "Mean ± std dev"],
                 [(r["step"], "SecureChat" if r["system"] == "secure" else "Plaintext", f"{r['median_ms']:.2f} ms",
                   f"{r['mean_ms']:.2f} ± {r['std_ms']:.2f} ms") for r in connect], right_from=2)

    out += ["**Round trip client → server → client** (mean ± std dev):", ""]
    rows = []
    for size in sorted({r["size_bytes"] for r in latency}):
        s, p = pick(latency, system="secure", size_bytes=size), pick(latency, system="plain", size_bytes=size)
        rows.append((size_label(size), f"{s['mean_ms']:.3f} ± {s['std_ms']:.3f} ms", f"{p['mean_ms']:.3f} ± {p['std_ms']:.3f} ms",
                     f"+{s['mean_ms'] - p['mean_ms']:.3f} ms", pct(s["mean_ms"], p["mean_ms"]), f"{s['p95_ms']:.2f} ms"))
    out += table(["Message", "SecureChat", "Plaintext", "Extra time", "Extra %", "SecureChat 95th pct"], rows)
    out += graph(f"network_{label}_latency.png", f"Round-trip latency, {NET_LABELS[label]}")
    out += graph(f"network_{label}_overhead.png", f"Encryption overhead, {NET_LABELS[label]}")

    out += [f"**Throughput** ({throughput[0]['messages']:,} messages sent back to back) and **file transfer** "
            f"(sent and received back, SHA-256 verified):", ""]
    rows = []
    for size in sorted({r["size_bytes"] for r in throughput}):
        s, p = pick(throughput, system="secure", size_bytes=size), pick(throughput, system="plain", size_bytes=size)
        rows.append((f"{size_label(size)} messages", f"{s['messages_per_s']:,.0f} msg/s ({s['mb_per_s']:.1f} MB/s)",
                     f"{p['messages_per_s']:,.0f} msg/s ({p['mb_per_s']:.1f} MB/s)"))
    for size in sorted({r["file_mb"] for r in files}):
        s, p = pick(files, system="secure", file_mb=size), pick(files, system="plain", file_mb=size)
        rows.append((f"{size} MB file", f"{s['mean_s']:.2f} s ({s['mb_per_s']:.1f} MB/s)",
                     f"{p['mean_s']:.2f} s ({p['mb_per_s']:.1f} MB/s)"))
    out += table(["Test", "SecureChat", "Plaintext"], rows)
    out += graph(f"network_{label}_throughput.png", f"Throughput, {NET_LABELS[label]}")

    out += [f"**Scalability** (every client chats non-stop for {scaling[0]['seconds']:g} s):", ""]
    rows = []
    for clients in sorted({r["clients"] for r in scaling}):
        s, p = pick(scaling, system="secure", clients=clients), pick(scaling, system="plain", clients=clients)
        rows.append((clients, f"{s['mean_ms']:.2f} ms", f"{s['p95_ms']:.2f} ms", f"{s['messages_per_s']:,.0f}",
                     f"{s['server_cpu_percent_of_one_core']:.0f}%", f"{s['server_rss_mb']:.0f} MB",
                     f"{p['mean_ms']:.2f} ms", f"{p['messages_per_s']:,.0f}", f"{p['server_cpu_percent_of_one_core']:.0f}%"))
    out += table(["Clients", "SecureChat mean", "SecureChat 95th pct", "SecureChat msg/s", "SecureChat server CPU",
                  "SecureChat server memory", "Plaintext mean", "Plaintext msg/s", "Plaintext server CPU"], rows)
    out += graph(f"network_{label}_scalability.png", f"Scalability, {NET_LABELS[label]}")
    return out


# ======================================================================= analysis
def section_analysis(aes, handshake, pbkdf2, resources, nets: List[str]) -> List[str]:
    gcm = lambda size: pick(aes, mode="GCM", key_bits=256, size_bytes=size)
    cbc = lambda size: pick(aes, mode="CBC+HMAC", key_bits=256, size_bytes=size)
    big = SIZES[-1]
    crossover = next((s for s in SIZES if gcm(s)["enc_mean_us"] < cbc(s)["enc_mean_us"]), None)
    ctr, ecb = pick(aes, mode="CTR", key_bits=256, size_bytes=big), pick(aes, mode="ECB", key_bits=256, size_bytes=big)
    key_change = [abs(100 * (pick(aes, mode=m, key_bits=256, size_bytes=big)["enc_mb_per_s"] /
                             pick(aes, mode=m, key_bits=128, size_bytes=big)["enc_mb_per_s"] - 1)) for m in MODES]

    out = ["## 5. Analysis", "", "### 5.1 Why AES-256-GCM is the right choice", "",
           "GCM is **not** the fastest mode at every size, and the numbers show where it loses:", "",
           f"* **Small messages:** GCM needs {gcm(1024)['enc_mean_us']:.0f} µs to encrypt a 1 KB message against "
           f"{cbc(1024)['enc_mean_us']:.0f} µs for CBC + HMAC. Most of that is a fixed cost of setting up a new "
           f"GCM object in PyCryptodome for each message (it takes {gcm(16)['enc_mean_us']:.0f} µs even for 16 bytes)."
           + (f" From {size_label(crossover)} upwards GCM is the faster of the two." if crossover else ""),
           f"* **Large messages and files:** at 1 MB GCM encrypts at {gcm(big)['enc_mb_per_s']:,.0f} MB/s, "
           f"{gcm(big)['enc_mb_per_s'] / cbc(big)['enc_mb_per_s']:.1f}× the speed of CBC + HMAC "
           f"({cbc(big)['enc_mb_per_s']:,.0f} MB/s), because it encrypts and authenticates in one pass "
           f"instead of running AES-CBC and then a separate SHA-256 HMAC.",
           f"* **CTR and ECB are faster** ({ctr['enc_mb_per_s']:,.0f} and {ecb['enc_mb_per_s']:,.0f} MB/s at 1 MB) "
           f"but give **no integrity**: an attacker can flip bits in CTR ciphertext and the receiver cannot tell, and "
           f"ECB encrypts identical 16-byte blocks to identical ciphertext, leaking patterns. Neither is acceptable "
           f"for a chat that must reject tampered messages.", "",
           "GCM wins on what matters for this application:", "",
           "1. **Authenticated encryption (AEAD).** One primitive gives confidentiality *and* integrity: the "
           "16-byte tag makes any modification detectable. The tamper demo (`security_demo/tamper_test.py`) relies "
           "on exactly this. Associated data binds each packet to its direction (`SecureChat/1|C2S` / `|S2C`) without "
           "encrypting it.",
           "2. **Fewer ways to get it wrong.** CBC + HMAC is secure only when the MAC is checked before decrypting "
           "(encrypt-then-MAC) with a separate key; mistakes here have produced real padding-oracle attacks. GCM has "
           "no padding at all.",
           f"3. **Smaller packets.** {gcm(1024)['overhead_bytes']:.0f} bytes of overhead per message against "
           f"{cbc(1024)['overhead_bytes']:.0f} for CBC + HMAC.",
           "4. **It is the standard.** GCM is specified by NIST (SP 800-38D) and is one of the AEAD modes allowed "
           "by TLS 1.3, which permits only AEAD ciphers.", "",
           f"The ~{gcm(1024)['enc_mean_us'] - cbc(1024)['enc_mean_us']:.0f} µs GCM loses on a 1 KB message is "
           f"invisible next to a network round trip (section 5.2), so it is a good trade for built-in integrity.", "",
           f"**Key size:** at 1 MB, AES-256 is within {max(key_change):.0f}% of AES-128 in every mode. The CPU's AES "
           f"instructions (AES-NI) do the extra rounds of AES-256 (14 instead of 10) in hardware, so the larger "
           f"key costs almost nothing here.", ""]

    # --- overhead and whether users notice it
    out += ["### 5.2 The overhead of encryption, and whether users notice it", ""]
    for label in nets:
        latency = read_csv(f"network_{label}_latency.csv", RESULTS)
        files = read_csv(f"network_{label}_files.csv", RESULTS)
        s, p = pick(latency, system="secure", size_bytes=1024), pick(latency, system="plain", size_bytes=1024)
        extras = [pick(latency, system="secure", size_bytes=z)["mean_ms"] - pick(latency, system="plain", size_bytes=z)["mean_ms"]
                  for z in sorted({r["size_bytes"] for r in latency})]
        fs, fp = (pick(files, system=x, file_mb=max(r["file_mb"] for r in files)) for x in ("secure", "plain"))
        out += [f"**{NET_TITLES[label]}:** a 1 KB message takes {s['mean_ms']:.3f} ms with SecureChat "
                f"against {p['mean_ms']:.3f} ms in plain text - {pct(s['mean_ms'], p['mean_ms'])} or "
                f"{s['mean_ms'] - p['mean_ms']:.2f} ms extra. Across all message sizes the extra time stays between "
                f"{min(extras):.2f} and {max(extras):.2f} ms, i.e. it is a roughly fixed cost per message. "
                f"A {fs['file_mb']:.0f} MB file takes {fs['mean_s']:.2f} s instead of {fp['mean_s']:.2f} s.", ""]
    if "localhost" in nets:
        out += ["On one PC the percentage is large only because the plaintext baseline is tiny: the plaintext chat "
                "does nothing but copy bytes inside the same computer, while each SecureChat message is encrypted "
                "or decrypted eight times on its trip (client encrypt → server decrypt → server encrypts the "
                "ACK, the forwarded message and the DELIVERED receipt → client decrypts all three), and the server "
                "also validates it and looks up the recipient.", ""]
    if "lan" in nets:
        lan = read_csv("network_lan_latency.csv", RESULTS)
        s, p = pick(lan, system="secure", size_bytes=1024), pick(lan, system="plain", size_bytes=1024)
        out += [f"Between two real PCs the same 1 KB message costs {pct(s['mean_ms'], p['mean_ms'])} "
                f"({s['mean_ms'] - p['mean_ms']:.2f} ms); here the network itself is part of both measurements.", ""]
    else:
        out += ["*The two-PC measurement has not been run yet, so the overhead over a real network is not reported "
                "here; run `python -m performance.benchmark_network --remote <server-ip>` and regenerate this report.*", ""]
    worst, file_extra = 0.0, []
    for label in nets:
        latency = read_csv(f"network_{label}_latency.csv", RESULTS)
        files = read_csv(f"network_{label}_files.csv", RESULTS)
        worst = max([worst] + [pick(latency, system="secure", size_bytes=z)["mean_ms"] -
                               pick(latency, system="plain", size_bytes=z)["mean_ms"]
                               for z in {r["size_bytes"] for r in latency}])
        biggest = max(r["file_mb"] for r in files)
        file_extra.append((label, biggest, pick(files, system="secure", file_mb=biggest)["mean_s"] -
                           pick(files, system="plain", file_mb=biggest)["mean_s"]))
    if nets:
        verdict = (f"about {PERCEPTION_MS / worst:,.0f} times smaller than that, so users cannot perceive it"
                   if worst < PERCEPTION_MS / 10 else
                   "close enough to that limit that some users may notice it" if worst < PERCEPTION_MS else
                   "above that limit, so users would notice it")
        files_text = "; ".join(f"{NET_LABELS[l]}: +{extra:.2f} s for a {mb:.0f} MB file" for l, mb, extra in file_extra)
        out += [f"**Noticeable?** About {PERCEPTION_MS} ms is the commonly cited limit for a response to feel "
                f"instantaneous (Nielsen, *Usability Engineering*, 1993). The largest extra time measured per message "
                f"is {worst:.2f} ms - {verdict}. Files take measurably longer ({files_text}), which matters only "
                f"for the largest files.", ""]

    # --- handshake
    full = pick(handshake, operation="Complete handshake over a local socket")
    message = next(r for r in handshake if r["who"] == "reference")
    keygen = pick(handshake, operation="RSA-2048 key pair generation")
    decrypt = pick(handshake, operation="RSA-OAEP decrypt session secret")
    encrypt = pick(handshake, operation="RSA-OAEP encrypt session secret")
    out += ["### 5.3 The RSA handshake is paid once per session", "",
            f"* A complete handshake (RSA-OAEP key transport + HKDF + key confirmation) takes **{full['mean_ms']:.2f} ms** "
            f"- the same time as encrypting about {full['mean_ms'] / message['mean_ms']:,.0f} 1 KB messages with AES-GCM. "
            f"It happens once per connection; every message after that uses only the symmetric session key.",
            f"* The most expensive cryptographic step is the server's RSA private-key operation ({decrypt['mean_ms']:.2f} ms) - "
            f"about {decrypt['mean_ms'] / encrypt['mean_ms']:.0f}× slower than the client's public-key encryption "
            f"({encrypt['mean_ms']:.3f} ms). That asymmetry is why RSA is used only to transport one 32-byte secret, "
            f"never to encrypt messages.",
            f"* Generating the server's RSA-2048 key pair takes {keygen['mean_ms']:.0f} ms (± {keygen['std_ms']:.0f} ms - "
            f"it depends on how quickly random primes are found) but happens only on the server's first start; the "
            f"key is then saved encrypted."]
    for label in nets:
        connect = read_csv(f"network_{label}_connect.csv", RESULTS)
        latency = read_csv(f"network_{label}_latency.csv", RESULTS)
        hs = next(r for r in connect if r["step"].startswith("TCP connect +"))
        tcp = next(r for r in connect if r["step"] == "TCP connect")
        login = next(r for r in connect if r["step"].startswith("Login"))
        rt = pick(latency, system="secure", size_bytes=1024)
        out.append(f"* {NET_TITLES[label]}: connecting takes {hs['median_ms']:.2f} ms with the "
                   f"handshake against {tcp['median_ms']:.2f} ms for plain TCP; that is about "
                   f"{hs['median_ms'] / rt['mean_ms']:.0f} message round trips, once per session. Logging in takes "
                   f"another {login['median_ms']:.0f} ms, of which about "
                   f"{pick(pbkdf2, rounds=CHOSEN_ROUNDS)['mean_ms']:.0f} ms is the server's PBKDF2 check (section 4.5).")
    out.append("")

    # --- PBKDF2
    chosen = pick(pbkdf2, rounds=CHOSEN_ROUNDS)
    fastest = pbkdf2[0]
    upper = next(r for r in pbkdf2 if r["rounds"] > 600_000 or r is pbkdf2[-1])
    lower = max((r for r in pbkdf2 if r["rounds"] <= 600_000), key=lambda r: r["rounds"])
    at_600k = lower["mean_ms"] + (upper["mean_ms"] - lower["mean_ms"]) * (600_000 - lower["rounds"]) / (upper["rounds"] - lower["rounds"])
    common = 10_000
    years = 26 ** 8 / chosen["guesses_per_second_per_core"] / (365.25 * 24 * 3600)
    out += ["### 5.4 The PBKDF2 trade-off", "",
            f"PBKDF2 time grows linearly with the number of rounds ({fastest['mean_ms']:.2f} ms at "
            f"{fastest['rounds']:,} rounds, {pbkdf2[-1]['mean_ms']:.1f} ms at {pbkdf2[-1]['rounds']:,}). The same "
            f"cost that a legitimate login pays once is paid by an attacker for *every guess*:", "",
            f"* **The user:** {chosen['mean_ms']:.1f} ms per login at SecureChat's {CHOSEN_ROUNDS:,} rounds - "
            f"unnoticeable.",
            f"* **An attacker with a stolen database:** {chosen['guesses_per_second_per_core']:,.0f} guesses per "
            f"second per CPU core instead of {fastest['guesses_per_second_per_core']:,.0f} at {fastest['rounds']:,} "
            f"rounds. Trying a list of {common:,} common passwords against one account takes "
            f"{common / chosen['guesses_per_second_per_core']:.0f} s per core instead of "
            f"{common / fastest['guesses_per_second_per_core']:.1f} s, and the per-user salt means this work cannot be "
            f"reused for the next account. A random 8-letter lower-case password (26⁸ possibilities) would take "
            f"about {years:,.0f} core-years.",
            "* **Caveat:** attackers use GPUs, which compute PBKDF2-SHA256 far faster than one CPU core, so these "
            "figures show the *relative* gain from more rounds, not an absolute guarantee. Strong passwords still "
            "matter.",
            "* **Online attacks** are limited separately: the server locks an account for 60 s after 5 wrong "
            "passwords (see `security_demo/bruteforce_login_test.py`).",
            f"* **Choosing the number:** the OWASP Password Storage Cheat Sheet currently recommends 600,000 rounds "
            f"for PBKDF2-HMAC-SHA256. From the measured line, 600,000 rounds would cost about {at_600k:.0f} ms per "
            f"login on this machine - still unnoticeable - so raising `PBKDF2_ITERATIONS` from 200,000 is a cheap "
            f"improvement (existing hashes store their round count, so old accounts keep working).", ""]

    # --- scalability
    out += ["### 5.5 Scalability", ""]
    gcm_res = pick(resources, mode="GCM")
    for label in nets:
        scaling = read_csv(f"network_{label}_scalability.csv", RESULTS)
        secure = [r for r in scaling if r["system"] == "secure"]
        plain = [r for r in scaling if r["system"] == "plain"]
        one, most = secure[0], secure[-1]
        per_client = (most["mean_ms"] - one["mean_ms"]) / (most["clients"] - one["clients"])
        capacity = min(r["messages_per_s"] for r in secure[1:]) if len(secure) > 1 else one["messages_per_s"]
        demand = most["clients"] * 0.5
        out += [f"**{NET_TITLES[label]}:**", "",
                f"* The SecureChat server handles {min(r['messages_per_s'] for r in secure):,.0f}-"
                f"{max(r['messages_per_s'] for r in secure):,.0f} messages per second whether 1 or {most['clients']} clients "
                f"are chatting, so with more clients each one waits its turn: latency grows almost linearly, by about "
                f"{per_client:.2f} ms per extra active client ({one['mean_ms']:.2f} ms → {most['mean_ms']:.2f} ms).",
                f"* Server CPU levels off at {max(r['server_cpu_percent_of_one_core'] for r in secure):.0f}% of one core "
                f"(out of {psutil_cores(label)} logical cores). Python's global interpreter lock lets only one thread run "
                f"Python code at a time, so the thread-per-client server cannot use the other cores; the share above "
                f"100% is time spent in C code (PyCryptodome, sockets) that runs outside that lock.",
                f"* The plaintext relay reaches {max(r['messages_per_s'] for r in plain):,.0f} messages per second - the "
                f"difference is the per-message work of security (eight AES-GCM operations, validation, receipts).",
                f"* Memory grows from {one['server_rss_mb']:.0f} MB to {most['server_rss_mb']:.0f} MB "
                f"(about {(most['server_rss_mb'] - one['server_rss_mb']) / (most['clients'] - one['clients']) * 1024:.0f} KB "
                f"per extra connected client).",
                f"* **In practice:** if all {most['clients']} users were very active and each sent a message every two "
                f"seconds, the server would need {demand:.0f} messages per second, about "
                f"{100 * demand / capacity:.0f}% of the measured capacity; at that rate the measured capacity would "
                f"serve roughly {capacity / 0.5:,.0f} such users. Going further would need several server processes "
                f"(or a language without a GIL), since more threads in one Python process cannot use more cores.", ""]
    out += [f"On the client side, continuous AES-GCM encryption keeps one core busy "
            f"({gcm_res['cpu_percent_of_one_core']:.0f}% of one core = {gcm_res['cpu_percent_of_machine']:.1f}% of the "
            f"machine) and needs only {gcm_res['peak_rss_mb'] - gcm_res['baseline_rss_mb']:.1f} MB of extra memory, "
            f"while a normal chat encrypts only a few messages per second.", ""]
    return out


def psutil_cores(label: str) -> int:
    info = load_json(f"network_{label}_environment.json")
    return info["server"]["cpu_cores_logical"] if info else 0


def section_limitations(nets: List[str]) -> List[str]:
    out = ["## 6. Limitations", "",
           "* **One machine.** The crypto results come from a single laptop. Its CPU mixes performance and "
           "efficiency cores and changes its turbo clock, so repeated runs differ by several percent; the standard "
           "deviations in the tables show the spread.",
           "* **Python.** Absolute speeds reflect Python + PyCryptodome. The fixed per-call cost (e.g. creating a GCM "
           "object) would be much smaller in C, Go or Rust, and the GIL limits the server to about one core for "
           "Python code.",
           "* **The plaintext baseline is simpler than SecureChat.** It has no login, no database lookup and no "
           "receipts, so the network overhead measures *the whole secure protocol*, not AES alone. Section 4.1 isolates "
           "the pure encryption cost.",
           "* **Simulated users.** Users message themselves and send as fast as possible; real users are much slower "
           "and burstier. Scalability was measured up to 50 clients.",
           "* **Transport encryption only.** The network benchmark has end-to-end encryption switched off "
           "(the simulated users have no identity keys); E2E adds one ECDH key agreement per contact "
           "(measured in 4.4) and one more AES-GCM operation at each end.",
           "* **PBKDF2 guesses are CPU figures**; GPUs and dedicated hardware are much faster."]
    if "lan" not in nets:
        out.append("* **No two-PC results yet.** All network numbers are on one PC, where there is no real "
                   "network delay, no Wi-Fi interference and no packet loss. They show the *processing* cost of "
                   "security, not what users would see over Wi-Fi.")
    else:
        out.append("* **One network.** The two-PC run used one Wi-Fi/LAN at one time of day; other networks will "
                   "have different delays.")
    return out + [""]


def section_conclusion(aes, handshake, pbkdf2, nets: List[str]) -> List[str]:
    gcm1mb = pick(aes, mode="GCM", key_bits=256, size_bytes=SIZES[-1])
    full = pick(handshake, operation="Complete handshake over a local socket")
    chosen = pick(pbkdf2, rounds=CHOSEN_ROUNDS)
    out = ["## 7. Conclusion", "",
           f"AES-256-GCM provides confidentiality and integrity at {gcm1mb['enc_mb_per_s']:,.0f} MB/s for large data on "
           f"this laptop. Its fixed per-message cost of a few tens of microseconds in PyCryptodome makes it slower "
           f"than CBC + HMAC on tiny messages, but that difference is far too small to matter. The RSA-2048 "
           f"handshake costs {full['mean_ms']:.1f} ms once per connection, and PBKDF2 with {CHOSEN_ROUNDS:,} rounds "
           f"costs {chosen['mean_ms']:.0f} ms per login while slowing password guessing to "
           f"{chosen['guesses_per_second_per_core']:,.0f} guesses per second per core."]
    if nets:
        latency = read_csv(f"network_{nets[-1]}_latency.csv", RESULTS)
        s, p = pick(latency, system="secure", size_bytes=1024), pick(latency, system="plain", size_bytes=1024)
        scaling = read_csv(f"network_{nets[-1]}_scalability.csv", RESULTS)
        cap = min(r["messages_per_s"] for r in scaling if r["system"] == "secure")
        extra = s["mean_ms"] - p["mean_ms"]
        verdict = ("**For the users of a chat application, the cost of security is effectively invisible.**"
                   if extra < PERCEPTION_MS / 10 else
                   "**The cost of security is measurable but below what users perceive.**" if extra < PERCEPTION_MS else
                   "**The cost of security is large enough for users to notice.**")
        out += ["", f"End to end on {NET_LABELS[nets[-1]]}, the full secure protocol adds "
                    f"{extra:.2f} ms to a 1 KB message - about {PERCEPTION_MS / extra:,.0f} times below the "
                    f"{PERCEPTION_MS} ms a person can notice - and one Python server process sustains about "
                    f"{cap:,.0f} messages per second. {verdict} The main improvements left are "
                    f"raising PBKDF2 to the currently recommended 600,000 rounds and, for many simultaneous users, "
                    f"a server that can use more than one CPU core."]
    return out + [""]


# ======================================================================= main
def build() -> str:
    aes = read_csv("aes_modes.csv", RESULTS)
    handshake = read_csv("handshake.csv", RESULTS)
    pbkdf2 = read_csv("pbkdf2.csv", RESULTS)
    resources = read_csv("resources.csv", RESULTS)
    env = load_json("environment.json") or environment.collect()
    nets = [label for label in ("localhost", "lan") if has(f"network_{label}_latency.csv")]
    net_env = {label: load_json(f"network_{label}_environment.json") for label in nets}
    net_env = {k: v for k, v in net_env.items() if v}
    net_params = {}
    for label in nets:
        latency = read_csv(f"network_{label}_latency.csv", RESULTS)
        files = read_csv(f"network_{label}_files.csv", RESULTS)
        net_params[label] = {"iterations": latency[0]["iterations"],
                             "burst": read_csv(f"network_{label}_throughput.csv", RESULTS)[0]["messages"],
                             "seconds": read_csv(f"network_{label}_scalability.csv", RESULTS)[0]["seconds"],
                             "file_repeats": files[0]["repeats"]}

    out = ["# SecureChat - Performance Report", "",
           f"*Generated {time.strftime('%Y-%m-%d %H:%M')} by `python -m performance.make_report` from the files in "
           f"`performance/results/`. Every measured number below comes from those files; derived figures "
           f"(ratios, estimates) are calculated from them.*", "",
           "## 1. Objective", "",
           "Measure what SecureChat's security costs in speed and resources, and decide whether that cost is "
           "acceptable:", "",
           "* compare AES modes (GCM, CBC + HMAC, CTR, ECB) and key sizes (128/192/256-bit) on realistic message sizes;",
           "* measure the one-off costs: the RSA-2048 handshake per connection and PBKDF2 password hashing per login;",
           "* measure the end-to-end overhead of the full secure protocol against an identical chat with no "
           "security, including throughput, file transfer and behaviour with up to 50 simultaneous clients;",
           "* judge whether any of this is noticeable to users.", ""]
    out += section_environment(env, net_env)
    out += section_method(aes, handshake, pbkdf2, resources, net_params)
    out += section_aes(aes)
    out += section_handshake(handshake, pbkdf2, resources)
    numbers = iter(["4.7", "4.8"])
    for label in nets:
        out += section_network(label, next(numbers))
    if "localhost" in nets and "lan" in nets:
        out += ["### 4.9 One PC vs two PCs", ""] + graph("network_localhost_vs_lan.png", "Localhost vs LAN latency")
    if "lan" not in nets:
        out += ["### Two PCs over the LAN - not run yet", "",
                "Run `python -m performance.benchmark_network --serve` on the server PC and "
                "`python -m performance.benchmark_network --remote <server-ip>` on the other PC, then "
                "`python -m performance.make_report` to add the results here.", ""]
    out += section_analysis(aes, handshake, pbkdf2, resources, nets)
    out += section_limitations(nets)
    out += section_conclusion(aes, handshake, pbkdf2, nets)
    out += ["## 8. Reproducing these results", "", "```",
            "python -m performance.benchmark_crypto                       # ~2 minutes",
            "python -m performance.benchmark_network                      # ~1 minute, one PC",
            "python -m performance.benchmark_network --serve              # on the server PC ...",
            "python -m performance.benchmark_network --remote <server-ip> # ... and on the other PC",
            "python -m performance.make_report                            # rewrite this report", "```", ""]
    return "\n".join(out)


def main() -> None:
    REPORT.write_text(build(), encoding="utf-8")
    print(f"Wrote {REPORT.relative_to(ROOT.parent)}")


if __name__ == "__main__":
    main()
