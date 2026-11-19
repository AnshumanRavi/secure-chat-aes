"""
Run every security demo one after another and print a scorecard.

    python -m security_demo.run_all                          # everything on throwaway demo servers
    python -m security_demo.run_all --server 127.0.0.1:5555  # attack your running server instead

The first demo compares what an eavesdropper captures from SecureChat with what they
capture from the deliberately insecure chat.
"""

import argparse
import sys
import time

from security_demo import bruteforce_login_test, replay_test, tamper_test
from security_demo.demo_utils import (
    BOLD, GREEN, RED, DemoServer, P, attack, bad, banner, info, ok, parse_target, scorecard, step,
    utf8_attempt, verdict, wait_for, demo_user,
)
from security_demo.insecure_chat import InsecureServer, run_demo
from security_demo.sniffer_proxy import MitmProxy

SECRET = "my bank PIN is 4711"


def eavesdropping_demo(target=None) -> bool:
    banner("EAVESDROPPING TEST - what does a sniffer on the network capture?",
           "The same secret is sent through SecureChat and through an insecure plain-text chat.")
    server = None
    if target is None:
        server = DemoServer(show_log=False)
        target = (server.host, server.port)

    step(1, "SecureChat: Alice and Bob chat through the attacker's proxy")
    secure_proxy = MitmProxy(target, listen_port=0).start()
    alice = demo_user("127.0.0.1", secure_proxy.port, "alice")
    bob = demo_user("127.0.0.1", secure_proxy.port, "bob")
    inbox = []
    bob.on("message", lambda m: inbox.append(m["text"]))
    alice.send_message(bob.username, SECRET)
    wait_for(lambda: inbox)
    captured = [body for conn in secure_proxy.connections for _, _, body in conn.history]
    leaked = [b for b in captured if b"4711" in b]
    readable = [b for b in captured if utf8_attempt(b)[0] and b"HANDSHAKE" not in b]
    ok(f"Bob received the message: “{inbox[-1]}”") if inbox else bad("Bob received nothing")
    info(f"the attacker captured {len(captured)} packets ({sum(map(len, captured)):,} bytes)")
    (ok if not leaked else bad)(f"packets containing the PIN: {len(leaked)}")
    (ok if not readable else bad)(f"readable packets (apart from the public handshake): {len(readable)}")
    secure_safe = bool(inbox) and not leaked and not readable
    for c in (alice, bob):
        c.logout()
    secure_proxy.stop()
    if server is not None:
        server.stop()

    step(2, "Insecure chat: the same message through the same kind of proxy")
    insecure = InsecureServer(port=0, host="127.0.0.1", verbose=False).start_in_background()
    plain_proxy = MitmProxy(("127.0.0.1", insecure.port), listen_port=0, framed=False).start()
    run_demo("127.0.0.1", plain_proxy.port)
    time.sleep(0.5)
    plain_captured = [body for conn in plain_proxy.connections for _, _, body in conn.history]
    for body in plain_captured:
        if b"4711" in body:
            attack("captured: " + P(RED + BOLD, body.decode().strip()))
    insecure_leaked = any(b"4711" in b for b in plain_captured)
    plain_proxy.stop()
    insecure.stop()

    print()
    print(P(GREEN + BOLD, "  SecureChat   → ") + "the attacker sees random bytes (AES-256-GCM)")
    print(P(RED + BOLD, "  Insecure chat → ") + "the attacker reads the PIN in plain text")
    verdict(secure_safe and insecure_leaked, "Encryption is what keeps the PIN secret.")
    return secure_safe and insecure_leaked


def main() -> None:
    parser = argparse.ArgumentParser(description="Run all security demos")
    parser.add_argument("--server", help="attack a running server, e.g. 127.0.0.1:5555 (default: demo servers)")
    target = parse_target(parser.parse_args().server)
    results = [
        ("Eavesdropping (packet sniffing)", eavesdropping_demo(target), "only ciphertext on the wire"),
        ("Tampering (1 bit flipped)", tamper_test.run(target), "GCM tag check fails, packet dropped"),
        ("Replay (re-sent packets / session)", replay_test.run(target), "sequence numbers + per-session salt"),
        ("Brute-force login", bruteforce_login_test.run(target), "lockout after 5 wrong passwords"),
    ]
    scorecard(results)
    sys.exit(0 if all(blocked for _, blocked, _ in results) else 1)


if __name__ == "__main__":
    main()
