"""
REPLAY TEST - an attacker records a valid encrypted packet and sends it again.

    python -m security_demo.replay_test                         # uses its own throwaway server
    python -m security_demo.replay_test --server 127.0.0.1:5555   # attack your running server instead

The attacker can't read or change the packet, but could they make "Pay Bob ₹500"
happen twice just by re-sending it? No - three defences:

1. Sequence numbers: every packet carries an increasing number INSIDE the encryption.
   A copy has an old number, so the receiver drops it.
2. A fresh key per connection: replaying a whole recorded session on a new connection
   fails, because the server picks a new random salt and therefore a new session key.
3. Timestamps: a packet held back and delivered later than 60 s is rejected as stale.
"""

import argparse
import json
import socket
import sys
import time

from common import crypto_utils as cu
from common.protocol import MsgType, ReplayError, SecureChannel, recv_frame, send_frame
from security_demo.demo_utils import (
    DemoServer, attack, banner, bad, info, note, ok, parse_target, pause, step, verdict, wait_for, demo_user,
)
from security_demo.sniffer_proxy import C2S, MitmProxy


def run(target=None) -> bool:
    banner("REPLAY TEST - re-sending a captured encrypted packet",
           "Alice talks to the server THROUGH an attacker's proxy that records every packet.")
    server = None
    if target is None:
        server = DemoServer()
        target = (server.host, server.port)
    proxy = MitmProxy(target, listen_port=0).start()
    results = []
    try:
        step(1, "Alice sends a payment request; the attacker records the packet")
        alice = demo_user("127.0.0.1", proxy.port, "alice")
        bob = demo_user(*target, "bob")
        bob_inbox = []
        bob.on("message", lambda m: bob_inbox.append(m["text"]))
        conn = proxy.connections[-1]
        alice.send_message(bob.username, "Pay Bob ₹500 - order #1001")
        wait_for(lambda: bob_inbox)
        ok(f"Bob received: “{bob_inbox[-1]}”")
        captured = [body for direction, _, body in conn.history if direction == C2S][-1]
        attack(f"captured the encrypted packet ({len(captured)} bytes): {captured[:20].hex()}…")
        pause()

        step(2, "Attacker re-sends the exact same packet twice on Alice's connection")
        for attempt in (1, 2):
            attack(f"replay #{attempt}")
            proxy.inject(conn, C2S, captured)
            pause(0.5)
        replays_caught = server is None or wait_for(lambda: len(server.events("REPLAY")) >= 2, 3)
        if len(bob_inbox) == 1 and replays_caught:
            ok("The server REJECTED both copies: the sequence number inside them was already used")
            ok(f"Bob still has exactly ONE payment request ({len(bob_inbox)} message)")
        else:
            bad(f"Bob received {len(bob_inbox)} copies!")
        results.append(len(bob_inbox) == 1 and replays_caught)
        pause()

        step(3, "Attacker replays Alice's WHOLE recorded session on a new connection")
        recorded = [body for direction, _, body in conn.history if direction == C2S]
        info(f"{len(recorded)} recorded packets: the handshake (RSA-encrypted secret) + encrypted messages")
        sock = socket.create_connection(target, timeout=5)
        hello = json.loads(recv_frame(sock))
        info(f"the server greets the attacker with a NEW random salt: {hello['salt']}")
        before = len(server.events("TAMPER")) if server else 0
        for body in recorded:
            send_frame(sock, body)
            time.sleep(0.05)
        attack(f"re-sent all {len(recorded)} packets")
        time.sleep(0.8)
        sock.close()
        session_caught = server is None or len(server.events("TAMPER")) > before
        if session_caught and len(bob_inbox) == 1:
            ok("The server could not decrypt any replayed message: new salt → new session key")
            ok("No login, no messages - the recorded session is useless")
        else:
            bad("The replayed session was accepted!")
        results.append(session_caught and len(bob_inbox) == 1)
        pause()

        step(4, "Attacker holds a packet back and delivers it 2 minutes later")
        key = cu.generate_aes_key()
        a, b = socket.socketpair()
        late_sender = SecureChannel(a, key, "client", clock=lambda: time.time() - 120)
        receiver = SecureChannel(b, key, "server")
        late_sender.send({"type": MsgType.CHAT_MSG, "to": "bob", "text": "Pay Bob ₹500"})
        try:
            receiver.recv()
            bad("The delayed packet was accepted!")
            results.append(False)
        except ReplayError as exc:
            ok(f"Rejected: {exc}")
            results.append(True)
        a.close(), b.close()
        info("(simulated with the real SecureChannel class, so nobody has to wait 60 seconds)")

        note("Sequence numbers and timestamps are INSIDE the encrypted packet, "
             "so the attacker can't change them either.")
        blocked = all(results)
        verdict(blocked, "Replayed and delayed packets are rejected; the payment happened exactly once.")
        for c in (alice, bob):
            c.logout()
        return blocked
    finally:
        proxy.stop()
        if server is not None:
            server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Show that replayed packets are rejected")
    parser.add_argument("--server", help="attack a running server, e.g. 127.0.0.1:5555 (default: start a demo server)")
    sys.exit(0 if run(parse_target(parser.parse_args().server)) else 1)


if __name__ == "__main__":
    main()
