"""
TAMPER TEST - an attacker in the middle flips ONE bit of an encrypted packet.

    python -m security_demo.tamper_test                        # uses its own throwaway server
    python -m security_demo.tamper_test --server 127.0.0.1:5555  # attack your running server instead

Why it fails: every packet is AES-256-GCM. The 16-byte authentication tag is a
cryptographic checksum of the ciphertext computed with the secret session key.
Change a single bit and the tag no longer matches; without the key the attacker
can't compute a new valid tag. The receiver drops the packet - nothing forged
ever reaches the chat.
"""

import argparse
import sys

from security_demo.demo_utils import (
    DemoServer, attack, banner, bad, info, note, ok, parse_target, pause, step, verdict, wait_for, demo_user,
)
from security_demo.sniffer_proxy import C2S, S2C, MitmProxy

HANDSHAKE_PACKETS = 1      # packet #0 from the client is the (plain JSON) handshake


def run(target=None) -> bool:
    banner("TAMPER TEST - flipping one bit inside an encrypted packet",
           "Alice talks to the server THROUGH an attacker's proxy. Bob is connected normally.")
    server = None
    if target is None:
        server = DemoServer()
        target = (server.host, server.port)

    plan = {C2S: False, S2C: False}
    flipped = []

    def on_packet(conn, direction, index, body):
        if plan[direction] and index >= HANDSHAKE_PACKETS:
            plan[direction] = False
            position = len(body) // 2
            tampered = bytearray(body)
            tampered[position] ^= 0x01                       # flip the lowest bit of one byte
            flipped.append((direction, position, body[position], tampered[position]))
            attack(f"flipped 1 bit in a {direction} packet: byte {position} "
                   f"0x{body[position]:02x} → 0x{tampered[position]:02x}  ({len(body)} bytes)")
            return bytes(tampered)
        return body

    proxy = MitmProxy(target, listen_port=0, on_packet=on_packet).start()
    try:
        step(1, "Normal message (the attacker only watches)")
        alice = demo_user("127.0.0.1", proxy.port, "alice")      # through the attacker
        bob = demo_user(*target, "bob")                          # direct
        bob_inbox, alice_alerts = [], []
        bob.on("message", lambda m: bob_inbox.append(m["text"]))
        alice.on("security", lambda kind, text: alice_alerts.append(text))
        alice.send_message(bob.username, "Please transfer ₹100 to Bob")
        if wait_for(lambda: bob_inbox):
            ok(f"Bob received: “{bob_inbox[-1]}”")
        pause()

        step(2, "Attacker modifies a packet from Alice to the server")
        plan[C2S] = True
        alice.send_message(bob.username, "Please transfer ₹100 to Carol")
        pause(1.0)
        server_caught = server is None or wait_for(lambda: server.events("TAMPER"), 3)
        if len(bob_inbox) == 1 and server_caught:
            ok("The server REJECTED the packet: GCM authentication failed — message tampered")
            ok("Bob received nothing - the forged message never reached him")
            if server is not None:
                info(f"logged to {server.log.path.name}: {server.events('TAMPER')[-1]}")
        else:
            bad("The tampered packet was accepted!")
        pause()

        step(3, "Attacker modifies a packet from the server to Alice")
        plan[S2C] = True
        bob.send_message(alice.username, "Your refund of ₹100 is on its way")
        client_caught = wait_for(lambda: alice_alerts, 3)
        if client_caught:
            ok(f"Alice's app REJECTED it: {alice_alerts[-1]}")
        else:
            bad("Alice's app accepted a modified packet!")

        note("Without the session key the attacker can't recompute the 128-bit GCM tag, "
             "so any change - even one bit - is detected.")
        blocked = bool(len(flipped) == 2 and len(bob_inbox) == 1 and server_caught and client_caught)
        verdict(blocked, "Modified packets are detected and dropped in both directions.")
        for c in (alice, bob):
            c.logout()
        return blocked
    finally:
        proxy.stop()
        if server is not None:
            server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Show that tampered packets are rejected")
    parser.add_argument("--server", help="attack a running server, e.g. 127.0.0.1:5555 (default: start a demo server)")
    sys.exit(0 if run(parse_target(parser.parse_args().server)) else 1)


if __name__ == "__main__":
    main()
