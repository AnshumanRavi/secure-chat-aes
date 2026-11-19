"""
BRUTE-FORCE LOGIN TEST - an attacker tries common passwords against an account.

    python -m security_demo.bruteforce_login_test                         # throwaway demo server
    python -m security_demo.bruteforce_login_test --server 127.0.0.1:5555   # your running server

Defences shown:
1. Lockout: after 5 wrong passwords the account is locked for 60 seconds - even the
   RIGHT password is refused during the lockout.
2. PBKDF2 (200,000 rounds): every guess costs the server real CPU work, and stolen
   hashes are just as slow to crack offline.
3. No username enumeration: "wrong password" and "no such user" give the same reply.
"""

import argparse
import sys
import time

from client.network import AuthFailed, ChatClient, ClientError
from security_demo.demo_utils import (
    BOLD, DEMO_PASSWORD, GREY, RED, DemoServer, P, attack, banner, bad, info, note, ok, parse_target,
    pause, step, verdict, demo_user,
)

GUESSES = ["123456", "password", "qwerty123", "alice2024", "letmein1", "iloveyou1", DEMO_PASSWORD]


def try_login(host: str, port: int, username: str, password: str):
    """One login attempt on a fresh connection. Returns (accepted, server reply, milliseconds)."""
    client = ChatClient(host, port, heartbeat_interval=0)
    client.connect()
    started = time.perf_counter()
    try:
        client.login(username, password)
        return True, "logged in", (time.perf_counter() - started) * 1000
    except AuthFailed as exc:
        return False, str(exc), (time.perf_counter() - started) * 1000
    finally:
        client.close()


def run(target=None) -> bool:
    banner("BRUTE-FORCE LOGIN TEST - guessing passwords",
           "The attacker knows the username and tries the most common passwords.")
    server = None
    if target is None:
        server = DemoServer()
        target = (server.host, server.port)
    host, port = target
    try:
        step(1, "A victim account exists (with a decent password)")
        victim = demo_user(host, port, "victim")
        username = victim.username
        victim.logout()
        ok(f"account '{username}' created")
        pause()

        step(2, "Attacker tries common passwords (the 7th guess is actually correct!)")
        locked_at = None
        right_password_refused = False
        for number, guess in enumerate(GUESSES, start=1):
            accepted, reply, ms = try_login(host, port, username, guess)
            shown = P(RED + BOLD, guess) if guess == DEMO_PASSWORD else guess
            attack(f"guess #{number}: {shown:<24} → {reply}  {P(GREY, f'({ms:.0f} ms)')}")
            if accepted:
                bad("The attacker got in!")
                break
            if "locked" in reply.lower() or "try again" in reply.lower():
                locked_at = locked_at or number
                if guess == DEMO_PASSWORD:
                    right_password_refused = True
            time.sleep(0.15)
        if locked_at:
            ok(f"The account LOCKED after {locked_at - 1 if locked_at > 5 else locked_at} wrong guesses")
        if right_password_refused:
            ok("Even the CORRECT password was refused during the lockout")
        pause()

        step(3, "Can the attacker at least find out which usernames exist?")
        _, real_reply, real_ms = try_login(host, port, demo_user(host, port, "probe").username, "wrongpass1")
        _, fake_reply, fake_ms = try_login(host, port, "no_such_user_xyz", "wrongpass1")
        info(f"existing user, wrong password : “{real_reply}”  ({real_ms:.0f} ms)")
        info(f"user that doesn't exist       : “{fake_reply}”  ({fake_ms:.0f} ms)")
        same_reply = real_reply == fake_reply
        if same_reply:
            ok("Identical replies - and an unknown user still costs one PBKDF2 run, so timing doesn't tell either")
        else:
            bad("Different replies reveal which usernames exist")
        pause()

        step(4, "What would a real brute-force attack cost?")
        combos = 62 ** 8
        per_day = 5 * 60 * 24                      # 5 guesses per 60-second lockout window
        years = combos / per_day / 365
        info(f"8-character passwords (a-z, A-Z, 0-9): {combos:.2e} possibilities")
        info(f"with the lockout: at most {per_day:,} guesses per day per account")
        print(P(BOLD, f"    → about {years:.1e} years to try them all"))
        info("and every guess also costs the server a 200,000-round PBKDF2 computation")

        if server is not None:
            note(f"server log: {len(server.events('AUTH_FAIL'))} failed logins, "
                 f"{len(server.events('LOCKOUT'))} lockout events recorded in security.log")
        blocked = bool(locked_at) and right_password_refused and same_reply
        verdict(blocked, "Password guessing is stopped by the lockout; usernames can't be enumerated.")
        return blocked
    except ClientError as exc:
        bad(f"Could not reach the server: {exc}")
        return False
    finally:
        if server is not None:
            server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Show the login lockout after 5 wrong passwords")
    parser.add_argument("--server", help="attack a running server, e.g. 127.0.0.1:5555 (default: start a demo server)")
    sys.exit(0 if run(parse_target(parser.parse_args().server)) else 1)


if __name__ == "__main__":
    main()
