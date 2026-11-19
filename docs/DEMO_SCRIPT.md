# SecureChat — 10-Minute Live Demo

A step-by-step plan: what to have ready, what to click, and what to say. Times are cumulative.
Lines in *italics* are what you say; **bold** is what you click or type.

---

## Before the audience arrives (10 minutes of preparation)

**Machines.** PC 1 runs the server and Alice. PC 2 runs Bob. (No second PC? Run everything on PC 1 and start
`run_client.bat` twice — the demo works the same, just say "imagine this window is the other laptop".)

**Checklist**

- [ ] Both PCs on the same Wi-Fi or phone hotspot; `allow_firewall.bat` already run as administrator on PC 1
      (see `docs/DEPLOYMENT.md`). Quick test from PC 2: `Test-NetConnection <PC1-IP> -Port 5555`.
- [ ] Both clocks synced (*Settings → Time & language → Date & time → Sync now*).
- [ ] Start from clean data so the first-connection screens appear: rename `data` and `keys` on PC 1 and
      `client_settings.json` / `data` on PC 2 (keep the old folders as a backup).
- [ ] Two small files on the desktop to send: `photo.jpg` and `report.pdf`.
- [ ] Open three terminals on PC 1 in the project folder and enlarge the font (Ctrl + scroll):
      - **Terminal A** — for the server
      - **Terminal B** — PowerShell with the environment active: `.venv\Scripts\activate` (attacks)
      - **Terminal C** — for the "attacked" client in step 5:00
- [ ] Turn off Windows notifications/Focus assist so nothing private pops up.
- [ ] Do one full rehearsal with a timer.

**Accounts used:** `alice` (PC 1), `bob` (PC 2), `carol` (PC 1, through the "attacker"). Password for all:
`Demo2026pass`.

---

## 0:00 – 0:45 · The problem

*"On a shared Wi-Fi anyone can capture packets. A chat that sends plain text leaks every message and every
password. SecureChat is a WhatsApp-style chat where every packet is encrypted and authenticated with
AES-256-GCM, the key is exchanged with RSA-2048, and I'll show you live that sniffing, tampering, replaying
and password guessing all fail."*

## 0:45 – 1:45 · Start the server (PC 1)

1. **Terminal A:** type `run_server.bat --show-bodies` and press Enter.
   (`--show-bodies` makes the server print any message text it *can* read — we use it at 8:00.)
2. Type a passphrase twice (first start only).

*"On first start the server generates an RSA-2048 key pair. The private key is saved encrypted with this
passphrase. Here is the address other PCs use, and here is the key's fingerprint — a SHA-256 hash of the
public key. Remember the first four groups."* (Point at the `>>> Clients on other PCs should connect to:`
line and the fingerprint.)

## 1:45 – 3:15 · Connect two users

1. **PC 1:** double-click **`run_client.bat`** → **Find server on LAN**.
   *"The app broadcasts a small UDP request; the server answers with its address. Convenient — but not trusted,
   anyone could answer. The real check comes next."*
2. **Create account** → username `alice`, password → **Create account**.
3. The **Verify the server** dialog appears.
   *"This is the first connection, so the app shows the server's fingerprint. I compare it with the server
   window — it matches — so nobody is in the middle. From now on it is pinned: if the key ever changes, the
   app refuses or shows a red warning."* → **It matches – connect**.
4. **PC 2:** same steps for `bob`.
   *"Behind the scenes: the client made a random 256-bit secret, encrypted it with the server's RSA public key
   using OAEP, and both sides derived an AES-256 session key with HKDF — a new key for every connection.
   The password was sent only inside that encrypted channel and is stored as a salted PBKDF2 hash."*

## 3:15 – 5:00 · Chat like WhatsApp — and look at the wire

1. **PC 1 (Alice):** open Bob's chat, type *"Hi Bob, the exam is at 10"*, **Send**.
   *"One grey tick: the server got it. Two grey ticks: Bob's app got it."*
2. **PC 2 (Bob):** open the chat → on PC 1 the ticks turn **blue**. Start typing → Alice sees *typing…*.
3. **Point at the server window.**
   *"Every line is one packet. The server sees only hex — nonce, ciphertext, tag. Even whether it's a chat
   message or a typing notification is inside the encryption."*
4. **PC 1:** right-click the message → **Message info**.
   *"This is the actual packet that carried the message: a 12-byte random nonce, the ciphertext and a
   16-byte authentication tag. The same text sent twice would look completely different because the nonce is
   new every time."*
5. **PC 2 (Bob):** attach (📎) **`photo.jpg`**, then **`report.pdf`**.
   *"Files go in 64 KB chunks, each its own encrypted packet, and the receiver checks a SHA-256 of the whole
   file before keeping it."*

## 5:00 – 6:30 · The eavesdropper

1. **Terminal B:** `python -m security_demo.sniffer_proxy`
   *"This is the attacker: a proxy between a client and the server that prints every packet it sees."*
2. **Terminal C:** `run_client.bat --port 6666` (a new app window, connected *through* the attacker) →
   **Create account** `carol`.
   The fingerprint dialog appears again (new address) — **point out that it is the real server's
   fingerprint**: *"The attacker can forward the key but can't replace it without the fingerprint changing."*
   → **It matches – connect**.
3. Carol sends Bob *"My bank PIN is 4711"*.
4. **Point at Terminal B:** hex, *"UTF-8 decode attempt: ✗ unreadable"*, entropy close to the maximum.
   *"The attacker has the packet but only random-looking bytes. Bob still got the message normally."*
5. **Ctrl + C** in Terminal B → summary. *"The only readable packets are the two handshake messages — a public
   key, a salt and an RSA-encrypted secret. Nothing secret."* Close Carol's window.

## 6:30 – 8:00 · Every attack, with a scorecard

**Terminal B:** `python -m security_demo.run_all` (about 15 seconds, on its own throwaway server).

Narrate as it runs:

* **Eavesdropping** — *"the same secret through an insecure plain-text chat is readable; through SecureChat
  it isn't."*
* **Tampering** — *"one bit flipped: the GCM tag no longer matches, the packet is dropped. The attacker can't
  compute a new tag without the key."*
* **Replay** — *"a captured packet sent again: rejected by the sequence number; a whole recorded session
  replayed later: the server's new salt gives a new key, so nothing decrypts."*
* **Brute force** — *"after five wrong passwords the account locks for 60 seconds, and an unknown username
  gives exactly the same answer, so attackers can't even find accounts."*

End on the **SECURITY SCORECARD** — four × **BLOCKED ✓**.

## 8:00 – 9:00 · Even the server can't read it (end-to-end)

1. **Point at the server window** (started with `--show-bodies`): the Alice ↔ Bob messages appear as
   `[E2E ciphertext] … (no key on the server - cannot decrypt)`.
   *"One-to-one chats are also end-to-end encrypted: the two apps agree on a key with elliptic-curve
   Diffie–Hellman. The server only relays ciphertext — even with all of its own keys it can't read it."*
2. **PC 1:** in Bob's chat, **⋮ → Verify security code**. Show it on PC 2 as well.
   *"The server hands out the public keys, so it could cheat by giving Alice its own key. This 60-digit code
   is computed from both real keys — if the numbers on both screens match, nobody swapped a key. Same idea as
   WhatsApp's security code."*
3. *(If time allows — the most convincing part)* **PC 1: ⋮ (above the chat list) → Settings → Security →**
   switch off **"End-to-end encrypt my 1-to-1 messages"**, close Settings, send Bob *"now the server can read
   this"*. The server window prints `body readable by the server: 'now the server can read this'`.
   *"Without end-to-end mode the network is still protected, but the server decrypts every message to
   re-encrypt it for Bob. With it on, it can't."* → switch it back **on**.
   (Group chats are hop-by-hop like this too — that's in my future work.)

## 9:00 – 9:40 · Data at rest and performance

1. **PC 1:** **⋮ → Settings → Security → Show what's stored on disk.**
   *"Chat history on the laptop is encrypted with a key derived from my password — the file contains only
   ciphertext, and even the contact names are replaced by HMACs."*
2. Show `performance/graphs/network_localhost_latency.png` (or the report).
   *"Cost: AES-256-GCM runs at about 1 GB per second, the handshake takes 2 milliseconds once per
   connection, and the whole secure protocol adds about two-thirds of a millisecond per message —
   about 150 times less than anyone could notice."*

## 9:40 – 10:00 · Close

*"So: AES-256-GCM for confidentiality and integrity, RSA-OAEP and HKDF for a fresh key every session,
sequence numbers and timestamps against replay, PBKDF2 and lockout for passwords, and end-to-end encryption
with a security code against a curious server — all verified by 287 automated tests and the attacks you just
saw. Thank you — happy to take questions."*

---

## If something goes wrong

| Problem | Do this |
|---|---|
| PC 2 can't connect / Find server finds nothing | Type PC 1's IP from the server window. Still failing → switch both to the phone hotspot, or continue on one PC with two windows |
| A "key CHANGED" warning appears | Old pinned settings: click **Disconnect**, then delete `client_settings.json` on that PC and reconnect |
| Messages don't arrive | Check both clocks (replay protection rejects packets > 60 s off) |
| Server asks for a passphrase you forgot | Rename the `keys` folder and restart — a new key pair is made (clients see the new-key dialog) |
| Anything crashes | `python -m security_demo.run_all` works on its own throwaway server — use it and the screenshots in `docs/PROJECT_REPORT.md` |

## Questions to expect right after the demo

See `docs/VIVA_QUESTIONS.md`. The most likely: **why GCM over CBC** (Q9), **what a nonce is and why it must
never repeat** (Q10), **how you stop a man-in-the-middle** (Q21), **how replay is prevented** (Q26),
**forward secrecy** (Q23 — answer honestly: not yet), **what PBKDF2 and the salt do** (Q32–33).
