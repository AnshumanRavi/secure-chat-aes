# SecureChat — Viva Questions and Answers

52 questions an examiner is likely to ask, with short answers you can say out loud and the project facts
to back them up. Numbers come from `performance/PERFORMANCE_REPORT.md` (Intel Core i5-13500H laptop).

**Sections:** [A. Cryptography basics](#a-cryptography-basics) ·
[B. Key exchange and authentication of the server](#b-key-exchange-and-authentication-of-the-server) ·
[C. The protocol](#c-the-protocol) · [D. Passwords and accounts](#d-passwords-and-accounts) ·
[E. End-to-end encryption](#e-end-to-end-encryption) · [F. Files and local data](#f-files-and-local-data) ·
[G. Implementation, testing and performance](#g-implementation-testing-and-performance) ·
[H. Big-picture questions](#h-big-picture-questions)

---

## A. Cryptography basics

**1. What is the difference between symmetric and asymmetric encryption?**
Symmetric encryption (AES) uses the **same key** to encrypt and decrypt. It is very fast but both sides must
already share the key. Asymmetric encryption (RSA, ECC) uses a **key pair**: anyone can encrypt with the
public key, only the private-key holder can decrypt. It solves key distribution but is slow and can only
encrypt small data. SecureChat uses both: RSA once per connection to send a random secret, AES for
everything after (hybrid encryption, like TLS).

**2. Why did you choose AES?**
It is the NIST standard (FIPS 197), has no practical attacks after 20+ years of analysis, is accelerated in
hardware (AES-NI), and is what TLS, WhatsApp and disk encryption use.

**3. Why AES-256 and not AES-128? Is it slower?**
AES-256 uses 14 rounds instead of 10, giving a bigger security margin (including against Grover's quantum
search, which would halve the effective key length). On my laptop it costs almost nothing: at 1 MB,
AES-GCM ran at 1,027 MB/s with AES-128 and 1,015 MB/s with AES-256 — about 1 % slower, because AES-NI does
the rounds in hardware.

**4. What is a block cipher mode of operation and why do we need one?**
AES only encrypts one 16-byte block. A mode defines how to encrypt longer messages securely — how blocks are
chained, how randomness (IV/nonce) is used, and whether integrity is provided. ECB, CBC, CTR and GCM are
modes.

**5. What is the "ECB penguin" problem?**
ECB encrypts each 16-byte block independently with the same key, so identical plaintext blocks give
identical ciphertext blocks. If you encrypt a bitmap image of the Linux penguin with ECB, the outline of the
penguin is still visible in the ciphertext. ECB leaks patterns and has no IV and no integrity. It is in my
benchmarks only as an insecure baseline (`test_ecb_round_trip_and_pattern_leak` shows the leak).

**6. How does CBC work and what is its weakness?**
Each plaintext block is XORed with the previous ciphertext block before encryption; the first block uses a
random IV. It hides patterns, but it gives **no integrity**, needs padding, and if the padding check leaks
(a "padding oracle", Vaudenay 2002) an attacker can decrypt messages. It is only safe with a separate MAC
checked *before* decrypting (encrypt-then-MAC).

**7. What is wrong with plain CTR mode?**
CTR turns AES into a stream cipher: ciphertext = plaintext XOR keystream. Flipping a bit in the ciphertext
flips the same bit in the plaintext, and the receiver cannot detect it (bit-flipping attack). So CTR gives
confidentiality but no integrity.

**8. What is GCM?**
Galois/Counter Mode = CTR-mode encryption **plus** a GHASH-based authentication tag computed over the
ciphertext and the associated data. It is an AEAD scheme: authenticated encryption with associated data
(NIST SP 800-38D).

**9. Why did you choose AES-GCM over AES-CBC?** *(very likely)*
1. **Integrity built in** — one primitive gives confidentiality and tamper detection; CBC needs a separate
   HMAC that must be implemented correctly.
2. **No padding**, so no padding-oracle attacks.
3. **Faster for large data** — 1,015 MB/s vs 388 MB/s for CBC + HMAC at 1 MB (2.6×), because it is one pass
   and parallelisable.
4. **Smaller overhead** — 28 bytes per message vs 64.
5. **Standard** — TLS 1.3 only allows AEAD ciphers.

Honestly: for tiny messages CBC + HMAC was faster in PyCryptodome (24 µs vs 44 µs for 1 KB) because GCM has
a fixed set-up cost, but 20 µs is invisible next to a network round trip.

**10. What is a nonce and why must it never repeat?** *(very likely)*
A nonce is a "number used once" — a value that makes each encryption under the same key unique. In GCM, if
the same key and nonce are used twice: (a) the two keystreams are identical, so XORing the ciphertexts gives
the XOR of the two plaintexts; and (b) the attacker can solve for the GHASH authentication key and then
**forge** valid tags for any message (Joux's "forbidden attack"). So nonce reuse breaks both
confidentiality and integrity.

**11. How do you make sure nonces never repeat?**
Every packet gets a fresh **random 12-byte (96-bit) nonce** from the operating system's CSPRNG
(`get_random_bytes`), and every connection uses a **new session key**. The chance of a repeat under one key
is about n²/2⁹⁷ for n messages — negligible for a chat session (NIST limits random nonces to 2³² messages per
key; a chat session sends far fewer). `test_nonces_are_unique` checks this.

**12. What does the authentication tag do?**
It is a 16-byte (128-bit) cryptographic checksum of the ciphertext and associated data, computed with the
secret key. The receiver recomputes it; if even one bit of the ciphertext, nonce, tag or associated data
changed, the tags don't match and **decryption returns an error instead of plaintext**. Without the key an
attacker cannot compute a valid tag for modified data.

**13. What is associated data (AAD) and what do you put in it?**
Data that is authenticated by the tag but not encrypted. SecureChat uses `SecureChat/1|C2S` for client→server
packets and `SecureChat/1|S2C` for server→client. This binds every packet to its direction, so an attacker
cannot take a packet the server sent and reflect it back to the server. End-to-end messages use
`e2e|v1|sender|recipient|message-id`, so the server can't re-address them.

**14. What happens when a packet fails the tag check?**
`aes_decrypt` raises `IntegrityError`; the packet is dropped (never parsed), logged as **TAMPER** with its
ciphertext in `security.log`, and counted as a violation. After 3 violations the server closes the
connection. The app shows a "⚠ Security: …" notification. Demo: `python -m security_demo.tamper_test`.

---

## B. Key exchange and authentication of the server

**15. Why is RSA used only for the key exchange and not for messages?**
RSA is slow (one private-key operation took 0.62 ms here — AES-GCM can encrypt about 600 KB in that time),
with OAEP it can only encrypt 190 bytes per operation, and it gives no integrity. So RSA transports one
32-byte secret per connection and AES does the rest. This is hybrid encryption, as in TLS.

**16. Walk me through your handshake.**
1. Server sends its RSA-2048 public key and a fresh random 16-byte salt.
2. Client checks the key's fingerprint (pinned, or shown to the user the first time) and refuses keys under
   2048 bits.
3. Client generates a random 32-byte secret, encrypts it with RSA-OAEP-SHA256 and sends it.
4. Both derive the session key = HKDF-SHA256(secret, salt).
5. Server sends an AES-GCM encrypted `HANDSHAKE_OK` — key confirmation.
6. Login/registration then happens inside the encrypted channel.

**17. What is OAEP and why not textbook RSA or PKCS #1 v1.5?**
Textbook RSA is deterministic (the same message always encrypts the same way) and malleable. OAEP adds
randomised padding using a hash (SHA-256 here), so every encryption differs, and it is proven secure against
chosen-ciphertext attacks. PKCS #1 v1.5 padding is vulnerable to Bleichenbacher's padding-oracle attack.

**18. Is RSA-2048 secure enough?**
It gives about 112 bits of security, which NIST (SP 800-57) accepts until 2030. For longer-term protection
3072-bit RSA or elliptic-curve keys would be used.

**19. Why do you use HKDF instead of using the random secret directly as the AES key?**
HKDF is a proper key derivation function: it mixes in the server's salt (so both sides contribute
randomness), binds the key to a context string ("SecureChat v1 session key"), and lets one secret produce
several independent keys if needed. It is standard practice (RFC 5869, used in TLS 1.3 and Signal).

**20. Why does the server send a salt?**
So the session key depends on randomness from **both** sides. If an attacker recorded an entire session and
replayed the client's packets to the server later, the server would pick a new salt, derive a different key,
and every replayed packet would fail the GCM check (`test_recorded_session_cannot_be_replayed`).

**21. How do you prevent a man-in-the-middle attack?** *(very likely)*
An attacker in the middle would have to give the client **its own** RSA public key (it doesn't have the
server's private key). Its fingerprint (SHA-256 of the public key) would differ from the real server's. The
client shows the fingerprint on first connection to compare with the server window, then **pins** it; any
later mismatch aborts the handshake before the secret is sent and shows a red warning. Key confirmation
(`HANDSHAKE_OK`) also proves the server could decrypt the secret.

**22. What is trust on first use (TOFU) and its weakness?**
The client trusts the key it sees the first time (after the user compares it) and pins it, like SSH. The
weakness: if a user skips the comparison on the very first connection while an attacker is already in the
middle, the attacker's key gets pinned. A certificate authority would remove this, at the cost of more
infrastructure.

**23. Does your system have forward secrecy?** *(likely trap question)*
**No.** The session secret is encrypted with the server's long-term RSA key. If someone recorded traffic
and **later** stole the server's private key (and its passphrase), they could decrypt those recordings.
Forward secrecy needs **ephemeral** Diffie–Hellman per session (as TLS 1.3 does with ECDHE), where the key
material is deleted after use. That is listed as future work.

**24. How would you add forward secrecy?**
Replace RSA key transport with ephemeral ECDH (X25519): both sides generate a fresh key pair per connection,
the server signs its ephemeral public key with its long-term key (so it is still authenticated), and the
ephemeral private keys are deleted afterwards. For end-to-end messages, adopt X3DH + the Double Ratchet like
Signal.

---

## C. The protocol

**25. Why do you need a length prefix on every packet?**
TCP is a byte stream with no message boundaries: one `recv()` may return half a message or two messages. Each
packet is sent as `[4-byte big-endian length][body]`, and `recv_exact` keeps reading until it has exactly that
many bytes.

**26. How do you prevent replay attacks?** *(very likely)*
Four layers:
1. Every message has a **sequence number** inside the encrypted payload; the receiver rejects any number
   that is not larger than the last one seen.
2. Every message has a **timestamp**; anything more than **60 seconds** off is rejected.
3. **Per-session keys** (server salt) — a packet from an old session can't even be decrypted.
4. **Direction-bound AAD** stops reflection.
Because the sequence number and timestamp are inside the ciphertext, the attacker can't change them without
breaking the tag. Demo: `python -m security_demo.replay_test`.

**27. Why do you need both a sequence number and a timestamp?**
The sequence number stops replays **within** a session; the timestamp stops a captured packet from being
held back and delivered much later (a delay attack), and gives a second line of defence. The trade-off: the
two PCs' clocks must agree within 60 seconds.

**28. What is a reflection attack and how do you stop it?**
Sending a victim its own message back as if it came from the other side. Both directions use the same
session key, so without protection a server-to-client packet could be replayed towards the server. The
direction label in the associated data (`C2S`/`S2C`) makes such a packet fail the tag check.

**29. What can an eavesdropper still see?**
IP addresses and ports, the timing and approximate size of packets, and the handshake's public key, salt and
RSA ciphertext — nothing secret. Even the message **type** is inside the encryption, so they can't tell a
chat message from a typing notification. The server (not the eavesdropper) knows who talks to whom.

**30. How do you stop a malicious client from crashing the server?**
Frame size limits checked before allocating memory (8 KB during the handshake, 1 MB after), a 10-second
handshake timeout, a 60-second login timeout, validation of every field with clear error codes (39
malformed-request tests), a violation counter that disconnects after 3 bad packets, caps on queued offline
messages and tracked failed logins, and a catch-all per connection so one client's error never affects
others.

---

## D. Passwords and accounts

**31. How are passwords stored?**
Never in plain text. The server stores `pbkdf2_sha256$200000$<salt>$<hash>`: PBKDF2-HMAC-SHA256 with a random
16-byte salt per user and 200,000 iterations. The password is sent only inside the encrypted channel.

**32. What is PBKDF2 and why is it better than SHA-256?**
SHA-256 is designed to be fast, so a stolen hash can be attacked with billions of guesses per second. PBKDF2
repeats HMAC-SHA256 many times (200,000 here), so each guess costs the attacker as much as a login costs the
server: I measured 13.5 ms per hash → only **74 guesses per second per CPU core**, versus 10,538 at 1,000
iterations.

**33. What does the salt do?**
It is random per user and stored next to the hash. (1) Two users with the same password get different
hashes, so you can't spot shared passwords. (2) Precomputed rainbow tables are useless — the attacker has to
attack each account separately.

**34. Why 200,000 iterations? Is that enough?**
It keeps a login under 15 ms while slowing attackers 200,000×. The current OWASP recommendation for
PBKDF2-SHA256 is 600,000; my measurements predict ~42 ms per login at 600,000 — still unnoticeable — so
raising it is an easy improvement. GPUs are much faster than CPU cores, so memory-hard Argon2 would be even
better.

**35. How do you stop online password guessing, and username enumeration?**
After 5 wrong passwords within 15 minutes an account is locked for 60 seconds. Unknown usernames and wrong
passwords get the **same** error message, unknown usernames still take one PBKDF2 computation (same timing),
and unknown usernames lock the same way — so the attacker can't learn which accounts exist.

**36. How does automatic reconnection work without storing the password?**
After login the server gives the client a random 256-bit **resume token**. The server stores only its
SHA-256 hash (a stolen database contains no usable tokens). Each token works **once**, is replaced on every
resume, is tied to the username, expires after 24 hours and is revoked at logout.

**37. Why do you use `hmac.compare_digest` to compare hashes?**
A normal `==` stops at the first different byte, so the time taken leaks how many bytes matched (a timing
attack). `compare_digest` takes the same time regardless.

---

## E. End-to-end encryption

**38. What is the difference between hop-by-hop and end-to-end encryption?**
Hop-by-hop: each client has its own key with the server; the server decrypts and re-encrypts, so it can read
everything. End-to-end: the message key is known only to the two users; the server relays ciphertext it
cannot decrypt. SecureChat does hop-by-hop always and adds end-to-end for one-to-one chats.

**39. How does your end-to-end mode work?**
Each app has a long-term ECC **P-256** identity key pair stored encrypted in its local history; only the
public key is uploaded. Alice computes ECDH(Alice private, Bob public), Bob computes ECDH(Bob private,
Alice public) — the same shared secret — which HKDF turns into an AES-256 key. Each message is AES-GCM
sealed with that key and `sender|recipient|id` as associated data, then sent through the normal encrypted
channel (encrypted twice on the wire). `--show-bodies` on the server proves it only sees ciphertext.

**40. If the server distributes the public keys, can't it cheat?**
Yes — it could hand Alice its own key instead of Bob's (a man-in-the-middle). That is why both users can open
**Verify security code**: a 60-digit number derived from both real public keys (SHA-512 iterated 5,200
times, like Signal's safety number). If the server swapped a key, the numbers on the two screens differ. The
app also warns when a contact's key changes.

**41. What does the server still learn in end-to-end mode?**
Metadata: who sends to whom, when, and message sizes. Group messages and files are not end-to-end encrypted
in this version.

**42. How does this compare with WhatsApp / Signal?**
WhatsApp uses the Signal Protocol: X3DH key agreement with one-time pre-keys plus the **Double Ratchet**,
which gives a new key for every message (forward secrecy and post-compromise security), Sender Keys for
end-to-end groups, and the Noise framework for the client–server transport. SecureChat implements the same
core ideas — AEAD, authenticated key agreement, key verification with a security code — but with static
keys, so it has no forward secrecy, and groups are hop-by-hop.

---

## F. Files and local data

**43. Each file chunk is already AES-GCM authenticated — why also SHA-256 the whole file?**
GCM proves each **chunk** is unmodified, but not that the **file** is complete and in the right order (a chunk
could be missing, duplicated or reordered, or the sender could announce one file and send another). The
SHA-256 in `FILE_START` lets the receiver prove the reassembled file is exactly what the sender hashed; if not,
the partial file is deleted.

**44. What is path traversal and how do you prevent it?**
A malicious sender names a file `..\..\Windows\evil.exe` so the receiver writes outside the downloads
folder. `safe_filename` keeps only the last name component and replaces unsafe characters. It also removes
invisible Unicode characters (a right-to-left override can make `photo‮gpj.exe` look like `photoexe.jpg`)
and renames Windows device names like `CON`.

**45. How is the chat history on each PC protected?**
A key is derived from the user's password with PBKDF2 (never stored). HKDF splits it into separate keys for
encryption, indexing and password checking. Each row is AES-GCM encrypted with its message id as associated
data (rows can't be swapped), and chats are indexed by an HMAC of the contact's name, so a stolen file
doesn't even show who you talk to. Settings → Security → *Show what's stored on disk* demonstrates it.

**46. What protects the server's own keys and the offline messages?**
The RSA private key file is encrypted with a passphrase (PKCS #8, PBKDF2 + AES-256). Offline messages are
AES-GCM encrypted with a random storage key, which is itself RSA-encrypted — so a stolen database file is
useless without the private key and passphrase.

---

## G. Implementation, testing and performance

**47. Why `secrets`/`get_random_bytes` and not Python's `random` module?**
`random` is a Mersenne Twister: fast but predictable — after observing 624 outputs you can predict all future
ones. Keys and nonces must come from a cryptographically secure generator (the OS CSPRNG).

**48. How does the server handle many clients, and how does the GUI stay responsive?**
One thread per client connection; shared state (online users, database) is protected by locks, and each
channel has send and receive locks so packets never interleave. In the GUI, connecting, logging in,
reconnecting and uploads run on `QThread` workers; network events reach the GUI through Qt signals; sends
time out after 10 s, after which the app reconnects automatically and resends pending messages.

**49. How did you test that the security actually works?**
287 automated tests (pytest), many written as attacks: flipping bits, replaying packets, reflecting them,
forging the sender, wrong fingerprints, weak keys, malformed and oversized requests, path traversal,
tampered files. 92 % statement coverage of the crypto, protocol and server code. Plus live demos:
`python -m security_demo.run_all` runs eavesdropping, tampering, replay and brute-force attacks and prints a
scorecard — all **BLOCKED**.

**50. How much does all this security cost in performance?**
- **Handshake:** 2.1 ms, paid once per connection.
- **Login:** about 21 ms, mostly PBKDF2.
- **Each message:** the full protocol adds about 0.66 ms to a round trip on one PC. That's about 150× below the ~100 ms at which people notice a delay.
- **Raw speed:** AES-256-GCM runs at about 1 GB/s.
- **Server limit:** one Python server process handles about 1,300 messages per second. Python's global interpreter lock is the limit, not the cryptography.

---

## H. Big-picture questions

**51. What are the main limitations of your project?**
- **No forward secrecy:** RSA key transport and static end-to-end keys.
- **End-to-end mode is one-to-one text only:** group chats and files are protected hop-by-hop.
- **Metadata:** the server sees who talks to whom.
- **Trust on first use:** a user who skips the first fingerprint check can be fooled once.
- **Clocks:** the two PCs' clocks must agree within 60 s.
- **Scale:** one Python process, about 1,300 messages per second.
- **Password hashing:** PBKDF2 at 200,000 rounds is below today's recommendation.

**52. If you had more time, what would you add?**
- **Forward secrecy:** ephemeral ECDH (X25519) for the transport, and X3DH + Double Ratchet for end-to-end chats.
- **End-to-end groups and files:** Sender Keys, as WhatsApp uses.
- **Stronger password hashing:** Argon2id.
- **Server authentication:** a small private certificate authority instead of trust on first use.
- **A faster server:** an asyncio or multi-process design.
- **Proof:** formal verification of the handshake with ProVerif or Tamarin.

---

### Quick numbers to remember

| | |
|---|---|
| AES key / nonce / tag | 256 bit / 96 bit / 128 bit |
| Packet overhead | 4-byte length + 12-byte nonce + 16-byte tag = 32 bytes |
| RSA | 2048-bit, OAEP with SHA-256, key fingerprint = SHA-256 of the public key |
| Session key | HKDF-SHA256(32-byte secret, 16-byte server salt) |
| Replay window | sequence numbers + ±60 s timestamps |
| Passwords | PBKDF2-HMAC-SHA256, 16-byte salt, 200,000 rounds, lockout 5 tries / 60 s |
| E2E | ECDH P-256 + HKDF, AES-256-GCM, 60-digit security code |
| Files | 64 KB chunks, max 25 MB, SHA-256 verified |
| Tests | 287 tests, 92 % coverage of common/ + server/ |
| Speed | GCM 1,015 MB/s · handshake 2.1 ms · +0.66 ms per message · PBKDF2 13.5 ms |
