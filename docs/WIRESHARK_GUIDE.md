# Wireshark Guide: Proving the Chat Traffic Is Encrypted

This guide shows how to capture SecureChat traffic with **Wireshark**, the standard network-analysis tool, and prove that an eavesdropper sees only ciphertext. You then repeat the capture on the deliberately insecure chat, so you can show the difference side by side.

Time needed: about 15 minutes. You need the project set up from Prompts 1–13.

---

## 1. Install Wireshark (once)

1. Download Wireshark for Windows from **wireshark.org** and run the installer.
2. When the installer offers **Npcap**, install it, and **tick "Support loopback traffic"**.
   Without this option, Wireshark can't see traffic between two programs on the *same* PC (127.0.0.1).
3. Start Wireshark. If it says "no interfaces found", run it once **as Administrator**.

---

## 2. Pick the right interface

| Your setup | Interface to double-click in Wireshark |
|---|---|
| Server and both clients on **one PC** (127.0.0.1) | **Adapter for loopback traffic capture** |
| **Two PCs** on Wi-Fi / LAN | **Wi-Fi** (or **Ethernet**) on either PC |

> Tip: before you start, type the **capture filter** `tcp port 5555` into the box under "Capture… using this filter". That way Wireshark only records chat traffic.

---

## 3. Capture an encrypted conversation

1. Start the capture (the blue shark-fin button).
2. Start the server: `python -m server.server`
3. Start two clients (`python -m client.gui.main`) and log in as Alice and Bob.
4. Send a message with something easy to search for, for example:
   **`my bank PIN is 4711`**
5. Stop the capture (the red square).
6. In the **display filter** bar at the top, type:
   ```
   tcp.port == 5555
   ```
   and press Enter.

You'll see the TCP handshake (SYN, SYN-ACK, ACK) followed by packets marked `[PSH, ACK]`. Those carry the data.

---

## 4. Follow the TCP stream

1. Right-click any packet → **Follow** → **TCP Stream**.
2. A window opens with the whole conversation. Red = client → server, blue = server → client.
3. Here's what you'll see, and what it means:

| What you see | What it is | Is it secret? |
|---|---|---|
| `{"type": "HANDSHAKE_PUBKEY", "public_key": "-----BEGIN PUBLIC KEY-----…", "salt": "…"}` | The server's RSA-2048 **public** key and a random salt | No, public keys are meant to be shared |
| `{"type": "HANDSHAKE_SESSION_KEY", "encrypted_secret": "…"}` | The session secret, **RSA-OAEP encrypted** | Yes, only the server's private key can open it |
| Everything after that: random-looking bytes | AES-256-GCM packets: `[4-byte length][12-byte nonce][ciphertext][16-byte tag]` | Yes, unreadable |

4. At the bottom, switch **"Show data as"** to **Hex Dump** to see the raw bytes, the same view as the demo sniffer.

---

## 5. Search for the secret (the key proof)

1. Close the stream window. Go to **Edit → Find Packet** (Ctrl+F).
2. Set the search to **String**, search in **Packet bytes**, and type `4711`.
3. Click **Find**.

**Result: "No packet found."** The PIN is nowhere on the wire. Search for `PIN`, `bank` and `alice` too; none of them appear after the handshake. Even the message type (`CHAT_MSG`) is hidden, because it's inside the encryption.

---

## 6. Compare with the insecure chat

Start the deliberately insecure chat. It sends plain text on **port 5556**:

```powershell
python -m security_demo.insecure_chat server                   # terminal 1
python -m security_demo.insecure_chat client --name alice      # terminal 2
python -m security_demo.insecure_chat client --name bob        # terminal 3
```

1. Capture again, this time with the filter `tcp.port == 5556`.
2. Send `my bank PIN is 4711` from Alice.
3. **Follow → TCP Stream**: you read `{"from": "alice", "text": "my bank PIN is 4711"}` in plain text.
4. **Find Packet → String → `4711`** finds it straight away.

This is exactly what anyone on the same Wi-Fi network could do to an unencrypted chat.

---

## 7. Bonus checks

- **Tamper and replay attacks:** run `python -m security_demo.run_all` while capturing. Each attack's packets show up in Wireshark, and the scorecard shows them all blocked.
- **Statistics → Conversations → TCP:** shows each client's connection. Every connection has its own session key, so the same message looks completely different on each one.
- **End-to-end mode:** start the server with `python -m server.server --show-bodies`. With E2E on, the server window itself prints only `[E2E ciphertext]`. Not even the server can read the message.
- **The demo sniffer** does the same job without Wireshark:
  `python -m security_demo.sniffer_proxy`, then connect a client to port **6666**.

---

## 8. Screenshots for the report

Take these screenshots (Windows: **Win + Shift + S**) and save them to `docs/screenshots/`:

| # | Screenshot | Suggested caption |
|---|---|---|
| 1 | Packet list filtered with `tcp.port == 5555` | "SecureChat traffic captured with Wireshark on port 5555." |
| 2 | **Follow TCP Stream** on SecureChat (ASCII view) | "After the RSA handshake, all chat data is AES-256-GCM ciphertext." |
| 3 | The same stream as **Hex Dump** | "Encrypted packets: 12-byte nonce, ciphertext and 16-byte GCM tag." |
| 4 | **Find Packet** for `4711` → "No packet found" | "The secret message does not appear anywhere on the network." |
| 5 | **Follow TCP Stream** on the insecure chat (port 5556) | "Without encryption, the same message is readable by anyone sniffing the network." |
| 6 | The packet details pane of one SecureChat data packet | "A single encrypted packet: TCP payload contains only ciphertext." |
| 7 | The `run_all` scorecard (terminal) | "All simulated attacks (eavesdropping, tampering, replay, brute force) were blocked." |
| 8 | Server window with `--show-bodies` showing `[E2E ciphertext]` | "With end-to-end encryption even the server cannot read the message." |

---

## 9. What to say during the demo

1. "This is Wireshark capturing everything on port 5555, exactly what an attacker on the Wi-Fi would see."
2. "The handshake is readable, but it only contains the server's **public** key and an **RSA-encrypted** secret."
3. "Everything after that is AES-256-GCM. Let me search for the PIN I just sent… nothing."
4. "Now the same message through a chat **without** encryption… and there's the PIN in plain text."
5. "And if an attacker changes even one bit, the GCM tag check fails and the packet is thrown away." (Run `tamper_test`.)

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No packets when everything runs on one PC | Reinstall Npcap with **"Support loopback traffic"**, then capture on **Adapter for loopback traffic capture** |
| No packets between two PCs | Capture on the **Wi-Fi/Ethernet** interface; check the server's IP and that the firewall allows port 5555 |
| Filter bar turns red | Display filters use `==`: `tcp.port == 5555` (capture filters use `tcp port 5555`) |
| "No interfaces found" | Run Wireshark as Administrator, or reinstall Npcap |
| Too many packets | Apply the display filter, or right-click a packet → **Conversation Filter → TCP** |
