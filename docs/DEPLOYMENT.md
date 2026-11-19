# Running SecureChat on two PCs

```
        PC 1                                          PC 2
 +--------------------------+                  +--------------------------+
 | run_server.bat  (server) |   same Wi-Fi,    | run_client.bat  (user B) |
 | run_client.bat  (user A) | <--------------> |                          |
 +--------------------------+  hotspot or LAN  +--------------------------+
                               TCP 5555 = chat
                               UDP 5555 = "Find server on LAN"
```

**Short version**

1. Copy the project folder to both PCs (section 1).
2. PC 1: double-click **`run_server.bat`**. Note the address it prints after `>>> Clients on other PCs should connect to:`.
3. PC 1, once: right-click **`allow_firewall.bat`** → *Run as administrator* (section 3).
4. PC 2: double-click **`run_client.bat`** → **Find server on LAN** (or type the address from step 2) → compare the fingerprint with the server window → create an account.
5. PC 1: double-click `run_client.bat` too and log in as a second user. Chat.

If PC 2 can't connect, see [Troubleshooting](#7-troubleshooting). On college Wi-Fi, a [mobile hotspot](#5-when-the-college-wi-fi-blocks-it-use-a-hotspot) often fixes it.

---

## 1. Install on both PCs

### Option A - with Python (recommended)

1. Install **Python 3.11 or newer** (developed and tested with 3.13) from <https://www.python.org/downloads/>.
   In the installer, tick **"Add python.exe to PATH"**.
2. Copy the whole project folder to each PC (USB stick, zip, or `git clone`). You can leave out
   `.venv`, `keys`, `data`, `logs`, `build` and `dist` - they are created on each PC.
3. Double-click `run_client.bat` (or `run_server.bat`). **The first run** creates a private Python
   environment in `.venv` and installs `requirements.txt` - it needs internet once and takes 2-3 minutes.
   After that it starts in a few seconds, offline too.

| File | What it does |
|---|---|
| `run_server.bat` | Starts the server (console window). Extra options are passed on, e.g. `run_server.bat --port 6000` |
| `run_client.bat` | Starts the chat app. Double-click it twice to be two users on one PC. `run_client.bat --console` shows error messages |
| `setup_env.bat` | Used by the two above: creates `.venv` and installs the requirements on the first run |
| `allow_firewall.bat` | Adds (or with `remove`, deletes) the Windows Firewall rules - run as administrator, server PC only |

### Option B - PC 2 without Python (standalone .exe)

Build once, on a PC that has the project set up:

```
.venv\Scripts\python -m pip install -r requirements-build.txt
.venv\Scripts\pyinstaller packaging\securechat.spec --noconfirm
```

This takes about a minute and creates:

| Folder | Contents | Size |
|---|---|---|
| `dist\SecureChat\` | `SecureChat.exe` - the chat app | ~150 MB |
| `dist\SecureChatServer\` | `SecureChatServer.exe` - the server | ~22 MB |

Zip the **whole folder** (the `.exe` needs the `_internal` folder next to it), copy it to the other PC,
unzip and double-click the `.exe`. Keys, database, logs and settings are created in that folder.
The `.exe` files are not code-signed, so Windows SmartScreen may say *"Windows protected your PC"*:
click **More info → Run anyway**.

---

## 2. Start the server (PC 1)

Double-click `run_server.bat`. On the very first start it asks for a **passphrase** that encrypts the
server's RSA private key (`keys/server_private.pem`); you need it every time the server starts.
(To avoid typing it, set the environment variable `SECURECHAT_KEY_PASSPHRASE`.)

The server then prints its addresses and key fingerprint:

```
|  Listening on         0.0.0.0:5555                                        |
|  Clients on this PC   127.0.0.1:5555                                      |
|                                                                           |
|  >>> Clients on other PCs should connect to:  192.168.1.20:5555   (Wi-Fi) |
|      ... or press "Find server on LAN" in the app (UDP 5555)              |
|                                                                           |
|  Key fingerprint      CC24 9DD2 CD25 1C89 13D0 DEBB 6930 07A6             |
|                       4372 1F25 D3A2 E874 06DF 1273 D8C8 3E77             |
```

Keep this window open - closing it stops the server. If Windows shows a firewall popup
*"Allow python.exe to communicate on these networks"*, click **Allow access** (and see section 3).

### Finding the IP address yourself (`ipconfig`)

Open *Command Prompt* on PC 1 and run `ipconfig`. Use the **IPv4 Address** of the adapter that is
connected to the shared network - usually **Wireless LAN adapter Wi-Fi**:

```
Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . . . . . . . . : 192.168.1.20      <- this one
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
```

Ignore adapters called *vEthernet (WSL)*, *VirtualBox Host-Only*, *VMware* or *Bluetooth* - the other PC
can't reach those. On a Windows mobile hotspot the hosting PC is usually `192.168.137.1`.

---

## 3. Allow the server through Windows Firewall (PC 1, once)

Windows blocks incoming connections by default, so PC 2 gets a **timeout** until you add a rule.
Only the **server** PC needs this.

**Easiest:** right-click `allow_firewall.bat` → **Run as administrator**.

**Or by hand:** open *Command Prompt as administrator* and run:

```
netsh advfirewall firewall add rule name="SecureChat server (TCP 5555)" dir=in action=allow protocol=TCP localport=5555 profile=any
netsh advfirewall firewall add rule name="SecureChat discovery (UDP 5555)" dir=in action=allow protocol=UDP localport=5555 profile=any
```

The first rule is the chat itself; the second lets the **Find server on LAN** button work.
For the two-PC performance benchmark (`python -m performance.benchmark_network --serve`) also add:

```
netsh advfirewall firewall add rule name="SecureChat benchmark (TCP 5600-5602)" dir=in action=allow protocol=TCP localport=5600-5602 profile=any
```

`profile=any` makes the rules work even when Windows treats the network as *Public* (college Wi-Fi and
hotspots usually are). That also opens the ports on other public networks, so **remove the rules after the
demo** - `allow_firewall.bat remove`, or:

```
netsh advfirewall firewall delete rule name="SecureChat server (TCP 5555)"
netsh advfirewall firewall delete rule name="SecureChat discovery (UDP 5555)"
netsh advfirewall firewall delete rule name="SecureChat benchmark (TCP 5600-5602)"
```

*(Using a different port with `--port`? Change `5555` in the first rule to that port.)*

---

## 4. Connect from PC 2

1. Double-click `run_client.bat`.
2. Click **Find server on LAN**. The app broadcasts on every network it is connected to; the server
   answers and the IP address and port are filled in. If several servers answer, pick yours from the list.
   If nothing answers, type the address from the server window instead.
3. Choose **Create account**, enter a username and password, and click the button.
4. The first time, a popup shows the **server's key fingerprint**. Compare it with the one in the server
   window on PC 1. Only if they match, click **It matches - connect**. (This is what defeats a
   man-in-the-middle; the search result itself is never trusted, because anyone on the network could answer it.)
5. Do the same on PC 1 with a second account and start chatting - text, groups, images and files all go
   through the server.

**✅ Check:** a message sent on PC 2 appears on PC 1 within a moment, gets two ticks, and turns blue
when PC 1 opens the chat.

Quick network test from PC 2 (PowerShell) - it should print `TcpTestSucceeded : True`:

```
Test-NetConnection 192.168.1.20 -Port 5555
```

(`ping` is not a good test: Windows blocks ping by default even when SecureChat works.)

---

## 5. When the college Wi-Fi blocks it: use a hotspot

Many college, office and hotel networks use **client isolation**: every laptop can reach the internet but
**not each other**. Symptoms: *Find server on LAN* finds nothing **and** `Test-NetConnection` fails, even
with the firewall rule. The fix is a small network of your own:

**Option 1 - phone hotspot (simplest).** Turn on the hotspot on a phone and connect **both** laptops to it.
Chat traffic goes laptop → phone → laptop and doesn't use mobile data. Start the server again (or look at
`ipconfig`) to see PC 1's new address.

**Option 2 - Windows Mobile hotspot on PC 1.** On PC 1: *Settings → Network & internet → Mobile hotspot →
On*. Connect PC 2 to the network name shown there. PC 1's address is then usually **192.168.137.1**.
(On some PCs Windows only allows this while PC 1 itself has an internet connection to share.)

In both cases the new network is usually *Public*, which the `profile=any` firewall rules already cover.

---

## 6. Keep the clocks in sync

Every packet carries a timestamp, and packets more than **60 seconds** old are rejected as possible replays
(`max_clock_skew` in `config.json`). If the two PCs' clocks differ by more than a minute, messages are
dropped. Fix: on both PCs *Settings → Time & language → Date & time → Sync now* (with *Set time
automatically* on).

---

## 7. Troubleshooting

| What you see | Likely cause | Fix |
|---|---|---|
| **"No SecureChat server at 192.168.1.20:5555. Is it running?"** (connection refused - comes back instantly) | The server isn't running, a different port was used, or the IP belongs to a different PC | Start `run_server.bat`; check the port; use the address the server window prints |
| **"Timed out connecting to 192.168.1.20:5555. Check the IP address and the server's firewall."** | Firewall on PC 1 (most common), the PCs are on different networks, a VPN is on, or the Wi-Fi uses client isolation | Section 3; make sure both PCs are on the same Wi-Fi; turn the VPN off; test with `Test-NetConnection`; use a hotspot (section 5) |
| **"No SecureChat server answered…"** after *Find server on LAN*, but typing the IP works | The network or firewall blocks UDP broadcasts | Add the UDP rule (section 3) or just type the IP - discovery is only a shortcut |
| Server window says **"LAN discovery off: UDP port 5555 is in use"** | Another SecureChat server is already running on PC 1 | Close the other server window |
| **"Could not listen on 0.0.0.0:5555 … Is another server already running?"** | Port 5555 is taken | Close the other server, or `run_server.bat --port 6000` (then use port 6000 on PC 2 and in the firewall rule) |
| The server window shows only a `172.x.x.x` or `vEthernet` address | PC 1 isn't connected to the shared Wi-Fi | Connect Wi-Fi/Ethernet and restart the server |
| Red popup **"The server's key has CHANGED"** | The server's keys were re-created (the `keys` folder was deleted or a different server folder is running) - **or someone is intercepting the connection** | Only continue if you know the keys were re-created; otherwise disconnect |
| **"Wrong passphrase"** when the server starts | Not the passphrase chosen on the first run | Use that passphrase. Starting over: delete the `keys` folder (clients will see the key-changed warning and queued offline messages are lost) |
| Messages don't arrive; the server log shows **REPLAY** / "stale packet" | The PCs' clocks differ by more than 60 s | Section 6 |
| The app window never appears | A start-up error | Run `run_client.bat --console` to see it |
| `run_*.bat` says **Python was not found** | Python missing or not on PATH | Install it with "Add python.exe to PATH" ticked (section 1) |
| First run fails while installing requirements | No internet, or a proxy blocks pip | Connect to the internet and run it again (it retries from scratch) |
| **"Windows protected your PC"** when starting an `.exe` | The `.exe` is not code-signed | *More info → Run anyway* |

---

## 8. What is exposed on the network

* **TCP 5555** only speaks SecureChat's protocol: an RSA-2048 handshake, then AES-256-GCM for every packet.
  Like any chat app, anyone who can reach it can create an account; existing accounts are protected by
  their password (PBKDF2-hashed, locked for 60 s after 5 wrong attempts).
* **UDP 5555** answers *Find server on LAN* with the server's PC name, port and **public**-key fingerprint -
  nothing secret. A request must be at least 512 bytes and the answer is smaller, so the server can't be
  abused to amplify traffic towards someone else. Turn it off with `run_server.bat --no-discovery`.
* Remove the firewall rules when you no longer need them (section 3).
