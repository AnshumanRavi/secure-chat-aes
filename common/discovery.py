"""
Find a SecureChat server on the local network (UDP broadcast discovery).

    servers = discover()          # client: [FoundServer(host, port, name, fingerprint), ...]
    DiscoveryResponder(5555, fingerprint).start()     # server side (started by ChatServer)

How it works
------------
1. The client broadcasts a small DISCOVER packet to UDP port 5555 on every network it
   is connected to (Wi-Fi, Ethernet, hotspot ...), plus 127.0.0.1 for a server on the same PC.
2. Every SecureChat server that hears it answers the sender directly with its name, TCP
   port and public-key fingerprint.
3. The address the answer CAME FROM is the IP the client should connect to - so the
   server never has to guess which of its addresses the client can reach.

Security
--------
* Discovery is only a convenience and its answers are NOT trusted: anyone on the network
  could answer. The real check is unchanged - the RSA handshake proves the server owns
  the private key, and the user compares its fingerprint with the one shown in the
  server window (popup on the first connection, pinned afterwards).
* No amplification: a request must be at least REQUEST_SIZE bytes and an answer is never
  larger than that, so a spoofed request can't make the server flood someone else.
"""

import ipaddress
import json
import secrets
import selectors
import socket
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import psutil

DISCOVERY_PORT = 5555          # UDP - the same number as the chat's TCP port, so one firewall note covers both
REQUEST_TYPE = "SECURECHAT_DISCOVER"
REPLY_TYPE = "SECURECHAT_SERVER"
VERSION = 1
REQUEST_SIZE = 512             # requests are padded to this size ...
MAX_REPLY = 480                # ... and replies are never bigger (no amplification)
# Adapter names that are almost never the network the other laptop is on
VIRTUAL_HINTS = ("virtual", "vethernet", "vmware", "vbox", "hyper-v", "loopback", "bluetooth",
                 "tailscale", "zerotier", "docker", "wsl", "npcap")


@dataclass
class Adapter:
    name: str          # e.g. "Wi-Fi"
    ip: str            # e.g. "192.168.1.20"
    broadcast: str     # e.g. "192.168.1.255"
    virtual: bool      # VirtualBox / Hyper-V / VPN ... - listed last


@dataclass
class FoundServer:
    host: str
    port: int
    name: str
    fingerprint: str

    @property
    def short_fingerprint(self) -> str:
        return " ".join(self.fingerprint.split(" ")[:4])


# ---------------------------------------------------------------- adapters
def _route_ip() -> Optional[str]:
    """The IP Windows would use for outside traffic - usually the Wi-Fi/Ethernet one.
    (Connecting a UDP socket sends nothing; it only picks the route.)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return None


def adapters() -> List[Adapter]:
    """IPv4 network adapters that are up, best guess first, virtual ones last."""
    stats = psutil.net_if_stats()
    found = []
    for name, addresses in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue
        for address in addresses:
            ip = address.address
            if address.family != socket.AF_INET or ip.startswith(("127.", "169.254.")):
                continue                  # loopback, or "no DHCP answer" self-assigned address
            network = ipaddress.IPv4Network(f"{ip}/{address.netmask or '255.255.255.0'}", strict=False)
            found.append(Adapter(name, ip, str(network.broadcast_address),
                                 any(hint in name.lower() for hint in VIRTUAL_HINTS)))
    primary = _route_ip()
    found.sort(key=lambda a: (a.ip != primary, a.virtual, a.name.lower()))
    return found


def lan_ips() -> List[str]:
    return [a.ip for a in adapters()]


# ---------------------------------------------------------------- server side
class DiscoveryResponder:
    """Answers DISCOVER broadcasts. Raises OSError if the UDP port is already in use."""

    def __init__(self, tcp_port: int, fingerprint: str, name: Optional[str] = None,
                 host: str = "0.0.0.0", port: int = DISCOVERY_PORT):
        self.tcp_port = tcp_port
        self.fingerprint = fingerprint
        self.name = (name or socket.gethostname())[:40]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self._running = threading.Event()

    def start(self) -> "DiscoveryResponder":
        self._running.set()
        threading.Thread(target=self._loop, name="discovery", daemon=True).start()
        return self

    def stop(self) -> None:
        self._running.clear()
        self.sock.close()

    def answer(self, data: bytes) -> Optional[bytes]:
        """The reply to one request, or None to ignore it."""
        if len(data) < REQUEST_SIZE:
            return None
        try:
            request = json.loads(data)
        except ValueError:
            return None
        nonce = request.get("nonce") if isinstance(request, dict) else None
        if request.get("type") != REQUEST_TYPE or request.get("v") != VERSION or \
                not isinstance(nonce, str) or len(nonce) > 64:
            return None
        reply = json.dumps({"type": REPLY_TYPE, "v": VERSION, "nonce": nonce, "name": self.name,
                            "port": self.tcp_port, "fingerprint": self.fingerprint}).encode()
        return reply if len(reply) <= MAX_REPLY else None

    def _loop(self) -> None:
        while self._running.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue       # Windows reports an ICMP "port unreachable" from an earlier send this way
            except OSError:
                return         # socket closed by stop()
            reply = self.answer(data)
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass


# ---------------------------------------------------------------- client side
def _request(nonce: str) -> bytes:
    body = {"type": REQUEST_TYPE, "v": VERSION, "nonce": nonce}
    padding = REQUEST_SIZE - len(json.dumps(dict(body, pad="")).encode())
    return json.dumps(dict(body, pad="." * max(0, padding))).encode()


def discover(timeout: float = 1.5, port: int = DISCOVERY_PORT,
             targets: Optional[List[str]] = None) -> List[FoundServer]:
    """
    Ask every reachable network for SecureChat servers and wait `timeout` seconds for answers.
    targets: send only to these addresses instead of broadcasting (used by the tests).
    """
    nonce = secrets.token_hex(8)
    request = _request(nonce)
    selector = selectors.DefaultSelector()
    sockets: List[socket.socket] = []

    def open_socket(bind_ip: str = "") -> Optional[socket.socket]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((bind_ip, 0))
            sock.setblocking(False)
        except OSError:
            return None
        sockets.append(sock)
        selector.register(sock, selectors.EVENT_READ)
        return sock

    def send(sock: Optional[socket.socket], address: str) -> None:
        if sock is not None:
            try:
                sock.sendto(request, (address, port))
            except OSError:
                pass              # e.g. an adapter that can't broadcast - try the others

    try:
        if targets is not None:
            sock = open_socket()
            for address in targets:
                send(sock, address)
        else:
            send(open_socket("127.0.0.1"), "127.0.0.1")            # a server on this PC
            for adapter in adapters():
                # one socket per adapter, bound to its IP, so each broadcast leaves through that adapter
                sock = open_socket(adapter.ip)
                send(sock, adapter.broadcast)
                send(sock, "255.255.255.255")

        found: Dict[Tuple[str, int], FoundServer] = {}
        deadline = time.monotonic() + timeout
        while (left := deadline - time.monotonic()) > 0:
            for key, _ in selector.select(left):
                try:
                    data, (host, _) = key.fileobj.recvfrom(2048)
                    reply = json.loads(data)
                except (ConnectionResetError, ValueError):
                    continue
                except OSError:
                    continue
                if not (isinstance(reply, dict) and reply.get("type") == REPLY_TYPE and reply.get("nonce") == nonce
                        and isinstance(reply.get("port"), int) and isinstance(reply.get("fingerprint"), str)):
                    continue
                server = FoundServer(host, reply["port"], str(reply.get("name", "?"))[:40], reply["fingerprint"])
                found[(server.fingerprint, server.port, host)] = server
    finally:
        selector.close()
        for sock in sockets:
            sock.close()
    return _prefer_lan_address(list(found.values()))


def _prefer_lan_address(servers: List[FoundServer]) -> List[FoundServer]:
    """One entry per server: its LAN address if it answered on one (that's the address worth
    sharing with others), otherwise 127.0.0.1."""
    best: Dict[Tuple[str, int], FoundServer] = {}
    for server in servers:
        key = (server.fingerprint, server.port)
        current = best.get(key)
        if current is None or (current.host.startswith("127.") and not server.host.startswith("127.")):
            best[key] = server
    return sorted(best.values(), key=lambda s: (s.name.lower(), s.host))
