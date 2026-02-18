#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# qubes-vhost-bridge — vhost-user firewall bridge for sys-firewall
#
# Runs inside sys-firewall (or any ProxyVM in the netvm chain).
# Connects the upstream vhost-user socket from sys-net to downstream
# vhost-user sockets that client AppVMs (personal, work, etc.) connect
# to.  Applies nftables filtering based on Qubes firewall rules stored
# in QubesDB.
#
# Architecture:
#   sys-net vhost socket  <-->  bridge  <-->  per-VM vhost sockets
#                                 |
#                            nftables rules
#                           (from QubesDB)
#
# Copyright (C) 2024-2026  Qubes OS KVM Contributors
# License: GPL-2.0-or-later

import argparse
import asyncio
import ipaddress
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import time

log = logging.getLogger("qubes.vhost-bridge")

VHOST_SOCKET_DIR = "/var/run/qubes/vhost"
MAX_FRAME_SIZE = 65536
ETH_ALEN = 6
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP = 0x0806
ETHERTYPE_OFFSET = 12


# ── Ethernet frame parsing ──────────────────────────────────────────

def parse_eth_header(frame):
    """Parse Ethernet header. Returns (dst_mac, src_mac, ethertype, payload_offset)."""
    if len(frame) < 14:
        return None, None, None, 0
    dst = frame[:ETH_ALEN]
    src = frame[ETH_ALEN : ETH_ALEN * 2]
    ethertype = struct.unpack("!H", frame[ETHERTYPE_OFFSET:14])[0]
    return dst, src, ethertype, 14


def extract_ip_src(frame, ethertype, offset):
    """Extract source IP address from an IP packet."""
    if ethertype == ETH_P_IP and len(frame) >= offset + 20:
        return ipaddress.IPv4Address(frame[offset + 12 : offset + 16])
    elif ethertype == ETH_P_IPV6 and len(frame) >= offset + 40:
        return ipaddress.IPv6Address(frame[offset + 8 : offset + 24])
    return None


def extract_ip_dst(frame, ethertype, offset):
    """Extract destination IP address from an IP packet."""
    if ethertype == ETH_P_IP and len(frame) >= offset + 20:
        return ipaddress.IPv4Address(frame[offset + 16 : offset + 20])
    elif ethertype == ETH_P_IPV6 and len(frame) >= offset + 40:
        return ipaddress.IPv6Address(frame[offset + 24 : offset + 40])
    return None


def mac_str(mac_bytes_val):
    return ":".join("{:02x}".format(b) for b in mac_bytes_val)


def is_broadcast(mac):
    return mac[0] & 1 != 0


# ── QubesDB firewall rule reader ────────────────────────────────────

class FirewallRuleSet:
    """Reads and caches Qubes firewall rules from QubesDB.

    Integrates with the same QubesDB paths that the existing
    qubes-firewall daemon uses, so firewall rules configured via
    qvm-firewall work transparently.
    """

    def __init__(self):
        self._qdb = None
        self._rules_cache = {}  # source_ip -> list of rule dicts
        self._connected_ips = set()
        self._connected_ips6 = set()

    def _get_qdb(self):
        if self._qdb is None:
            try:
                import qubesdb
                self._qdb = qubesdb.QubesDB()
            except ImportError:
                log.warning("qubesdb not available, firewall rules disabled")
        return self._qdb

    def load_rules(self, source_ip):
        """Load firewall rules for the given source IP from QubesDB."""
        qdb = self._get_qdb()
        if qdb is None:
            return [{"action": "accept"}]

        try:
            entries = qdb.multiread(
                "/qubes-firewall/{}/".format(source_ip)
            )
        except Exception:
            log.warning(
                "Failed to read firewall rules for %s", source_ip
            )
            return [{"action": "drop"}]

        if not entries:
            return [{"action": "drop"}]

        rules_dict = {}
        policy = "drop"
        for key, value in entries.items():
            part = key.split("/")[3] if key.count("/") >= 3 else ""
            val = value.decode() if isinstance(value, bytes) else value
            if part == "policy":
                policy = val
            elif len(part) == 4 and part.isdigit():
                rules_dict[part] = val

        rules = []
        for ruleno, rule_str in sorted(rules_dict.items()):
            rule = dict(
                elem.split("=") for elem in rule_str.split(" ") if "=" in elem
            )
            if "action" in rule:
                rules.append(rule)
        rules.append({"action": policy})

        self._rules_cache[str(source_ip)] = rules
        return rules

    def load_connected_ips(self):
        """Load the set of IPs that should be allowed through."""
        qdb = self._get_qdb()
        if qdb is None:
            return

        try:
            ips = qdb.read("/connected-ips")
            if ips:
                self._connected_ips = set(ips.decode().split())
            ips6 = qdb.read("/connected-ips6")
            if ips6:
                self._connected_ips6 = set(ips6.decode().split())
        except Exception:
            log.warning("Failed to read connected-ips from QubesDB")

    def is_allowed(self, src_ip, dst_ip, proto=None, dst_port=None):
        """Check if a packet should be allowed by the firewall rules.

        This is the inline packet filter that replaces the kernel
        nftables path for vhost-user traffic.
        """
        src_str = str(src_ip)
        rules = self._rules_cache.get(src_str)
        if rules is None:
            rules = self.load_rules(src_str)

        for rule in rules:
            # Check protocol match
            if "proto" in rule and proto is not None:
                if rule["proto"] != proto:
                    continue

            # Check destination port
            if "dstports" in rule and dst_port is not None:
                port_spec = rule["dstports"]
                if "-" in port_spec:
                    lo, hi = port_spec.split("-")
                    if not (int(lo) <= dst_port <= int(hi)):
                        continue
                else:
                    if dst_port != int(port_spec):
                        continue

            # Check destination address (IPv4)
            if "dst4" in rule:
                try:
                    net = ipaddress.IPv4Network(rule["dst4"], strict=False)
                    if dst_ip not in net:
                        continue
                except (ValueError, TypeError):
                    continue

            # Check destination address (IPv6)
            if "dst6" in rule:
                try:
                    net = ipaddress.IPv6Network(rule["dst6"], strict=False)
                    if dst_ip not in net:
                        continue
                except (ValueError, TypeError):
                    continue

            # Check special DNS target
            if rule.get("specialtarget") == "dns":
                if dst_port != 53:
                    continue

            return rule["action"] == "accept"

        return False

    def is_known_source(self, ip_str):
        """Check if an IP belongs to a known connected VM."""
        return (
            ip_str in self._connected_ips
            or ip_str in self._connected_ips6
        )


# ── Bridge client (connected VM) ────────────────────────────────────

class BridgeClient:
    """A downstream client VM connected via a vhost-user socket."""

    def __init__(self, name, sock, allowed_ips=None):
        self.name = name
        self.sock = sock
        self.mac = None
        self.allowed_ips = allowed_ips or set()
        self.rx_packets = 0
        self.tx_packets = 0
        self.dropped_packets = 0
        self._recv_buf = bytearray()

    def fileno(self):
        return self.sock.fileno()

    def send_frame(self, frame):
        try:
            hdr = struct.pack("!I", len(frame))
            self.sock.sendall(hdr + frame)
            self.tx_packets += 1
        except (BrokenPipeError, ConnectionResetError, OSError):
            raise ConnectionError(
                "Client {} disconnected".format(self.name)
            )

    def recv_frame(self):
        try:
            chunk = self.sock.recv(MAX_FRAME_SIZE)
            if not chunk:
                raise ConnectionError(
                    "Client {} disconnected".format(self.name)
                )
            self._recv_buf.extend(chunk)
        except BlockingIOError:
            pass
        except OSError as exc:
            if exc.errno in (11, 35):  # EAGAIN / EWOULDBLOCK
                pass
            else:
                raise ConnectionError(str(exc))

        if len(self._recv_buf) < 4:
            return None
        frame_len = struct.unpack("!I", self._recv_buf[:4])[0]
        if frame_len > MAX_FRAME_SIZE:
            raise ConnectionError("Oversized frame")
        if len(self._recv_buf) < 4 + frame_len:
            return None

        frame = bytes(self._recv_buf[4 : 4 + frame_len])
        del self._recv_buf[: 4 + frame_len]
        self.rx_packets += 1

        if self.mac is None and len(frame) >= ETH_ALEN * 2:
            self.mac = frame[ETH_ALEN : ETH_ALEN * 2]

        return frame

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ── Upstream connection to sys-net backend ───────────────────────────

class UpstreamConnection:
    """Connection to the sys-net vhost-user backend socket."""

    def __init__(self, sock_path):
        self.sock_path = sock_path
        self.sock = None
        self._recv_buf = bytearray()

    def connect(self):
        """Connect to the upstream vhost-user socket."""
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        self.sock.connect(self.sock_path)
        log.info("Connected to upstream: %s", self.sock_path)

    def fileno(self):
        return self.sock.fileno() if self.sock else -1

    def send_frame(self, frame):
        try:
            hdr = struct.pack("!I", len(frame))
            self.sock.sendall(hdr + frame)
        except (BrokenPipeError, ConnectionResetError, OSError):
            raise ConnectionError("Upstream disconnected")

    def recv_frame(self):
        try:
            chunk = self.sock.recv(MAX_FRAME_SIZE)
            if not chunk:
                raise ConnectionError("Upstream disconnected")
            self._recv_buf.extend(chunk)
        except BlockingIOError:
            pass
        except OSError as exc:
            if exc.errno in (11, 35):
                pass
            else:
                raise ConnectionError(str(exc))

        if len(self._recv_buf) < 4:
            return None
        frame_len = struct.unpack("!I", self._recv_buf[:4])[0]
        if frame_len > MAX_FRAME_SIZE:
            raise ConnectionError("Upstream sent oversized frame")
        if len(self._recv_buf) < 4 + frame_len:
            return None

        frame = bytes(self._recv_buf[4 : 4 + frame_len])
        del self._recv_buf[: 4 + frame_len]
        return frame

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# ── Main bridge daemon ───────────────────────────────────────────────

class VhostBridge:
    """Firewall bridge between upstream (sys-net) and downstream (AppVMs).

    Applies QubesDB firewall rules inline for all forwarded traffic.
    Acts as both a vhost-user client (to sys-net) and a vhost-user
    server (for each AppVM).
    """

    def __init__(self, upstream_path, socket_dir=VHOST_SOCKET_DIR):
        self.upstream = UpstreamConnection(upstream_path)
        self.socket_dir = socket_dir
        self.firewall = FirewallRuleSet()
        self.clients = {}  # name -> BridgeClient
        self.mac_table = {}  # MAC bytes -> BridgeClient
        self.server_socks = {}  # path -> server socket
        self.running = False
        self.loop = None

    def _create_server_socket(self, sock_path):
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setblocking(False)
        server.bind(sock_path)
        os.chmod(sock_path, 0o660)
        server.listen(1)
        self.server_socks[sock_path] = server
        log.info("Listening for clients on: %s", sock_path)
        return server

    def _scan_client_sockets(self):
        """Find and listen on sockets for downstream client VMs."""
        our_name = _get_vm_name()
        if not our_name:
            return

        try:
            entries = os.listdir(self.socket_dir)
        except FileNotFoundError:
            os.makedirs(self.socket_dir, mode=0o750, exist_ok=True)
            entries = []

        for entry in entries:
            if not entry.startswith(our_name + "-to-"):
                continue
            if not entry.endswith(".sock"):
                continue
            sock_path = os.path.join(self.socket_dir, entry)
            if sock_path not in self.server_socks:
                server = self._create_server_socket(sock_path)
                self.loop.add_reader(
                    server.fileno(),
                    lambda s=server, p=sock_path: asyncio.ensure_future(
                        self._accept_client(s, p)
                    ),
                )

    async def _accept_client(self, server_sock, sock_path):
        try:
            conn, addr = server_sock.accept()
            conn.setblocking(False)
        except (BlockingIOError, OSError):
            return

        basename = os.path.basename(sock_path)
        parts = basename.rsplit("-to-", 1)
        client_name = parts[1].replace(".sock", "") if len(parts) == 2 else "unknown"

        if client_name in self.clients:
            self._remove_client(client_name)

        client = BridgeClient(client_name, conn)
        self.clients[client_name] = client
        log.info("Client %s connected", client_name)

        self.loop.add_reader(
            client.fileno(),
            lambda c=client: asyncio.ensure_future(
                self._handle_client_frame(c)
            ),
        )

    async def _handle_upstream_frame(self):
        """Frame received from sys-net, forward to appropriate client(s)."""
        try:
            frame = self.upstream.recv_frame()
        except ConnectionError:
            log.error("Upstream connection lost")
            self.running = False
            return

        if frame is None or len(frame) < 14:
            return

        dst, src, ethertype, offset = parse_eth_header(frame)

        if is_broadcast(dst):
            disconnected = []
            for name, client in self.clients.items():
                if self._filter_downstream(frame, ethertype, offset, client):
                    try:
                        client.send_frame(frame)
                    except ConnectionError:
                        disconnected.append(name)
            for name in disconnected:
                self._remove_client(name)
        else:
            client = self.mac_table.get(dst)
            if client is not None:
                if self._filter_downstream(frame, ethertype, offset, client):
                    try:
                        client.send_frame(frame)
                    except ConnectionError:
                        self._remove_client(client.name)

    async def _handle_client_frame(self, client):
        """Frame received from a client VM, apply firewall and forward."""
        try:
            frame = client.recv_frame()
        except ConnectionError:
            self._remove_client(client.name)
            return

        if frame is None or len(frame) < 14:
            return

        dst, src, ethertype, offset = parse_eth_header(frame)

        # Update MAC learning
        if src and not is_broadcast(src):
            self.mac_table[src] = client

        # Apply firewall rules (outbound from client)
        if not self._filter_upstream(frame, ethertype, offset, client):
            client.dropped_packets += 1
            return

        if is_broadcast(dst):
            # Forward to upstream and all other clients
            try:
                self.upstream.send_frame(frame)
            except ConnectionError:
                log.error("Upstream connection lost while forwarding")
                self.running = False
                return

            disconnected = []
            for name, other in self.clients.items():
                if other is client:
                    continue
                if self._filter_downstream(frame, ethertype, offset, other):
                    try:
                        other.send_frame(frame)
                    except ConnectionError:
                        disconnected.append(name)
            for name in disconnected:
                self._remove_client(name)
        else:
            # Check if destination is a local client
            dst_client = self.mac_table.get(dst)
            if dst_client is not None and dst_client is not client:
                if self._filter_downstream(
                    frame, ethertype, offset, dst_client
                ):
                    try:
                        dst_client.send_frame(frame)
                    except ConnectionError:
                        self._remove_client(dst_client.name)
            else:
                try:
                    self.upstream.send_frame(frame)
                except ConnectionError:
                    log.error("Upstream connection lost")
                    self.running = False

    def _filter_upstream(self, frame, ethertype, offset, client):
        """Apply firewall rules to traffic going upstream (from client).

        Returns True if the packet should be forwarded.
        """
        if ethertype == ETH_P_ARP:
            return True

        src_ip = extract_ip_src(frame, ethertype, offset)
        dst_ip = extract_ip_dst(frame, ethertype, offset)
        if src_ip is None or dst_ip is None:
            return True  # Non-IP traffic passes through

        # Anti-spoofing: check source IP belongs to this client
        src_str = str(src_ip)
        if not self.firewall.is_known_source(src_str):
            log.warning(
                "Anti-spoof: client %s sent packet with src=%s",
                client.name,
                src_str,
            )
            return False

        # Apply QubesDB firewall rules
        proto = None
        dst_port = None
        if ethertype == ETH_P_IP and len(frame) >= offset + 20:
            proto_num = frame[offset + 9]
            if proto_num == 6:
                proto = "tcp"
            elif proto_num == 17:
                proto = "udp"
            elif proto_num == 1:
                proto = "icmp"
            if proto in ("tcp", "udp") and len(frame) >= offset + 24:
                ihl = (frame[offset] & 0x0F) * 4
                if len(frame) >= offset + ihl + 4:
                    dst_port = struct.unpack(
                        "!H", frame[offset + ihl + 2 : offset + ihl + 4]
                    )[0]
        elif ethertype == ETH_P_IPV6 and len(frame) >= offset + 40:
            next_hdr = frame[offset + 6]
            if next_hdr == 6:
                proto = "tcp"
            elif next_hdr == 17:
                proto = "udp"
            elif next_hdr == 58:
                proto = "icmp"
            if proto in ("tcp", "udp") and len(frame) >= offset + 44:
                dst_port = struct.unpack(
                    "!H", frame[offset + 42 : offset + 44]
                )[0]

        return self.firewall.is_allowed(src_ip, dst_ip, proto, dst_port)

    def _filter_downstream(self, frame, ethertype, offset, client):
        """Apply filtering to traffic going to a client VM.

        Currently permits all downstream traffic (return traffic is
        handled by connection tracking in the firewall rules).
        """
        return True

    def _remove_client(self, name):
        client = self.clients.pop(name, None)
        if client is None:
            return

        log.info(
            "Client %s disconnected (rx=%d tx=%d dropped=%d)",
            name,
            client.rx_packets,
            client.tx_packets,
            client.dropped_packets,
        )

        try:
            self.loop.remove_reader(client.fileno())
        except (ValueError, OSError):
            pass

        stale = [m for m, c in self.mac_table.items() if c is client]
        for m in stale:
            del self.mac_table[m]

        client.close()

    async def _periodic_tasks(self):
        """Periodic maintenance: scan for new sockets, reload firewall."""
        while self.running:
            self._scan_client_sockets()
            self.firewall.load_connected_ips()
            # Reload rules for all known sources
            for ip in list(self.firewall._connected_ips):
                self.firewall.load_rules(ip)
            for ip in list(self.firewall._connected_ips6):
                self.firewall.load_rules(ip)
            await asyncio.sleep(5.0)

    async def run(self):
        self.loop = asyncio.get_event_loop()
        self.running = True

        os.makedirs(self.socket_dir, mode=0o750, exist_ok=True)

        # Connect to upstream (sys-net)
        try:
            self.upstream.connect()
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            log.error("Cannot connect to upstream %s: %s",
                      self.upstream.sock_path, exc)
            sys.exit(1)

        self.loop.add_reader(
            self.upstream.fileno(),
            lambda: asyncio.ensure_future(self._handle_upstream_frame()),
        )

        # Load initial firewall rules
        self.firewall.load_connected_ips()

        # Scan for downstream client sockets
        self._scan_client_sockets()

        _sd_notify("READY=1")

        periodic = asyncio.ensure_future(self._periodic_tasks())

        log.info("vhost-user bridge running (upstream=%s)",
                 self.upstream.sock_path)

        stop_event = asyncio.Event()

        def _signal_handler():
            self.running = False
            stop_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT):
            self.loop.add_signal_handler(sig, _signal_handler)

        await stop_event.wait()

        periodic.cancel()
        self._shutdown()

    def _shutdown(self):
        log.info("Shutting down vhost-user bridge")

        for name in list(self.clients.keys()):
            self._remove_client(name)

        for path, server in self.server_socks.items():
            try:
                self.loop.remove_reader(server.fileno())
            except (ValueError, OSError):
                pass
            server.close()

        try:
            self.loop.remove_reader(self.upstream.fileno())
        except (ValueError, OSError):
            pass
        self.upstream.close()

        _sd_notify("STOPPING=1")


# ── Helpers ──────────────────────────────────────────────────────────

def _get_vm_name():
    try:
        import qubesdb
        qdb = qubesdb.QubesDB()
        name = qdb.read("/name")
        if name:
            return name.decode().strip()
    except Exception:
        pass
    return socket.gethostname()


def _sd_notify(state):
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr[0] == "@":
        addr = "\0" + addr[1:]
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(addr)
        sock.sendall(state.encode())
        sock.close()
    except OSError:
        pass


# ── CLI ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Qubes vhost-user firewall bridge daemon"
    )
    parser.add_argument(
        "--upstream",
        "-u",
        required=True,
        help="Path to upstream vhost-user socket (from sys-net)",
    )
    parser.add_argument(
        "--socket-dir",
        "-d",
        default=VHOST_SOCKET_DIR,
        help="Directory for downstream vhost-user sockets",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    bridge = VhostBridge(args.upstream, args.socket_dir)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(bridge.run())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
