#!/usr/bin/env python3
"""
nettest.py - layered network diagnostics for any network interface (Ethernet, USB, Wi-Fi, ...).

Walks the network stack bottom-up, for IPv4 and IPv6, and points at the first layer
that breaks:

  L0  Environment        tools, interfaces, competing routes, VPNs, rp_filter
  L1  Physical           adapter, driver, carrier, speed/duplex, link partner, USB bus speed
                         (USB NICs), Wi-Fi signal and bitrate, flapping, error counters, kernel log
  L2  IPv4 link          DHCP probes (standard, unicast-reply, new client / pool, INFORM,
                         bogus REQUEST -> NAK), ARP to the router, IP conflicts
  L2  IPv6 link          Router Solicitation -> RA analysis (flags, prefixes, lifetimes,
                         RDNSS, rogue RAs), NDP to the router, DHCPv6 SOLICIT and
                         INFORMATION-REQUEST, duplicate address detection
  LAN discovery          passive listen (broadcast storm, LLDP/STP/CDP, DHCP/RA speakers,
                         mDNS/SSDP), ARP scan, IPv6 all-nodes scan, host table with vendors
  L3  LAN                addressing, routes, router ping v4+v6 (loss/jitter/burst/large frames)
  L3  WAN                public IPs, mtr-style traceroute, ISP edge hop, path MTU (v4 + v6)
  DNS                    router/ISP/public resolvers over UDP+TCP via IPv4 and IPv6,
                         hijack check, DoT
  L4  Transport          TCP reachability and filtering, NTP / clock offset (v4 + v6)
  L7  Application        captive portal, HTTPS + TLS validation, DoH, public IP (v4 + v6)
  Router / WAN info      router fingerprint, UPnP-IGD WAN status, Huawei HiLink (LTE) status
  Performance            download / upload throughput, latency under load, IPv6 download
  Diagnosis              IPv4 and IPv6 layer ladders + most likely problem location
  Monitor (optional)     second-by-second watch (v4 + v6) to catch intermittent drops

Every probe is bound to the tested interface (SO_BINDTODEVICE / AF_PACKET), so other
links on the computer cannot mask the result.

Usage:   sudo python3 nettest.py                  # asks which interface to test, full test
         sudo python3 nettest.py -i wlan0         # test this interface
         sudo python3 nettest.py --monitor 30     # full test, then watch for drops 30 min
         sudo python3 nettest.py --monitor-only 0 # only watch, until Ctrl-C
         python3 nettest.py --help

Standard library only (Python 3.8+). Uses `ip`, `ping`, and (if present) `ethtool`,
`iw`, `nmcli`, `resolvectl`, `journalctl`, `mtr`, and the IEEE OUI list for MAC vendors.
"""

import argparse
import atexit
import collections
import concurrent.futures as cf
import datetime
import errno
import hmac
import html
import ipaddress
import itertools
import json
import os
import platform
import random
import re
import select
import shutil
import signal
import socket
import ssl
import statistics
import string
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

VERSION = "3.0"
REPORT_SCHEMA_VERSION = 1

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD
WIRED_KINDS = ("ethernet", "usb-ethernet")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
DSLITE_NET = ipaddress.ip_network("192.0.0.0/29")     # DS-Lite B4/AFTR addresses (RFC 6333)
ULA = ipaddress.ip_network("fc00::/7")

PUBLIC_V4 = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"),
             ("9.9.9.9", "Quad9"), ("208.67.222.222", "OpenDNS")]
PUBLIC_V6 = [("2606:4700:4700::1111", "Cloudflare"), ("2001:4860:4860::8888", "Google"),
             ("2620:fe::fe", "Quad9")]
REFERENCE_V4 = PUBLIC_V4[0][0]     # the default target of single-host probes
PUBLIC_DNS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
SPEED_DOWN_URL = "https://speed.cloudflare.com/__down?bytes="
SPEED_UP_URL = "https://speed.cloudflare.com/__up"
PUBLIC_DNS6 = ["2606:4700:4700::1111", "2001:4860:4860::8888"]
TCP_CHECKS = {False: [("1.1.1.1", 443), ("1.1.1.1", 80), ("8.8.8.8", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)],
              True: [("2606:4700:4700::1111", 443), ("2606:4700:4700::1111", 80), ("2001:4860:4860::8888", 443),
                     ("2001:4860:4860::8888", 53), ("2620:fe::fe", 443)]}
DNS_TEST_NAMES = ["example.com", "google.com", "wikipedia.org", "cloudflare.com"]
HTTPS_SITES = ["https://www.google.com/", "https://www.cloudflare.com/",
               "https://www.wikipedia.org/", "https://github.com/",
               "https://www.microsoft.com/", "https://www.amazon.com/"]
CONNECTIVITY_CHECKS = [
    ("http://connectivitycheck.gstatic.com/generate_204", 204, None),
    ("http://detectportal.firefox.com/success.txt", 200, b"success"),
    ("http://nmcheck.gnome.org/check_network_status.txt", 200, b"NetworkManager is online"),
]
PORTQUIZ_PORTS = [21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 1194, 1723,
                  3389, 5060, 8080, 8443]
# non-anycast destinations in different regions / networks: partial reachability = ISP upstream problem
DIVERSE_TARGETS = [("www.ripe.net", "RIPE NCC, NL"), ("speedtest.tele2.net", "Tele2, SE"),
                   ("www.arin.net", "ARIN, US"), ("www.isc.org", "ISC, US"), ("www.apnic.net", "APNIC, AU")]
# usual management addresses of modems / ONTs / upstream routers
MODEM_IPS = ["192.168.100.1", "192.168.1.1", "192.168.0.1", "192.168.1.254", "192.168.178.1",
             "192.168.2.1", "10.0.0.138", "10.0.0.1", "192.168.88.1", "169.254.1.1"]
UNREACH4 = {0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable", 3: "port unreachable",
            4: "fragmentation needed", 9: "network administratively prohibited",
            10: "host administratively prohibited", 13: "communication administratively prohibited"}
UNREACH6 = {0: "no route to destination", 1: "administratively prohibited", 3: "address unreachable",
            4: "port unreachable", 5: "source address failed policy", 6: "reject route"}
STAT_KEYS = ["rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors",
             "rx_dropped", "tx_dropped", "rx_crc_errors", "rx_frame_errors",
             "rx_length_errors", "rx_missed_errors", "rx_over_errors", "rx_fifo_errors",
             "tx_carrier_errors", "tx_aborted_errors", "tx_fifo_errors", "collisions"]
SERIOUS_STATS = ["rx_crc_errors", "rx_frame_errors", "rx_length_errors", "rx_errors",
                 "tx_errors", "tx_carrier_errors", "collisions", "rx_missed_errors",
                 "rx_over_errors", "rx_fifo_errors", "tx_fifo_errors", "tx_aborted_errors"]
DNS_ERRORS = (OSError, ValueError, IndexError, struct.error)
HTTP_ERRORS = (OSError, ssl.SSLError, ValueError)
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x88CC: "LLDP", 0x8100: "VLAN", 0x888E: "802.1X",
              0x8863: "PPPoE-disc", 0x8864: "PPPoE", 0x893A: "IEEE1905", 0x88E1: "HomePlug", 0x8912: "HomePlug-AV",
              0x88F7: "PTP", 0x9000: "loopback", 0x8809: "LACP", 0x22F0: "AVB", 0x0842: "Wake-on-LAN"}

IFACE = None        # interface under test
IFINDEX = 0
ROOT = os.geteuid() == 0
ARGS = None
RECORDER = None


# --------------------------------------------------------------------------- output

_UNSAFE_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def clean(text):
    """Strings from the network must not move the cursor, send escape codes or forge extra report lines."""
    return _UNSAFE_TEXT.sub(lambda m: " " if m.group(0) in "\t\r\n" else "?", str(text))


class Color:
    on = sys.stdout.isatty()

    @staticmethod
    def c(code, text):
        return f"\033[{code}m{text}\033[0m" if Color.on else text


STATUS_COLOR = {"PASS": "32", "WARN": "33", "FAIL": "31;1", "INFO": "36", "SKIP": "90"}


class Report:
    def __init__(self):
        self.results = []
        self.facts = {}
        self.text = []
        self.layer = "-"
        self.started = datetime.datetime.now().astimezone()
        self.lock = threading.Lock()

    def _emit(self, colored, plain):
        with self.lock:
            print(colored, flush=True)
            self.text.append(plain)

    def section(self, layer, title):
        self.layer = layer
        bar = "=" * 78
        self._emit("\n" + Color.c("1;34", f"{bar}\n {title}\n{bar}"), f"\n{bar}\n {title}\n{bar}")

    def add(self, status, name, detail="", **data):
        name, detail = clean(name), clean(detail)
        self.results.append({"layer": self.layer, "status": status, "name": name,
                             "detail": detail, "data": data,
                             "time": datetime.datetime.now().astimezone().isoformat(timespec="seconds")})
        tag = f"[{status}]"
        tail = f": {detail}" if detail else ""
        self._emit(Color.c(STATUS_COLOR[status], f"  {tag:<7}") + name + tail, f"  {tag:<7}{name}{tail}")

    def note(self, text):
        text = clean(text)
        self._emit(Color.c("90", "          " + text) if text.startswith("…") else "          " + text,
                   "          " + text)

    def progress(self, text):
        self.note("… " + text)


R = Report()
F = R.facts


class NetError(Exception):
    pass


HTTP_FAILURES = HTTP_ERRORS + (NetError,)


# --------------------------------------------------------------------------- helpers

def run(cmd, timeout=30):
    """Run a command; return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return 124, out, "timeout"


def ipj(*args):
    rc, out, _ = run(["ip", "-j", *args])
    if rc != 0 or not out.strip():
        return []
    try:
        return json.loads(out)
    except ValueError:
        return []


def sysread(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def has_carrier(name=None):
    return sysread(f"/sys/class/net/{name or IFACE}/carrier") == "1"


def ms(t0):
    return (time.monotonic() - t0) * 1000.0


def invoking_user():
    """(uid, gid) of the person behind sudo, or None."""
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    return (int(uid), int(gid)) if ROOT and uid.isdigit() and gid.isdigit() else None


def private_open(path, mode="w"):
    """Open one of our own output files for writing: mode 0600, owned by the invoking user, never through a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        ids = invoking_user()
        if ids:
            os.fchown(fd, *ids)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, mode)


def make_output_dir(path):
    """Create an output directory; one that already exists is left exactly as it is."""
    if os.path.isdir(path):
        return
    os.makedirs(path, mode=0o700, exist_ok=True)
    ids = invoking_user()
    if ids:
        os.chown(path, *ids, follow_symlinks=False)


def is_ip(text):
    try:
        ipaddress.ip_address(text.split("%")[0])
        return True
    except ValueError:
        return False


def norm6(a):
    return str(ipaddress.ip_address(a.split("%")[0]))


def addr_class(ip):
    a = ipaddress.ip_address(ip.split("%")[0])
    if a.version == 4 and a in CGNAT:
        return "CGNAT"
    if a.version == 6 and a in ULA:
        return "ULA"
    if a.is_multicast:
        return "multicast"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_private:
        return "private"
    if a.is_global:
        return "public"
    return "special"


def is_gua(a):
    return addr_class(a) == "public" and ":" in a


def sockaddr(ip, port):
    """(family, address tuple) for v4, v6 and scoped link-local v6."""
    if ":" in ip:
        addr = ip.split("%")[0]
        a = ipaddress.ip_address(addr)
        scope = IFINDEX if (a.is_link_local or a.is_multicast) else 0
        return socket.AF_INET6, (addr, port, 0, scope)
    return socket.AF_INET, (ip, port)


def packet_socket(proto):
    """Raw Ethernet socket on the interface under test."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
    s.bind((IFACE, proto))
    return s


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def fmt_ms(v):
    return "-" if v is None else (f"{v:.2f}" if v < 10 else f"{v:.1f}" if v < 100 else f"{v:.0f}")


def fmt_dur(secs):
    secs = int(secs)
    if secs < 120:
        return f"{secs} s"
    if secs < 7200:
        return f"{secs // 60} min"
    if secs < 172800:
        return f"{secs // 3600} h {secs % 3600 // 60} min"
    return f"{secs // 86400} days {secs % 86400 // 3600} h"


def macstr(b):
    return ":".join(f"{x:02x}" for x in b)


def parallel(fn, items, workers=8):
    items = list(items)
    if not items:
        return []
    with cf.ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


def mean(xs):
    return sum(xs) / len(xs) if xs else None


def jitter(rtts):
    if len(rtts) < 2:
        return None
    return mean([abs(b - a) for a, b in zip(rtts, rtts[1:])])


def dedupe(xs):
    out = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out


# MAC vendor database: IEEE assignments of 24 bits (MA-L), 28 bits (MA-M) and 36 bits (MA-S),
# keyed by the number of hex digits of the prefix
_HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLED = "site-packages" in _HERE         # pipx/pip install: never write inside the package directory
OUI_CACHE = os.path.join(os.path.expanduser("~/.cache/nettest") if INSTALLED else os.path.join(_HERE, "data"), "manuf")
OUI_URL = "https://www.wireshark.org/download/automated/data/manuf"
_oui = None
_oui_sources = []


def _oui_add(db, hexp, name):
    hexp = hexp.upper()
    if len(hexp) in db and name and name.strip():
        db[len(hexp)].setdefault(hexp, name.strip())


def _oui_manuf(db, f):          # Wireshark: "00:1B:C5:00:00:00/36<TAB>Short<TAB>Long name"
    for line in f:
        if line.startswith("#") or "\t" not in line:
            continue
        parts = line.rstrip("\n").split("\t")
        pfx, _, bits = parts[0].strip().partition("/")
        hexp = re.sub(r"[^0-9A-Fa-f]", "", pfx)
        n = int(bits) // 4 if bits.isdigit() else 6
        _oui_add(db, hexp[:n], parts[2] if len(parts) > 2 and parts[2].strip() else parts[1])


def _oui_csv(db, f):            # IEEE: "MA-L,10E992,Name,Address"
    import csv
    for row in csv.reader(f):
        if len(row) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{6,9}", row[1]):
            _oui_add(db, row[1], row[2])


def _oui_txt(db, f):            # IEEE text: "10-E9-92   (hex)\t\tName"
    for line in f:
        if "(hex)" in line:
            p, _, name = line.partition("(hex)")
            _oui_add(db, p.strip().replace("-", ""), name)


def _oui_tabbed(db, f):         # arp-scan "000000<TAB>XEROX", nmap "000000 XEROX"
    for line in f:
        p, _, name = line.strip().replace("\t", " ").partition(" ")
        if re.fullmatch(r"[0-9A-Fa-f]{6}", p):
            _oui_add(db, p, name)


OUI_SOURCES = [(OUI_CACHE, _oui_manuf), ("/usr/share/wireshark/manuf", _oui_manuf),
               ("/usr/share/ieee-data/oui.csv", _oui_csv), ("/usr/share/ieee-data/mam.csv", _oui_csv),
               ("/usr/share/ieee-data/oui36.csv", _oui_csv), ("/usr/share/ieee-data/oui.txt", _oui_txt),
               ("/var/lib/ieee-data/oui.txt", _oui_txt), ("/usr/share/hwdata/oui.txt", _oui_txt),
               ("/usr/share/misc/oui.txt", _oui_txt), ("/usr/share/arp-scan/ieee-oui.txt", _oui_tabbed),
               ("/usr/share/nmap/nmap-mac-prefixes", _oui_tabbed)]


def load_oui():
    global _oui
    db = {6: {}, 7: {}, 9: {}}
    _oui_sources.clear()
    for path, parser in OUI_SOURCES:
        try:
            with open(path, errors="replace") as f:
                before = sum(map(len, db.values()))
                parser(db, f)
            if sum(map(len, db.values())) > before:
                _oui_sources.append(path)
        except OSError:
            continue
    _oui = db
    return db


def vendor(mac):
    """Manufacturer of a MAC address (longest IEEE prefix wins), or a note for random/multicast MACs."""
    if _oui is None:
        load_oui()
    if not mac or len(mac.replace(":", "")) < 12:
        return ""
    h = mac.replace(":", "").upper()
    first = int(h[:2], 16)
    if first & 1:
        return "(multicast address)"
    for n in (9, 7, 6):
        if h[:n] in _oui[n]:
            return _oui[n][h[:n]]
    if first & 2:
        return "(private/random MAC)"
    return ""


def ensure_oui_db():
    """Report the vendor database; download Wireshark's list once if nothing usable is installed."""
    db = load_oui()
    count = len(db[6])
    cache_age = time.time() - os.path.getmtime(OUI_CACHE) if os.path.exists(OUI_CACHE) else None
    if (count < 5000 or ARGS.update_oui) and not ARGS.no_oui_download:
        R.progress(f"fetching the MAC vendor list from {urlparse(OUI_URL).hostname} (one-time, ~3 MB) …")
        try:
            import urllib.request    # plain system routing: this is data, not a test of the link
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": f"nettest/{VERSION}"})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read(20 * 1024 * 1024).decode("utf-8", "replace")
            probe = {6: {}, 7: {}, 9: {}}
            _oui_manuf(probe, body.splitlines(True))
            if len(probe[6]) < 5000:
                raise ValueError(f"unexpected content ({len(probe[6])} prefixes)")
            make_output_dir(os.path.dirname(OUI_CACHE))
            with private_open(OUI_CACHE + ".tmp") as f:
                f.write(body)
            os.replace(OUI_CACHE + ".tmp", OUI_CACHE)
            db = load_oui()
            count, cache_age = len(db[6]), 0
        except (OSError, ValueError) as e:
            R.add("INFO", "MAC vendor database", f"download failed ({describe_exc(e)}) - vendors may be missing; "
                  "install 'ieee-data' or 'wireshark-common', or retry with --update-oui")
    if count:
        R.add("INFO", "MAC vendor database", f"{count} 24-bit, {len(db[7])} 28-bit, {len(db[9])} 36-bit prefixes from "
              + ", ".join(_oui_sources) + (f" (cache {cache_age / 86400:.0f} days old)" if cache_age else ""))
    elif ARGS.no_oui_download:
        R.add("INFO", "MAC vendor database", "none installed and download disabled - devices show without maker")


def own_macs():
    out = {}
    for n in os.listdir("/sys/class/net"):
        m = sysread(f"/sys/class/net/{n}/address")
        if m and m != "00:00:00:00:00:00":
            out[m] = n
    return out


_bind_warned = False


def bsock(family, stype, proto=0):
    """Socket bound to the interface under test."""
    global _bind_warned
    s = socket.socket(family, stype, proto)
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, IFACE.encode())
    except PermissionError:
        if not _bind_warned:
            _bind_warned = True
            F["unbound"] = True
            R.add("WARN", "Socket binding",
                  f"cannot bind sockets to {IFACE} - DNS/TCP/HTTP tests follow the normal routing table and "
                  "may leave through another interface (e.g. Wi-Fi)")
    return s


# --------------------------------------------------------------------------- ping (iputils)

def ping(target, count=10, interval=0.2, size=None, df=False, wait=1.0, v6=None):
    if v6 is None:
        v6 = ":" in target
    if not ROOT:
        interval = max(interval, 0.2)
    cmd = ["ping", "-6" if v6 else "-4", "-n", "-c", str(count), "-i", str(interval),
           "-W", str(wait), "-I", IFACE]
    if size is not None:
        cmd += ["-s", str(size)]
    if df:
        cmd += ["-M", "do"]
    cmd.append(target.split("%")[0])
    rc, out, err = run(cmd, timeout=count * interval + wait + 15)
    text = out + err
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    tx, rx = (int(m.group(1)), int(m.group(2))) if m else (count, 0)
    rtts = [float(x) for x in re.findall(r"time[=<]([\d.]+) ?ms", text)]
    mtu = re.search(r"mtu\s*[=:]\s*(\d+)", text)
    errs = [l.strip() for l in text.splitlines()
            if re.search(r"unreachable|Frag needed|too long|Packet too big|Network is|cannot|failed|Invalid|denied", l, re.I)]
    return {"target": target, "tx": tx, "rx": rx,
            "loss": 100.0 * (tx - rx) / tx if tx else 100.0, "rtts": rtts,
            "min": min(rtts) if rtts else None, "avg": mean(rtts), "max": max(rtts) if rtts else None,
            "jitter": jitter(rtts), "mtu_hint": int(mtu.group(1)) if mtu else None,
            "errors": errs[:3], "rc": rc}


def ping_summary(p):
    s = f"{p['rx']}/{p['tx']} replies, loss {p['loss']:.0f}%"
    if p["rtts"]:
        s += (f", rtt min/avg/max {fmt_ms(p['min'])}/{fmt_ms(p['avg'])}/{fmt_ms(p['max'])} ms"
              f", jitter {fmt_ms(p['jitter'])} ms")
    elif p["errors"]:
        s += f" ({p['errors'][0]})"
    return s


def ping_status(p, warn_loss=1, fail_loss=20, warn_rtt=None):
    if p["rx"] == 0:
        return "FAIL"
    if p["loss"] >= fail_loss:
        return "FAIL"
    if p["loss"] >= warn_loss or (warn_rtt and p["avg"] and p["avg"] > warn_rtt):
        return "WARN"
    return "PASS"


# --------------------------------------------------------------------------- raw ICMP / ICMPv6

class RawIcmp:
    """Raw ICMP / ICMPv6 echo sender/receiver bound to the interface (root only)."""

    def __init__(self, v6=False):
        self.v6 = v6
        if v6:
            self.s = bsock(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, IFINDEX)
        else:
            self.s = bsock(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.ident = random.randint(1, 0xFFFF)
        self.seq = 0
        self.payload = b"nettest-" + bytes(48)

    def close(self):
        self.s.close()

    def send(self, dst, ttl=64):
        self.seq = (self.seq + 1) & 0xFFFF
        if self.v6:
            pkt = struct.pack("!BBHHH", 128, 0, 0, self.ident, self.seq) + self.payload  # kernel fills checksum
            self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
            self.s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, min(ttl, 255))
        else:
            hdr = struct.pack("!BBHHH", 8, 0, 0, self.ident, self.seq)
            pkt = struct.pack("!BBHHH", 8, 0, checksum(hdr + self.payload), self.ident, self.seq) + self.payload
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        t = time.monotonic()
        try:
            self.s.sendto(pkt, sockaddr(dst, 0)[1])
        except OSError:
            pass
        return self.seq, t

    def recv(self, timeout):
        """Return (kind, src, seq, t, code) for one of OUR packets, or None on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            r, _, _ = select.select([self.s], [], [], max(0.0, deadline - time.monotonic()))
            if not r:
                return None
            data, addr = self.s.recvfrom(2048)
            t = time.monotonic()
            try:
                ev = self._parse(data, addr, t)
            except (IndexError, struct.error, ValueError):
                ev = None          # malformed packet from the network: ignore it
            if ev:
                return ev

    def _parse(self, data, addr, t):
        """(kind, src, seq, t, code) if this packet answers one of our probes, else None."""
        src = addr[0].split("%")[0]
        if self.v6:
            icmp, reply, errs, inner_proto = data, 129, {3: "ttl", 1: "unreach", 2: "ptb"}, 58
        else:
            icmp, reply, errs, inner_proto = data[(data[0] & 0x0F) * 4:], 0, {11: "ttl", 3: "unreach"}, 1
        if len(icmp) < 8:
            return None
        typ, code = icmp[0], icmp[1]
        if typ == reply:
            ident, seq = struct.unpack("!HH", icmp[4:8])
            return ("reply", src, seq, t, code) if ident == self.ident else None
        if typ not in errs:
            return None
        inner = icmp[8:]
        if self.v6:
            if len(inner) < 48 or inner[6] != inner_proto:
                return None
            iicmp = inner[40:48]
        else:
            if len(inner) < 28 or inner[9] != inner_proto:
                return None
            iicmp = inner[(inner[0] & 0x0F) * 4:][:8]
        if len(iicmp) < 8:
            return None
        ident, seq = struct.unpack("!HH", iicmp[4:8])
        return (errs[typ], src, seq, t, code) if ident == self.ident else None


def path_wait(rtt_max_ms):
    """How long a trace round waits for answers: 1 s normally, longer on slow links (satellite, loaded LTE)."""
    return 1.0 if not rtt_max_ms or rtt_max_ms < 500 else min(4.0, rtt_max_ms / 1000 * 1.5 + 0.5)


def mtr(dst, rounds=10, max_ttl=30, wait=1.0, v6=False):
    """mtr-style trace: every round probes all TTLs at once, collects replies."""
    ri = RawIcmp(v6)
    hops = {t: {"sent": 0, "recv": 0, "rtts": [], "addrs": {}, "unreach": {}} for t in range(1, max_ttl + 1)}
    dest_ttl = None
    stop_ttl = None     # an intermediate router answered "unreachable": nothing lies beyond it
    dstn = dst.split("%")[0]
    try:
        for _ in range(rounds):
            pending = {}
            for ttl in range(1, (dest_ttl or stop_ttl or max_ttl) + 1):
                seq, t = ri.send(dst, ttl)
                pending[seq] = (ttl, t)
                hops[ttl]["sent"] += 1
                time.sleep(0.004)
            deadline = time.monotonic() + wait
            while pending and time.monotonic() < deadline:
                ev = ri.recv(deadline - time.monotonic())
                if not ev:
                    break
                kind, src, seq, t, code = ev
                if seq not in pending or kind == "ptb":
                    continue
                ttl, ts = pending.pop(seq)
                h = hops[ttl]
                if kind == "unreach":
                    h["unreach"][(src, code)] = h["unreach"].get((src, code), 0) + 1
                h["recv"] += 1
                h["rtts"].append((t - ts) * 1000)
                h["addrs"][src] = h["addrs"].get(src, 0) + 1
                if (kind == "reply" or (kind == "unreach" and src == dstn)) and (dest_ttl is None or ttl < dest_ttl):
                    dest_ttl = ttl
                elif kind == "unreach" and (stop_ttl is None or ttl < stop_ttl):
                    stop_ttl = ttl
    finally:
        ri.close()
    last = dest_ttl or stop_ttl or max(([t for t, h in hops.items() if h["recv"]] or [0]))
    if not dest_ttl and not stop_ttl:
        last = min(max_ttl, last + 2)
    out = []
    for ttl in range(1, last + 1):
        h = hops[ttl]
        addr = max(h["addrs"], key=h["addrs"].get) if h["addrs"] else None
        out.append({"ttl": ttl, "addr": addr, "all_addrs": list(h["addrs"]), "sent": h["sent"],
                    "recv": h["recv"], "loss": 100.0 * (h["sent"] - h["recv"]) / h["sent"] if h["sent"] else 100.0,
                    "avg": mean(h["rtts"]), "best": min(h["rtts"]) if h["rtts"] else None,
                    "worst": max(h["rtts"]) if h["rtts"] else None,
                    "unreach": [(s, c, n) for (s, c), n in h["unreach"].items()]})
    return out, dest_ttl


def tcp_trace(dst, port=443, v6=False, rounds=2, max_ttl=20, wait=1.5):
    """Traceroute with TCP SYNs to dst:port; gets through where ICMP echo is filtered."""
    fam, sa = sockaddr(dst, port)
    if v6:
        raw = bsock(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    else:
        raw = bsock(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    hops = {t: {"sent": 0, "recv": 0, "rtts": [], "addrs": {}} for t in range(1, max_ttl + 1)}
    dest_ttl = stop_ttl = None
    dstn = dst.split("%")[0]

    def record(ttl, src, t0):
        h = hops[ttl]
        h["recv"] += 1
        h["rtts"].append(ms(t0))
        h["addrs"][src] = h["addrs"].get(src, 0) + 1

    try:
        for _ in range(rounds):
            pending, fdmap = {}, {}
            for ttl in range(1, (dest_ttl or stop_ttl or max_ttl) + 1):
                s = bsock(fam, socket.SOCK_STREAM)
                s.setblocking(False)
                if v6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
                else:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                try:
                    s.connect(sa)
                except BlockingIOError:
                    pass
                except OSError:
                    s.close()
                    continue
                sport = s.getsockname()[1]
                pending[sport] = (ttl, time.monotonic(), s)
                fdmap[s.fileno()] = sport
                hops[ttl]["sent"] += 1
            socks = [p[2] for p in pending.values()]
            deadline = time.monotonic() + wait
            while pending and time.monotonic() < deadline:
                rl, wl, _ = select.select([raw], [p[2] for p in pending.values()], [], max(0.0, deadline - time.monotonic()))
                for s in wl:
                    sport = fdmap[s.fileno()]
                    if sport not in pending:
                        continue
                    ttl, t0, _ = pending.pop(sport)
                    if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in (0, errno.ECONNREFUSED):
                        record(ttl, dstn, t0)
                        dest_ttl = ttl if dest_ttl is None else min(dest_ttl, ttl)
                if raw in rl:
                    data, addr = raw.recvfrom(2048)
                    try:
                        icmp = data if v6 else data[(data[0] & 0x0F) * 4:]
                        if len(icmp) < 8 or icmp[0] not in ((3, 1) if v6 else (11, 3)):
                            continue
                        inner = icmp[8:]
                        if v6:
                            if len(inner) < 44 or inner[6] != 6:
                                continue
                            sport = struct.unpack("!H", inner[40:42])[0]
                        else:
                            if len(inner) < 24 or inner[9] != 6:
                                continue
                            sport = struct.unpack("!H", inner[(inner[0] & 0x0F) * 4:][:2])[0]
                        if sport in pending:
                            ttl, t0, _ = pending.pop(sport)
                            record(ttl, addr[0].split("%")[0], t0)
                            if icmp[0] == (1 if v6 else 3):
                                stop_ttl = ttl if stop_ttl is None else min(stop_ttl, ttl)
                    except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                        continue
            for s in socks:
                s.close()
    finally:
        raw.close()
    last = dest_ttl or stop_ttl or max(([t for t, h in hops.items() if h["recv"]] or [0]))
    out = []
    for ttl in range(1, last + 1):
        h = hops[ttl]
        addr = max(h["addrs"], key=h["addrs"].get) if h["addrs"] else None
        out.append({"ttl": ttl, "addr": addr, "sent": h["sent"], "recv": h["recv"], "avg": mean(h["rtts"])})
    return out, dest_ttl


def multicast_echo(group, wait=2.0):
    """Ping an IPv6 multicast group (ff02::1 all nodes, ff02::2 all routers); return responders."""
    ri = RawIcmp(v6=True)
    mine = {norm6(a) for a in (F.get("v6_ll") or []) + (F.get("v6_all_addrs") or [])}
    found = {}
    try:
        t0 = time.monotonic()
        for i in range(2):
            seq, t = ri.send(group, ttl=1)
            end = time.monotonic() + wait / 2
            while time.monotonic() < end:
                ev = ri.recv(end - time.monotonic())
                if ev and ev[0] == "reply" and ev[1] not in mine:
                    found.setdefault(ev[1], (ev[3] - t0) * 1000)
    finally:
        ri.close()
    return found


# --------------------------------------------------------------------------- DNS client

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_build(name, qtype, qid):
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".") if p) + b"\0"
    return hdr + q + struct.pack("!HH", qtype, 1)


def dns_name(buf, off):
    labels, end, hops = [], None, 0
    while True:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((ln & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 40:
                raise ValueError("DNS name compression loop")
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode(errors="replace"))
        off += 1 + ln
    return ".".join(labels), (end if end is not None else off)


def dns_names_plain(b):
    """Uncompressed label sequences (DHCPv6 option 24, RA DNSSL)."""
    names, labels, i = [], [], 0
    while i < len(b):
        ln = b[i]
        if ln == 0:
            if labels:
                names.append(".".join(labels))
            labels = []
            i += 1
            continue
        labels.append(b[i + 1:i + 1 + ln].decode(errors="replace"))
        i += 1 + ln
    return names


def dns_parse(buf):
    qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = dns_name(buf, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = dns_name(buf, off)
        t, _cl, ttl, rdl = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + rdl]
        if t == 1 and rdl == 4:
            val = socket.inet_ntop(socket.AF_INET, rd)
        elif t == 28 and rdl == 16:
            val = socket.inet_ntop(socket.AF_INET6, rd)
        elif t in (2, 5, 12):
            val = dns_name(buf, off)[0]
        else:
            val = rd.hex()
        answers.append((t, val, ttl))
        off += rdl
    return {"id": qid, "rcode": flags & 0x0F, "tc": bool(flags & 0x0200), "answers": answers}


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise NetError("connection closed")
        buf += d
    return buf


def dns_query(server, name, qtype="A", tcp=False, timeout=2.0):
    qid = random.randint(0, 0xFFFF)
    pkt = dns_build(name, QTYPES[qtype], qid)
    fam, sa = sockaddr(server, 53)
    t0 = time.monotonic()
    s = bsock(fam, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if tcp:
            s.connect(sa)
            s.sendall(struct.pack("!H", len(pkt)) + pkt)
            ln = struct.unpack("!H", recv_exact(s, 2))[0]
            data = recv_exact(s, ln)
        else:
            s.sendto(pkt, sa)
            while True:
                data, _ = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                    break
                if time.monotonic() - t0 > timeout:
                    raise socket.timeout()
    finally:
        s.close()
    r = dns_parse(data)
    r["ms"] = ms(t0)
    return r


_dns_cache = {}


def resolve(name, v6=False):
    """Resolve through the interface, using the resolvers found to work in the DNS stage."""
    if is_ip(name):
        return [name]
    key = (name, v6)
    if key in _dns_cache:
        return _dns_cache[key]
    for srv in (F.get("resolvers") or PUBLIC_DNS)[:4]:
        try:
            r = dns_query(srv, name, "AAAA" if v6 else "A", timeout=2)
        except DNS_ERRORS:
            continue
        if r["rcode"] in (0, 3):
            ips = [v for t, v, _ in r["answers"] if t == (28 if v6 else 1)]
            _dns_cache[key] = ips
            return ips
    return []


def rdns(ip, server=None):
    try:
        srv = server or (F.get("resolvers") or PUBLIC_DNS)[0]
        r = dns_query(srv, ipaddress.ip_address(ip.split("%")[0]).reverse_pointer, "PTR", timeout=1.5)
        names = [v for t, v, _ in r["answers"] if t == 12]
        return names[0] if names else None
    except DNS_ERRORS:
        return None


# --------------------------------------------------------------------------- TCP / HTTP

def tcp_connect(ip, port, timeout=3.0):
    fam, sa = sockaddr(ip, port)
    s = bsock(fam, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect(sa)
        return "open", ms(t0)
    except ConnectionRefusedError:
        return "refused", ms(t0)
    except socket.timeout:
        return "timeout", None
    except OSError as e:
        return f"error: {e.strerror or e}", None
    finally:
        s.close()


def _cert_name(field):
    if not field:
        return None
    d = {k: v for rdn in field for k, v in rdn}
    return d.get("organizationName") or d.get("commonName")


def dechunk(b):
    out, i = bytearray(), 0
    while True:
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(b[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        out += b[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return bytes(out)


def http_request(url, method="GET", headers=None, body=None, upload_size=0, timeout=8.0,
                 max_body=1 << 20, ip=None, v6=False, sink=None, stop_at=None, tcp_log=None):
    """Minimal HTTP/1.1 client over an interface-bound socket. Returns a dict."""
    u = urlparse(url)
    tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if tls else 80)
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    if ip is None:
        ips = resolve(host, v6)
        if not ips:
            raise NetError(f"DNS cannot resolve {host}" + (" (AAAA)" if v6 else ""))
        ip = ips[0]
    fam, sa = sockaddr(ip, port)
    timing, tlsinfo = {}, None
    t0 = time.monotonic()
    raw = bsock(fam, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    s = raw
    try:
        s.connect(sa)
        timing["connect_ms"] = ms(t0)
        if tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(raw, server_hostname=host)
            timing["tls_ms"] = ms(t0) - timing["connect_ms"]
            cert = s.getpeercert() or {}
            tlsinfo = {"version": s.version(), "cipher": s.cipher()[0],
                       "issuer": _cert_name(cert.get("issuer")), "expires": cert.get("notAfter")}
        hosthdr = f"[{host}]" if ":" in host else host
        if port not in (80, 443):
            hosthdr += f":{port}"
        h = {"Host": hosthdr, "User-Agent": f"nettest/{VERSION}", "Accept": "*/*", "Connection": "close"}
        if body is not None:
            h["Content-Length"] = str(len(body))
        elif upload_size:
            h["Content-Length"] = str(upload_size)
            h["Content-Type"] = "application/octet-stream"
        h.update(headers or {})
        req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        s.sendall(req.encode())
        if body is not None:
            s.sendall(body)
        elif upload_size:
            chunk, sent = bytes(65536), 0
            while sent < upload_size:
                if stop_at and time.monotonic() >= stop_at:
                    return {"status": None, "aborted": True, "bytes": 0, "timing": timing, "ip": ip}
                n = min(len(chunk), upload_size - sent)
                s.sendall(chunk[:n])
                sent += n
                if sink:
                    sink(n)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(65536)
            if not d:
                break
            buf += d
            if len(buf) > 262144:
                raise NetError("oversized response header")
        if not buf:
            raise NetError("connection closed without a response")
        timing["ttfb_ms"] = ms(t0)
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        parts = lines[0].split()
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        rh = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            rh[k.strip().lower()] = v.strip()
        clen = int(rh["content-length"]) if rh.get("content-length", "").isdigit() else None
        data, total = bytearray(), 0

        def take(d):
            nonlocal total
            total += len(d)
            if sink:
                sink(len(d))
            elif len(data) < max_body:
                data.extend(d[:max_body - len(data)])

        if rest:
            take(rest)
        while (clen is None or total < clen) and method != "HEAD" and status not in (204, 304):
            if stop_at and time.monotonic() >= stop_at:
                break
            if not sink and len(data) >= max_body:
                break
            d = s.recv(262144)
            if not d:
                break
            take(d)
        bodyb = bytes(data)
        if "chunked" in rh.get("transfer-encoding", "").lower() and not sink:
            bodyb = dechunk(bodyb)
        timing["total_ms"] = ms(t0)
        return {"status": status, "reason": " ".join(parts[2:]), "headers": rh, "body": bodyb,
                "bytes": total, "timing": timing, "ip": ip, "tls": tlsinfo}
    finally:
        if tcp_log is not None:
            try:
                tcp_log.append(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232))
            except OSError:
                pass
        s.close()


def describe_exc(e):
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"TLS certificate verification failed: {e.verify_message}"
    if isinstance(e, ssl.SSLError):
        return f"TLS error: {e.reason or e}"
    if isinstance(e, socket.timeout):
        return "timed out"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    if isinstance(e, ConnectionResetError):
        return "connection reset (RST injected or middlebox)"
    if isinstance(e, OSError):
        return e.strerror or str(e)
    return str(e)


# --------------------------------------------------------------------------- interface info

def iface_kind(name):
    base = f"/sys/class/net/{name}"
    if name == "lo":
        return "loopback"
    if os.path.exists(base + "/wireless") or os.path.exists(base + "/phy80211"):
        return "wifi"
    if not os.path.exists(base + "/device"):
        return "virtual"
    dev = os.path.realpath(base + "/device")
    etype = sysread(base + "/type") == "1"
    if "/usb" in dev:
        return "usb-ethernet" if etype else "usb-other"
    return "ethernet" if etype else "other"


def usb_info(name):
    base = f"/sys/class/net/{name}/device"
    if not os.path.exists(base):
        return None
    d = os.path.realpath(base)
    while d and d != "/":
        if os.path.exists(os.path.join(d, "idVendor")):
            rd = lambda f: sysread(os.path.join(d, f))  # noqa: E731
            return {"busid": os.path.basename(d), "vendor": rd("idVendor"), "product_id": rd("idProduct"),
                    "manufacturer": rd("manufacturer"), "product": rd("product"),
                    "speed": rd("speed"), "version": rd("version"), "power_control": rd("power/control"),
                    "autosuspend_ms": rd("power/autosuspend_delay_ms"), "path": d}
        d = os.path.dirname(d)
    return None


# USB Ethernet chips whose vendor driver is usually better than the generic class driver (cdc_ncm/cdc_ether)
# that grabs them when the adapter's active configuration exposes a CDC interface.
VENDOR_DRIVERS = {"0b95": ("ax88179_178a", "ASIX AX88179/AX88179A/B / AX88178A"),
                  "0bda": ("r8152", "Realtek RTL8152/8153/8156")}
GENERIC_USB_NET = {"cdc_ncm", "cdc_ether", "rndis_host", "cdc_subset"}
USB_CLASS = {0x02: "CDC", 0x0a: "CDC-data", 0xff: "vendor-specific", 0xe0: "wireless", 0x08: "storage"}
CDC_SUBCLASS = {0x06: "ECM", 0x0d: "NCM", 0x0e: "MBIM", 0x02: "ACM"}


def usb_configs(usb):
    """Parse the device's raw descriptors: {config value: [(interface no, class, subclass), ...]} (alt setting 0)."""
    try:
        with open(os.path.join(usb["path"], "descriptors"), "rb") as f:
            raw = f.read()
    except OSError:
        return {}
    out, cfg, i = {}, None, 18      # skip the 18-byte device descriptor
    while i + 2 <= len(raw):
        ln, typ = raw[i], raw[i + 1]
        if ln < 2 or i + ln > len(raw):
            break
        if typ == 2 and ln >= 9:
            cfg = raw[i + 5]
            out.setdefault(cfg, [])
        elif typ == 4 and ln >= 9 and cfg is not None and raw[i + 3] == 0:
            out[cfg].append((raw[i + 2], raw[i + 5], raw[i + 6]))
        i += ln
    return out


def intf_label(cls, sub):
    if cls == 0x02:
        return f"CDC-{CDC_SUBCLASS.get(sub, hex(sub))}"
    return USB_CLASS.get(cls, f"class {cls:#04x}")


def driver_situation(usb, driver):
    """Is a known vendor chip running on a generic class driver, and can it be switched to the vendor driver?"""
    if not usb or usb.get("vendor") not in VENDOR_DRIVERS:
        return None
    mod, chips = VENDOR_DRIVERS[usb["vendor"]]
    cur = int(sysread(os.path.join(usb["path"], "bConfigurationValue"), "0") or 0)
    cfgs = usb_configs(usb)
    vendor_cfgs = [c for c, intfs in cfgs.items() if any(cls == 0xff for _, cls, _ in intfs)]
    info = {"module": mod, "chips": chips, "current_config": cur, "configs": cfgs, "vendor_configs": vendor_cfgs,
            "generic": driver in GENERIC_USB_NET,
            "module_available": run(["modinfo", "-n", mod])[0] == 0,
            "busid": usb["busid"], "vendor": usb["vendor"], "product_id": usb["product_id"]}
    if not info["generic"]:
        info["action"] = None
    elif any(c != cur for c in vendor_cfgs):
        info["action"] = ("config", next(c for c in vendor_cfgs if c != cur))
    elif cur in vendor_cfgs:
        info["action"] = ("bind", None)     # vendor interface exists in this config but the generic driver holds it
    else:
        info["action"] = None               # firmware offers only the CDC interface: no vendor-driver path
    return info


def describe_configs(ds):
    return "; ".join(f"config {c}{' (active)' if c == ds['current_config'] else ''}: "
                     + (", ".join(intf_label(cls, sub) for _, cls, sub in intfs) or "no interfaces")
                     for c, intfs in sorted(ds["configs"].items())) or "descriptors not readable"


def usb_net_iface(busid):
    """The network interface that currently belongs to USB device `busid`, if any."""
    for n in sorted(os.listdir("/sys/class/net")):
        u = usb_info(n)
        if u and u["busid"] == busid:
            return n
    return None


def run_failed():
    """A check failed, or the final diagnosis found a failing layer."""
    return bool(F.get("diagnosis_failed")) or any(r["status"] == "FAIL" for r in R.results)


def link_in_use():
    """Is this interface connected and addressed, so that dropping the link would interrupt it?"""
    return has_carrier() and any(
        a.get("scope") == "global" for l in ipj("addr", "show", "dev", IFACE) for a in l.get("addr_info", []))


def fix_driver():
    """--fix-driver: move a vendor chip from the generic cdc_* driver to its vendor driver (until re-plug)."""
    global IFACE, IFINDEX
    R.section("L1", f"L1  DRIVER FIX   ({IFACE})")
    usb = usb_info(IFACE)
    drv_link = f"/sys/class/net/{IFACE}/device/driver"
    driver = os.path.basename(os.path.realpath(drv_link)) if os.path.exists(drv_link) else "?"
    ds = driver_situation(usb, driver)
    if not ds:
        R.add("SKIP", "Driver fix", f"{IFACE} is not a USB adapter with a known vendor driver - nothing to change")
        return
    R.add("INFO", "USB configurations", describe_configs(ds))
    if not ds["generic"]:
        R.add("PASS", "Driver fix", f"already on {driver} - nothing to change")
        return
    if not ROOT:
        R.add("SKIP", "Driver fix", "needs root")
        return
    if link_in_use() and not ARGS.force:
        R.add("SKIP", "Driver fix", f"{IFACE} has a working connection and rebinding the driver would drop it and "
              "request a new address - nothing changed (--force does it anyway)")
        return
    if not ds["module_available"]:
        R.add("FAIL", "Driver fix", f"the {ds['module']} module is not installed for this kernel")
        return
    if not ds["action"]:
        R.add("WARN", "Driver fix", f"the adapter's firmware offers only {driver}'s interface "
              f"(no vendor-specific one) - {ds['module']} cannot take it; nothing changed")
        return
    run(["modprobe", ds["module"]])
    kind, cfg = ds["action"]
    devpath = usb["path"]
    try:
        if kind == "config":
            R.progress(f"switching USB {ds['busid']} from config {ds['current_config']} to {cfg} …")
            with open(os.path.join(devpath, "bConfigurationValue"), "w") as f:
                f.write(str(cfg))
        else:
            intf = next((e for e in sorted(os.listdir(devpath))
                         if e.startswith(ds["busid"] + ":") and sysread(f"{devpath}/{e}/bInterfaceClass") == "ff"), None)
            if not intf:
                R.add("FAIL", "Driver fix", "vendor-specific interface not found in sysfs")
                return
            R.progress(f"moving USB interface {intf} from {driver} to {ds['module']} …")
            if os.path.exists(f"{devpath}/{intf}/driver"):
                with open(f"{devpath}/{intf}/driver/unbind", "w") as f:
                    f.write(intf)
            with open(f"/sys/bus/usb/drivers/{ds['module']}/bind", "w") as f:
                f.write(intf)
    except OSError as e:
        R.add("FAIL", "Driver fix", f"kernel refused the change: {e}")
        return
    new, t_end = None, time.monotonic() + 15
    while time.monotonic() < t_end:
        new = usb_net_iface(ds["busid"])
        if new and os.path.basename(os.path.realpath(f"/sys/class/net/{new}/device/driver")) == ds["module"]:
            break
        time.sleep(0.5)
    else:
        R.add("FAIL", "Driver fix", f"no {ds['module']} interface appeared within 15 s"
              + (f" (current: {new})" if new else "") + " - re-plug the adapter to go back")
        if new:
            IFACE, IFINDEX = new, socket.if_nametoindex(new)
        return
    # udev renames the new interface (eth0 -> enp…) a moment after it appears: wait, then look it up again
    run(["udevadm", "settle", "-t", "10"], timeout=15)
    time.sleep(1)
    new = usb_net_iface(ds["busid"]) or new
    IFACE, IFINDEX = new, socket.if_nametoindex(new)
    if not int(sysread(f"/sys/class/net/{IFACE}/flags", "0x0"), 16) & 1:
        run(["ip", "link", "set", IFACE, "up"])
    # give the PHY time to negotiate and NetworkManager time to start DHCP on the new interface
    R.progress("waiting for the link on the new driver …")
    t_end = time.monotonic() + 12
    while time.monotonic() < t_end and not has_carrier():
        time.sleep(0.5)
    time.sleep(3)
    F["driver_fixed"] = ds["module"]
    R.add("PASS", "Driver fix", f"{IFACE} now runs on {ds['module']} (was {driver}); "
          f"carrier {'up' if sysread(f'/sys/class/net/{IFACE}/carrier') == '1' else 'down'}. Lasts until the adapter is re-plugged.")
    if kind == "config":
        R.note("To make it permanent, create /etc/udev/rules.d/50-usb-ethernet-vendor-config.rules with:")
        R.note(f'  ACTION=="add", SUBSYSTEM=="usb", ATTR{{idVendor}}=="{ds["vendor"]}", '
               f'ATTR{{idProduct}}=="{ds["product_id"]}", ATTR{{bConfigurationValue}}!="{cfg}", '
               f'ATTR{{bConfigurationValue}}="{cfg}"')


def read_stats():
    return {k: int(sysread(f"/sys/class/net/{IFACE}/statistics/{k}", "0") or 0) for k in STAT_KEYS}


def ethtool_info():
    rc, out, _ = run(["ethtool", IFACE])
    info, key = {}, None
    if rc not in (0, 75):
        return info
    for line in out.splitlines()[1:]:
        s = line.strip()
        if not s:
            continue
        m = re.match(r"([A-Za-z][^:]*):\s*(.*)$", s)
        if m and not re.match(r"^\d+base", s):
            key = m.group(1).strip()
            info[key] = m.group(2).strip()
        elif key:
            info[key] = (info[key] + " " + s).strip()
    return info


def mode_speeds(text):
    return [int(x) for x in re.findall(r"(\d+)base", text or "")]


def my_mac():
    return bytes.fromhex(sysread(f"/sys/class/net/{IFACE}/address", "00:00:00:00:00:00").replace(":", ""))


def gather_addressing():
    addrs = ipj("addr", "show", "dev", IFACE)
    v4, v6info = [], []
    for a in (addrs[0].get("addr_info", []) if addrs else []):
        if a.get("family") == "inet":
            v4.append(f"{a['local']}/{a.get('prefixlen')}")
        elif a.get("family") == "inet6":
            v6info.append(a)
    F["ipv4_all"] = v4
    F["ipv4"] = v4[0].split("/")[0] if v4 else None
    F["ipv4_prefix"] = v4[0] if v4 else None
    F["apipa"] = bool(F["ipv4"] and F["ipv4"].startswith("169.254."))
    F["v6_addr_info"] = v6info
    F["v6_all_addrs"] = [a["local"] for a in v6info]
    F["v6_ll"] = [a["local"] for a in v6info if a.get("scope") == "link"]
    F["v6_global_addrs"] = [a["local"] for a in v6info if a.get("scope") == "global" and is_gua(a["local"])
                            and not a.get("deprecated")]
    F["v6_ula_addrs"] = [a["local"] for a in v6info if a.get("scope") == "global" and addr_class(a["local"]) == "ULA"]
    F["v6_dadfailed"] = [a["local"] for a in v6info if a.get("dadfailed")]
    F["v6_deprecated_addrs"] = [a["local"] for a in v6info if a.get("deprecated") and a.get("scope") == "global"]
    routes = ipj("route", "show", "default")
    F["all_default_routes"] = routes
    mine = [r for r in routes if r.get("dev") == IFACE]
    F["default_route"] = mine[0] if mine else None
    F["gateway"] = ARGS.gateway or (mine[0].get("gateway") if mine else None)
    r6 = ipj("-6", "route", "show", "default")
    F["all_default_routes6"] = r6
    mine6 = [r for r in r6 if r.get("dev") == IFACE]
    F["default_route6"] = mine6[0] if mine6 else None
    F["gateway6"] = mine6[0].get("gateway") if mine6 else None


def v6_route_ok():
    return bool(F.get("v6_global_addrs") and F.get("default_route6"))


def iface_dns_servers():
    found = []
    if shutil.which("nmcli"):
        _, out, _ = run(["nmcli", "-t", "-g", "IP4.DNS,IP6.DNS", "device", "show", IFACE])
        found += re.findall(r"[0-9a-fA-F:.]+", out.replace("\\:", ":"))
    if shutil.which("resolvectl"):
        _, out, _ = run(["resolvectl", "dns", IFACE])
        found += [t.split("%")[0] for t in out.split(":", 1)[-1].split()] if ":" in out else []
    servers = []
    for s in found:
        if is_ip(s) and s not in servers and addr_class(s) != "loopback":
            servers.append(norm6(s) if ":" in s else s)
    return dedupe(servers)


# --------------------------------------------------------------------------- L0

def test_environment():
    R.section("L0", "L0  ENVIRONMENT")
    un = os.uname()
    R.add("INFO", "Host", f"{un.nodename}, Linux {un.release}, Python {platform.python_version()}, nettest {VERSION}")
    R.add("INFO", "Start time", R.started.isoformat(timespec="seconds"))
    R.add("PASS" if ROOT else "WARN", "Privileges",
          "root" if ROOT else "not root - DHCP, ARP/NDP, LAN discovery and raw traceroute are skipped; "
                              "re-run with sudo for a complete result")
    for tool, need in (("ip", True), ("ping", True), ("ethtool", False), ("nmcli", False),
                       ("resolvectl", False), ("journalctl", False), ("mtr", False), ("iw", False)):
        if not shutil.which(tool):
            R.add("FAIL" if need else "WARN", f"Tool '{tool}'", "missing" + ("" if need else
                  " (optional - some details will be skipped)"))
    ensure_oui_db()
    R.note("Interfaces:")
    for link in ipj("addr"):
        name = link.get("ifname")
        v4 = [f"{a['local']}/{a['prefixlen']}" for a in link.get("addr_info", []) if a.get("family") == "inet"]
        v6 = [a["local"] for a in link.get("addr_info", []) if a.get("family") == "inet6" and a.get("scope") == "global"]
        R.note(f"  {name:<18} {iface_kind(name):<13} {link.get('operstate', '?'):<8} {' '.join(v4) or '-'}"
               + (f"  +{len(v6)} global IPv6" if v6 else ""))
    for fam, routes in (("IPv4", ipj("route", "show", "default")), ("IPv6", ipj("-6", "route", "show", "default"))):
        if routes:
            R.note(f"{fam} default routes:")
            for r in routes:
                R.note(f"  via {r.get('gateway', '-'):<26} dev {r.get('dev'):<16} metric {r.get('metric', 0)}"
                       f"  ({r.get('protocol', 'static')})")
        else:
            R.add("INFO", f"{fam} default route", "the system has none at all")
    vpns = [l.get("ifname") for l in ipj("-d", "link")
            if (l.get("linkinfo", {}).get("info_kind") in ("wireguard", "tun", "ipip", "gre", "vti"))
            or re.match(r"^(tun|tap|wg|ppp|vpn|tailscale|zt)", l.get("ifname", ""))]
    if vpns:
        R.add("WARN", "VPN / tunnel interfaces", ", ".join(vpns) + " - may alter routing or DNS while testing")


def select_iface():
    names = sorted(os.listdir("/sys/class/net"))
    if ARGS.iface:
        if ARGS.iface not in names:
            sys.exit(f"Interface {ARGS.iface!r} does not exist. Available: {', '.join(names)}")
        return ARGS.iface
    routes = {}
    for r in ipj("route", "show", "default"):
        if r.get("dev"):
            routes[r["dev"]] = min(r.get("metric", 0), routes.get(r["dev"], 1 << 32))
    cands = sorted((n for n in names if n != "lo"),
                   key=lambda n: (routes.get(n, 1 << 32), not has_carrier(n),
                                  iface_kind(n) == "virtual", n))
    if not cands:
        return None
    if not sys.stdin.isatty():
        sys.exit("No interface given and no terminal to ask on. Use --iface NAME. Available: " + ", ".join(cands))
    print("\nWhich interface do you want to test?")
    width = max(map(len, cands))
    for i, n in enumerate(cands, 1):
        print(f"  {i:>2}) {n:<{width}}  {clean(iface_summary(n))}" + ("  [default route]" if n in routes else ""))
    while True:
        try:
            answer = input(f"Number or name [1 = {cands[0]}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(130)
        if not answer:
            choice = cands[0]
        elif answer.isdigit() and 1 <= int(answer) <= len(cands):
            choice = cands[int(answer) - 1]
        elif answer in names:
            choice = answer
        else:
            print(f"  Not a valid choice: {answer!r}")
            continue
        ARGS.iface = choice
        return choice


def iface_summary(name):
    """One line for the interface menu: kind, link state, addresses, Wi-Fi network."""
    up = has_carrier(name)
    info = ipj("addr", "show", "dev", name)
    addrs = sorted((a for a in (info[0].get("addr_info", []) if info else []) if a.get("scope") == "global"),
                   key=lambda a: a.get("family") != "inet")
    parts = [f"{iface_kind(name):<12}", "link up" if up else "no link"]
    if addrs:
        parts.append(f"{addrs[0]['local']}/{addrs[0]['prefixlen']}")
    ssid = wifi_link(name).get("ssid") if up and iface_kind(name) == "wifi" else None
    if ssid:
        parts.append(f"SSID {ssid}")
    return "  ".join(parts)


def wifi_link(name=None):
    """Radio facts from `iw dev NAME link` (no root needed); {} when not associated or iw is missing."""
    rc, out, _ = run(["iw", "dev", name or IFACE, "link"], timeout=5)
    m = re.search(r"Connected to (\S+)", out)
    if rc != 0 or not m:
        return {}
    w = {"bssid": m.group(1)}
    for key, pat, conv in (("ssid", r"SSID: (.*)", str.strip), ("freq", r"freq:\s*([\d.]+)", float),
                           ("signal", r"signal:\s*(-?\d+)", int), ("rx_rate", r"rx bitrate:\s*([\d.]+)", float),
                           ("tx_rate", r"tx bitrate:\s*([\d.]+)", float)):
        m = re.search(pat, out)
        if m:
            w[key] = conv(m.group(1))
    return w


def test_wifi_radio():
    w = wifi_link()
    F["wifi"] = w
    if not w:
        R.add("SKIP", "Wi-Fi radio", "install 'iw' for signal and bitrate" if not shutil.which("iw")
              else "iw reports no association")
        return
    freq = w.get("freq")
    band = "" if not freq else " (2.4 GHz)" if freq < 3000 else " (5 GHz)" if freq < 5925 else " (6 GHz)"
    R.add("INFO", "Wi-Fi network", f"SSID {w.get('ssid', '?')}, access point {w['bssid']}, "
          f"{freq:.0f} MHz{band}" if freq else f"SSID {w.get('ssid', '?')}, access point {w['bssid']}")
    sig = w.get("signal")
    if sig is not None:
        word = "excellent" if sig >= -55 else "good" if sig >= -67 else "weak" if sig >= -80 else "very weak"
        F["wifi_weak"] = sig < -67
        R.add("PASS" if sig >= -67 else "WARN" if sig >= -80 else "FAIL", "Wi-Fi signal", f"{sig} dBm - {word}")
    if w.get("rx_rate") or w.get("tx_rate"):
        R.add("INFO", "Wi-Fi bitrate", f"negotiated rx {w.get('rx_rate', '?')} / tx {w.get('tx_rate', '?')} Mb/s "
              "(radio rate; real throughput is usually about half of it)")


# --------------------------------------------------------------------------- L1

def test_physical():
    R.section("L1", f"L1  ADAPTER & PHYSICAL LINK   ({IFACE})")
    base = f"/sys/class/net/{IFACE}"
    kind = iface_kind(IFACE)
    drv_link = base + "/device/driver"
    driver = os.path.basename(os.path.realpath(drv_link)) if os.path.exists(drv_link) else "?"
    F["driver"] = driver
    usb = usb_info(IFACE)
    eti = {}
    if shutil.which("ethtool"):
        _, out, _ = run(["ethtool", "-i", IFACE])
        eti = dict(re.findall(r"^([\w-]+):[ \t]*(.*)$", out, re.M))
    F["iface_found"] = True
    if usb:
        name = " ".join(x for x in (usb["manufacturer"], usb["product"]) if x) or "unknown"
        R.add("PASS", "Adapter", f"{name} [{usb['vendor']}:{usb['product_id']}] at USB {usb['busid']}")
        sp = usb["speed"]
        F["usb_speed"] = int(float(sp)) if sp else None
        if sp:
            spv = int(float(sp))
            label = {12: "USB 1.1 Full-Speed", 480: "USB 2.0 High-Speed", 5000: "USB 3.x 5 Gb/s",
                     10000: "USB 3.x 10 Gb/s", 20000: "USB 3.2 20 Gb/s"}.get(spv, f"{spv} Mb/s")
            if spv <= 12:
                R.add("FAIL", "USB bus speed", f"{label} - adapter is crippled (bad port/cable/hub?)")
            elif spv == 480:
                R.add("INFO", "USB bus speed", f"{label} - throughput caps around 300-400 Mb/s "
                      "(fine unless the WAN plan is faster)")
            else:
                R.add("PASS", "USB bus speed", label)
        if usb["power_control"] == "auto":
            R.add("INFO", "USB autosuspend", f"enabled (power/control=auto, delay {usb['autosuspend_ms']} ms) - "
                  "some adapters drop the link after idle; try 'on' if drops are seen")
    R.add("INFO", "Driver", f"{driver} {eti.get('version', '')} firmware={eti.get('firmware-version', '-') or '-'}"
          f" bus={eti.get('bus-info', '-') or '-'}")
    F["iface_kind"] = kind
    ds = driver_situation(usb, driver)
    if ds:
        F["driver_info"] = {k: v for k, v in ds.items() if k != "configs"}
        F["usb_configs"] = describe_configs(ds)
    if usb:
        F["adapter_id"] = f"{usb['vendor']}:{usb['product_id']} {my_mac().hex(':')}"
    if ds and ds["generic"]:
        F["generic_driver"] = driver
        R.add("WARN", "Driver choice", f"{ds['chips']} chip on the generic {driver} driver instead of {ds['module']} - "
              "generic class drivers on these chips are a known cause of 'link up but nothing received'")
        R.note("USB configurations: " + describe_configs(ds))
        if not ds["module_available"]:
            R.note(f"The {ds['module']} module is not installed for this kernel.")
        elif ds["action"]:
            F["driver_fixable"] = True
            R.note(f"Switch it to {ds['module']} for this session:  sudo python3 {sys.argv[0]} --fix-driver"
                   + (f" --iface {IFACE}" if ARGS.iface else ""))
        else:
            R.note(f"The firmware exposes no vendor-specific interface, so {ds['module']} cannot take it. If the link "
                   "stays dead, try a newer kernel or another adapter.")

    flags = int(sysread(base + "/flags", "0x0"), 16)
    F["admin_up"] = bool(flags & 1)
    if not F["admin_up"]:
        R.add("FAIL", "Admin state", f"interface is DOWN - bring it up: sudo ip link set {IFACE} up "
              "(or check that NetworkManager manages it)")
    carrier = sysread(base + "/carrier")
    oper = sysread(base + "/operstate")
    F["carrier"] = carrier == "1"
    wired = kind in WIRED_KINDS
    R.add("PASS" if F["carrier"] else "FAIL",
          "Wi-Fi association" if kind == "wifi" else "Carrier (cable signal)" if wired else "Carrier",
          ("present" if F["carrier"] else "NOT ASSOCIATED with an access point" if kind == "wifi"
           else "NO CARRIER - no electrical link to the router" if wired else "NO CARRIER") + f"; operstate={oper}")
    if kind == "wifi" and F["carrier"]:
        test_wifi_radio()

    et = ethtool_info() if shutil.which("ethtool") else {}
    F["ethtool"] = et
    speed = re.match(r"(\d+)", et.get("Speed", ""))
    speed = int(speed.group(1)) if speed else None
    F["link_speed"] = speed
    duplex = et.get("Duplex", "")
    sup = max(mode_speeds(et.get("Supported link modes")) or [0]) or None
    adv = max(mode_speeds(et.get("Advertised link modes")) or [0]) or None
    partner = max(mode_speeds(et.get("Link partner advertised link modes")) or [0]) or None
    F["link_max_supported"] = sup
    if et and kind != "wifi":
        R.add("INFO", "ethtool", f"speed={et.get('Speed', '?')} duplex={duplex or '?'} autoneg={et.get('Auto-negotiation', '?')}"
              f" port={et.get('Port', '?')} mdix={et.get('MDI-X', '?')}")
        R.note(f"supported up to {sup or '?'} Mb/s, advertising up to {adv or '?'} Mb/s, "
               f"link partner (router) advertises up to {partner or 'not reported'}"
               + (" Mb/s" if partner else ""))
    if F["carrier"] and speed:
        if speed <= 10:
            R.add("FAIL", "Link speed", f"{speed} Mb/s - almost certainly a damaged cable/connector")
            F["link_degraded"] = f"{speed} Mb/s"
        elif sup and speed < sup:
            if partner and partner > speed:
                R.add("WARN", "Link speed", f"{speed} Mb/s although both ends support {min(sup, partner)} Mb/s - "
                      "typical of a cable with a broken pair or a poor connector; try another cable")
                F["link_degraded"] = f"{speed} of {min(sup, partner)} Mb/s"
            elif partner:
                R.add("INFO", "Link speed", f"{speed} Mb/s - limited by the router port ({partner} Mb/s max)")
            else:
                R.add("WARN", "Link speed", f"{speed} Mb/s while the adapter supports {sup} Mb/s "
                      "(partner abilities unknown) - check cable and router port")
                F["link_degraded"] = f"{speed} of {sup} Mb/s"
        else:
            R.add("PASS", "Link speed", f"{speed} Mb/s")
        if duplex.lower().startswith("half"):
            R.add("FAIL", "Duplex", "HALF duplex - duplex mismatch causes heavy loss; re-enable auto-negotiation")
            F["half_duplex"] = True
        elif duplex.lower().startswith("full"):
            R.add("PASS", "Duplex", duplex)
        elif duplex:
            R.add("INFO", "Duplex", f"not reported by the {driver} driver ({duplex})")
        if et.get("Auto-negotiation", "").lower() == "off" and kind not in ("virtual", "wifi"):
            if driver in GENERIC_USB_NET:
                R.add("INFO", "Auto-negotiation", f"reported as off, but the generic {driver} driver cannot see the "
                      "PHY - not meaningful")
            else:
                R.add("WARN", "Auto-negotiation", "off - forced speed/duplex is a common cause of mismatches")

    up_c = sysread(base + "/carrier_up_count")
    down_c = sysread(base + "/carrier_down_count")
    changes = sysread(base + "/carrier_changes")
    if changes is not None:
        n = int(changes)
        F["carrier_changes"] = n
        if kind == "wifi":
            R.add("INFO", "Link flap history", f"{changes} carrier changes since the interface appeared "
                  f"(up {up_c}, down {down_c}) - Wi-Fi reconnects, roaming and suspend/resume all count")
        else:
            R.add("PASS" if n <= 2 else "WARN", "Link flap history", f"{changes} carrier changes since the adapter "
                  f"appeared (up {up_c}, down {down_c})" + (" - the link has been bouncing" if n > 2 else ""))
    rx0 = read_stats()["rx_packets"]
    if F["admin_up"]:
        secs = ARGS.link_watch
        R.progress(f"watching the link for {secs} s for flaps …")
        prev, trans, t_end = sysread(base + "/carrier"), 0, time.monotonic() + secs
        while time.monotonic() < t_end:
            cur = sysread(base + "/carrier")
            if cur != prev:
                trans += 1
                R.note(f"  {datetime.datetime.now():%H:%M:%S.%f}"[:-3] + f" carrier -> {cur}")
                prev = cur
            time.sleep(0.05)
        F["link_flaps_live"] = trans
        R.add("PASS" if trans == 0 else "FAIL", "Live link watch",
              f"{trans} carrier transitions during {secs} s"
              + ((" - Wi-Fi CONNECTION DROPPED" if kind == "wifi" else " - LINK IS FLAPPING") if trans else ""))
        F["carrier"] = has_carrier()
        link_reality(read_stats()["rx_packets"] - rx0, secs, et)

    st = read_stats()
    F["stats_start"] = st
    bad = {k: st[k] for k in SERIOUS_STATS if st.get(k)}
    rxp = max(st["rx_packets"], 1)
    R.add("INFO", "Traffic counters", f"rx {st['rx_packets']} pkts / {st['rx_bytes'] // 1048576} MiB, "
          f"tx {st['tx_packets']} pkts / {st['tx_bytes'] // 1048576} MiB, rx_dropped {st['rx_dropped']}")
    if bad:
        rate = 100.0 * sum(v for k, v in bad.items() if k.startswith("rx_")) / rxp
        R.add("WARN" if rate < 0.1 else "FAIL", "Error counters",
              ", ".join(f"{k}={v}" for k, v in bad.items()) + f" ({rate:.3f}% of rx) - " + ("radio interference or adapter" if kind == "wifi" else "cable, EMI or adapter"))
        F["phy_errors"] = True
    else:
        R.add("PASS", "Error counters", "no CRC/frame/collision/FIFO errors")
    if shutil.which("ethtool"):
        _, out, _ = run(["ethtool", "-S", IFACE])
        errs = [(k, int(v)) for k, v in re.findall(r"^\s*([\w.\-\[\]]+):\s*(\d+)\s*$", out, re.M)
                if int(v) and re.search(r"err|crc|drop|miss|fail|collis|align|symbol|runt|jabber|timeout", k, re.I)
                and "_reason_" not in k]   # cdc_ncm tx_reason_* = why a batch was sent, not errors
        if errs:
            R.add("INFO", "Driver statistics", ", ".join(f"{k}={v}" for k, v in errs[:12]))
        _, out, _ = run(["ethtool", "--show-eee", IFACE])
        m = re.search(r"EEE status:\s*(.*)", out)
        if m and "enabled" in m.group(1):
            R.add("INFO", "Energy-Efficient Ethernet", f"{m.group(1).strip()} - EEE causes drops with some "
                  f"router/adapter pairs; try: sudo ethtool --set-eee {IFACE} eee off")
    if ARGS.cable_test and link_in_use() and not ARGS.force:
        R.add("SKIP", "Cable test", f"{IFACE} has a working connection and the test would drop it (--force runs it anyway)")
    elif ARGS.cable_test and shutil.which("ethtool"):
        R.progress("running PHY cable test (the link drops for a few seconds) …")
        rc, out, err = run(["ethtool", "--cable-test", IFACE], timeout=30)
        if rc == 0:
            R.add("INFO", "Cable test", " | ".join(l.strip() for l in out.splitlines()
                                                    if "Pair" in l or "fault" in l.lower()) or out.strip())
        else:
            R.add("SKIP", "Cable test", f"not supported by this PHY ({(err or out).strip()[:80]})")
        time.sleep(3)
    kernel_log(driver, usb)


def poke_link():
    """Make the other side talk: IPv6 router solicitation, ARP for the router, DHCP DISCOVER if no router known."""
    mac = my_mac()
    if sysread(f"/proc/sys/net/ipv6/conf/{IFACE}/disable_ipv6") != "1":
        try:
            s = icmp6_sock()
            s.sendto(struct.pack("!BBHI", 133, 0, 0, 0) + bytes([1, 1]) + mac, ("ff02::2", 0, 0, IFINDEX))
            s.close()
        except OSError:
            pass
    gw = next((r.get("gateway") for r in ipj("route", "show", "default") if r.get("dev") == IFACE), None)
    mine = [a["local"] for l in ipj("addr", "show", "dev", IFACE) for a in l.get("addr_info", [])
            if a.get("family") == "inet"]
    if gw:
        try:
            s = packet_socket(ETH_P_ARP)
            s.send(arp_frame(mac, socket.inet_aton(mine[0]) if mine else bytes(4), socket.inet_aton(gw)))
            s.close()
        except OSError:
            pass
    elif not ARGS.no_dhcp_probe and not [a for a in mine if not a.startswith("169.254.")]:
        threading.Thread(target=lambda: dhcp4_exchange(mac, 1, timeout=2.5, settle=0.5), daemon=True).start()


ADV_BITS = {"10baseT/Half": 0x1, "10baseT/Full": 0x2, "100baseT/Half": 0x4, "100baseT/Full": 0x8,
            "1000baseT/Half": 0x10, "1000baseT/Full": 0x20, "2500baseT/Full": 0x800000000000,
            "5000baseT/Full": 0x1000000000000, "10000baseT/Full": 0x1000}


def downshift_test(et, wait=8):
    """Advertise only 10/100 for a few seconds: True = link comes up (gigabit pair fault), False = still no link,
    None = could not test. The original advertisement is restored afterwards."""
    orig = sum(ADV_BITS.get(m, 0) for m in et.get("Advertised link modes", "").split()) or 0x2f
    if run(["ethtool", "-s", IFACE, "advertise", "0x00f"])[0] != 0:
        return None
    R.progress(f"no link at gigabit - retrying with only 10/100 Mb/s advertised for {wait} s …")
    up, t_end = False, time.monotonic() + wait
    try:
        while time.monotonic() < t_end:
            if has_carrier():
                up = True
                break
            time.sleep(0.5)
    finally:
        run(["ethtool", "-s", IFACE, "advertise", hex(orig)])
    return up


def driver_rx_history(driver):
    """Earlier saved report in which this same adapter, on this same driver, did receive frames - proof that the
    driver can receive, so a silent link now is the far end. Returns the report's file name or None."""
    aid = F.get("adapter_id")
    for n, d in saved_reports():
        fa = d.get("facts", {})
        if fa.get("driver") != driver or fa.get("link_state") != "up":
            continue
        # match on USB id + MAC; older reports lack it, so fall back to the interface name (same port + USB config)
        # or to the MAC inside an 'enx<mac>' name
        if aid and fa.get("adapter_id"):
            same = fa["adapter_id"] == aid
        else:
            old = d.get("interface") or ""
            same = old == IFACE or (old.startswith("enx") and old[3:] == my_mac().hex())
        if same:
            return n
    return None


def usb_rx_blocks():
    """cdc_ncm counts the NTB blocks it gets over USB (ethtool -S rx_ntbs). Blocks arriving while no frames come out
    means the driver receives data but fails to unpack it - real evidence against the driver. None = not available."""
    if not shutil.which("ethtool"):
        return None
    _, out, _ = run(["ethtool", "-S", IFACE])
    m = re.search(r"^\s*rx_ntbs:\s*(\d+)", out, re.M)
    return int(m.group(1)) if m else None


def link_label():
    kind = F.get("iface_kind")
    return "Wi-Fi link status" if kind == "wifi" else "Ethernet link status" if kind in WIRED_KINDS else "Link status"


def link_reality(rx_delta, secs, et):
    """Is there a real connection - not just a carrier, but frames arriving from the other side?"""
    base = f"/sys/class/net/{IFACE}"
    if not F["carrier"]:
        oper = sysread(base + "/operstate")
        F["link_state"] = "no-link"
        partner = et.get("Link partner advertised link modes", "")
        # some drivers (e.g. ax88179_178a without link) echo our own advertisement as the "partner's": only trust
        # partner data that differs from what we advertise
        echo = set(partner.split()) == set(et.get("Advertised link modes", "").split())
        if echo and partner:
            R.note("ethtool's 'link partner' modes equal this adapter's own advertisement - the driver echoes them; "
                   "no real data from the far end")
        if partner and not echo and "not reported" not in partner.lower() and re.search(r"\d+base", partner):
            # auto-negotiation pulses got through both ways, so something answers - but the link never comes up
            F["link_state"] = "negotiated-no-link"
            top = max(mode_speeds(partner) or [0])
            R.add("FAIL", "Ethernet link status", f"NEGOTIATED BUT NO LINK - the far end answers auto-negotiation "
                  f"(advertises up to {top} Mb/s) but the link never comes up")
            res = downshift_test(et) if ROOT and top >= 1000 else None
            F["downshift_100"] = res
            if res is True:
                F["link_cause"] = "pair"
                R.add("FAIL", "100 Mb/s test", "the link comes up at 100 Mb/s but not at 1000 Mb/s - a broken wire "
                      "pair (4-5 or 7-8) in the cable or the port. Replace the cable / use another port")
            elif res is False:
                F["link_cause"] = "adapter"
                R.add("FAIL", "100 Mb/s test", "no link at 100 Mb/s either, although negotiation works on the same two "
                      "pairs - the cable is probably fine; the adapter (chip/driver) or the far port does not bring "
                      "the link up. Try the same cable in another adapter or the built-in Ethernet port")
            else:
                F["link_cause"] = "unknown"
                R.note("Causes: a broken wire pair (gigabit needs all 4 pairs, negotiation only 2), a bad port, or the "
                       "adapter's chip/driver. Run as root to let the tool retry at 100 Mb/s and tell them apart.")
            return
        if F.get("iface_kind") not in WIRED_KINDS:
            R.add("FAIL", link_label(), ("NOT CONNECTED - not associated with an access point"
                                         if F.get("iface_kind") == "wifi" else "NO LINK") + f" (operstate {oper})")
            return
        R.add("FAIL", "Ethernet link status", "NO LINK - no electrical signal from the other end: cable unplugged or "
              "broken, the device at the other end is off, or its port is dead/disabled"
              + (f" (operstate {oper}, ethtool 'Link detected: {et['Link detected']}')" if et.get("Link detected") else
                 f" (operstate {oper})"))
        return
    frames, senders, waited = rx_delta, None, secs
    if ROOT:
        # listen briefly while provoking answers, to see who is on the other side
        out = {}
        th = threading.Thread(target=lambda: out.update(st=passive_sniff(3)), daemon=True)
        th.start()
        time.sleep(0.3)
        poke_link()
        th.join(6)
        if out.get("st"):
            frames += out["st"]["frames"]
            senders = sorted(out["st"]["macs"])
            waited += 3
    partner = et.get("Link partner advertised link modes", "")
    neg = bool(partner) and "not reported" not in partner.lower()
    speed = F.get("link_speed")
    if frames > 0:
        F["link_state"] = "up"
        R.add("PASS", link_label(), f"REAL CONNECTION - carrier up{f' at {speed} Mb/s' if speed else ''} and "
              f"{frames} frames arrived from the other side in {waited} s"
              + (f" from {len(senders)} device(s): " + ", ".join(f"{m} {vendor(m)}".strip() for m in senders[:4])
                 + (" …" if len(senders) > 4 else "") if senders else "")
              + ("; the link partner auto-negotiates" if neg else ""))
    else:
        F["link_state"] = "carrier-only"
        wifi = F.get("iface_kind") == "wifi"
        if wifi:
            why = (": the access point isolates clients, authentication did not complete, or the AP is hung")
        elif F.get("generic_driver"):
            gd = F["generic_driver"]
            blocks = usb_rx_blocks() if gd == "cdc_ncm" else None
            F["usb_rx_blocks"] = blocks
            hist = driver_rx_history(gd)
            F["driver_rx_history"] = hist
            if blocks:
                F["driver_suspect"] = "proven"
                why = (f": the adapter delivers {blocks} USB data blocks but {gd} turns none of them into frames - "
                       "the generic driver is failing (try --fix-driver)")
            elif hist:
                why = (f": {gd} on this same adapter received frames before ({hist}), so the driver works - the far "
                       "end sends nothing: the device there is silent (e.g. a modem/router whose WAN is down and that "
                       "does not serve this port), hung, passive, or its port blocks traffic (802.1X / VLAN)")
            else:
                F["driver_suspect"] = "possible"
                why = (": the far end sends nothing - the device there is silent (modem/router with its WAN down, "
                       "unconnected switch, passive box), hung, or its port blocks traffic (802.1X / VLAN). "
                       f"The generic {gd} driver not receiving looks the same; --fix-driver rules it out")
        else:
            why = (": the far port blocks traffic (802.1X / port security / wrong VLAN), the device there is hung, "
                   "or it is a passive box (PoE injector, media converter without uplink)")
        R.add("FAIL" if ROOT else "WARN", link_label(),
              ("CARRIER ONLY - associated" if wifi else "CARRIER ONLY - the electrical link is up")
              + " but no frames arrive from the other side"
              + (" even after soliciting the router" if ROOT else " (not provoked - run as root to probe actively)")
              + why + ("; a link partner does negotiate" if neg and not wifi else ""))


def kernel_log(driver, usb):
    pats = [IFACE]
    if driver and driver != "?":
        pats.append(driver)
    if usb:
        pats.append(f"usb {usb['busid']}:")
    rc, out, _ = run(["journalctl", "-k", "-b", "--no-pager", "-o", "short-iso", "-n", "8000"], timeout=25)
    if rc != 0 or not out.strip():
        rc, out, _ = run(["dmesg", "-T"])
    if rc != 0 or not out.strip():
        R.add("SKIP", "Kernel log", "not readable (needs root or the adm group)")
        return
    # firewall log lines (UFW/netfilter "IN=... OUT=...") mention the interface but are not about it
    lines = [l for l in out.splitlines() if any(p in l for p in pats) and not re.search(r"\bIN=\S* OUT=", l)]
    downs = [l for l in lines if re.search(r"link (is )?down|carrier lost|link becomes not ready", l, re.I)]
    bad = [l for l in lines if re.search(r"tx timeout|watchdog|reset|disconnect|error|fail|over-?current|unable", l, re.I)]
    dad = [l for l in lines if re.search(r"duplicate address|DAD", l)]
    F["klog_link_downs"] = len(downs)
    F["klog_errors"] = len(bad)
    st = "WARN" if len(downs) > 3 or bad or dad else "PASS"
    R.add(st, "Kernel log (this boot)", f"{len(lines)} lines about the adapter, {len(downs)} link-down events, "
          f"{len(bad)} reset/error/disconnect lines" + (f", {len(dad)} IPv6 duplicate-address messages" if dad else ""))
    for l in (bad[-6:] + downs[-6:] + dad[-3:] if st == "WARN" else lines[-5:]):
        R.note("  " + l[:150])
    ups = [l for l in lines if re.search(r"link (is )?up|link becomes ready|carrier on", l, re.I)]
    if ups and F.get("carrier"):
        R.note(f"link last came up: {ups[-1].split()[0]}")


# --------------------------------------------------------------------------- L2 IPv4: DHCP + ARP

DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def dhcp4_exchange(chaddr, msgtype, broadcast=True, ciaddr=None, extra=b"", timeout=8.0, settle=2.0):
    """Send one DHCPv4 message from a raw socket and collect every matching reply
    (listening `settle` s after the first one, to catch a second DHCP server)."""
    mac = my_mac()
    s = packet_socket(ETH_P_IP)
    xid = random.getrandbits(32)
    ci = socket.inet_aton(ciaddr) if ciaddr else bytes(4)
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0,
                        ci, bytes(4), bytes(4), bytes(4), chaddr + bytes(10), bytes(64), bytes(128))
    opts = (b"\x63\x82\x53\x63" + bytes([53, 1, msgtype]) + bytes([61, 7, 1]) + chaddr + extra +
            bytes([55, 9, 1, 3, 6, 15, 26, 28, 51, 54, 119]) + b"\xff")
    payload = bootp + opts
    payload += bytes(max(0, 300 - len(payload)))
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), random.getrandbits(16), 0, 64, 17, 0,
                      ci, b"\xff" * 4)
    iph = iph[:10] + struct.pack("!H", checksum(iph)) + iph[12:]
    t0 = time.monotonic()
    replies = []
    try:
        s.send(b"\xff" * 6 + mac + struct.pack("!H", ETH_P_IP) + iph + udp)
        while True:
            left = timeout - (time.monotonic() - t0)
            if left <= 0:
                break
            if replies:
                left = min(left, replies[0]["ms"] / 1000 + settle - (time.monotonic() - t0))
                if left <= 0:
                    break
            r, _, _ = select.select([s], [], [], left)
            if not r:
                continue
            data = s.recv(2048)
            try:
                if len(data) < 14 + 20 + 8 + 240 or data[12:14] != b"\x08\x00":
                    continue
                ip = data[14:]
                ihl = (ip[0] & 0x0F) * 4
                if ip[9] != 17:
                    continue
                udph = ip[ihl:ihl + 8]
                if struct.unpack("!H", udph[0:2])[0] != 67:
                    continue
                bp = ip[ihl + 8:]
                if bp[0] != 2 or struct.unpack("!I", bp[4:8])[0] != xid or bp[236:240] != b"\x63\x82\x53\x63":
                    continue
                o, i = {}, 240
                while i < len(bp) - 1 and bp[i] != 255:
                    if bp[i] == 0:
                        i += 1
                        continue
                    code, ln = bp[i], bp[i + 1]
                    o[code] = bp[i + 2:i + 2 + ln]
                    i += 2 + ln
                ip4 = lambda b: [socket.inet_ntoa(b[j:j + 4]) for j in range(0, len(b) - 3, 4)]  # noqa: E731
                replies.append({
                    "ms": ms(t0), "type": DHCP_TYPES.get(o.get(53, b"\0")[0], str(o.get(53))),
                    "server": ip4(o[54])[0] if 54 in o else socket.inet_ntoa(ip[12:16]),
                    "src_ip": socket.inet_ntoa(ip[12:16]),
                    "src_mac": macstr(data[6:12]), "dst_mac": macstr(data[0:6]),
                    "yiaddr": socket.inet_ntoa(bp[16:20]),
                    "mask": ip4(o[1])[0] if 1 in o else None, "router": ip4(o[3]) if 3 in o else [],
                    "dns": ip4(o[6]) if 6 in o else [],
                    "lease": struct.unpack("!I", o[51])[0] if 51 in o and len(o[51]) == 4 else None,
                    "mtu": struct.unpack("!H", o[26])[0] if 26 in o and len(o[26]) == 2 else None,
                    "domain": o[15].decode(errors="replace") if 15 in o else None,
                    "message": o[56].decode(errors="replace") if 56 in o else None})
            except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                continue
    finally:
        s.close()
    return replies


def random_mac():
    return bytes([0x02]) + os.urandom(5)


def dhcp4_checks():
    """Standard DISCOVER plus special requests that probe the DHCP server's behaviour."""
    mac = my_mac()
    have_ip = F.get("ipv4") and not F.get("apipa")

    def report_inform(inf):
        if inf:
            a = inf[0]
            R.add("PASS", "DHCP INFORM", f"{a['type']} from {a['server']}: router {','.join(a['router']) or '-'}, dns "
                  f"{','.join(a['dns']) or '-'}" + (f", domain {a['domain']}" if a["domain"] else ""))
        else:
            R.add("INFO", "DHCP INFORM", "no answer (many home routers ignore DHCPINFORM - harmless)")

    if have_ip and not ARGS.active_dhcp:
        R.add("SKIP", "DHCP DISCOVER / REQUEST probes", f"this interface already has {F['ipv4']}: skipped to leave its "
              "lease alone (--active-dhcp runs them)")
        R.progress("DHCP INFORM (asks for settings only, involves no lease) …")
        report_inform(dhcp4_exchange(mac, 8, False, F["ipv4"], b"", 5.0))
        return
    R.progress("DHCP probes: standard DISCOVER (no REQUEST follows, so no lease is requested) …")
    std = dhcp4_exchange(mac, 1)
    R.progress("… then new-client DISCOVER, DISCOVER without broadcast flag, bogus REQUEST, INFORM …")
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        f_new = ex.submit(dhcp4_exchange, random_mac(), 1)
        f_uni = ex.submit(dhcp4_exchange, mac, 1, False)
        f_bog = ex.submit(dhcp4_exchange, random_mac(), 3, True, None, bytes([50, 4]) + socket.inet_aton("192.0.2.123"), 5.0)
        f_inf = ex.submit(dhcp4_exchange, mac, 8, False, F["ipv4"], b"", 5.0) if have_ip else None
        new, uni, bog = f_new.result(), f_uni.result(), f_bog.result()
        inf = f_inf.result() if f_inf else None
    F["dhcp_offers"] = len(std)
    F["dhcp_offer_list"] = std + new + uni
    servers = sorted({o["server"] for o in std + new})
    if not std:
        R.add("FAIL", "DHCP DISCOVER", "no DHCP server answered in 8 s - the router's DHCP is off, hung, "
              "or this port is not connected to a LAN port")
    else:
        o = std[0]
        R.add("PASS", "DHCP DISCOVER", f"{o['type']} from {o['server']} ({o['src_mac']} {vendor(o['src_mac'])}) in "
              f"{o['ms']:.0f} ms: ip {o['yiaddr']}/{o['mask']}, router {','.join(o['router']) or '-'}, "
              f"dns {','.join(o['dns']) or '-'}, lease {o['lease']} s" + (f", mtu {o['mtu']}" if o['mtu'] else "")
              + (f", domain {o['domain']}" if o['domain'] else ""))
        if o["ms"] > 2500:
            R.note("(a ~3 s delay is normal for servers that ping-check an address before offering it)")
        F["dhcp_dns"] = o["dns"]
        if not F.get("gateway") and o["router"]:
            F["gateway"] = o["router"][0]
            F["gateway_from_dhcp"] = True
        problems = []
        if F.get("gateway") and o["router"] and F["gateway"] not in o["router"]:
            problems.append(f"offers router {o['router'][0]} but this link uses {F['gateway']}")
        if F.get("ipv4_prefix") and o["mask"]:
            plen = ipaddress.ip_network(f"0.0.0.0/{o['mask']}").prefixlen
            if plen != ipaddress.ip_interface(F["ipv4_prefix"]).network.prefixlen:
                problems.append(f"offers /{plen} but the interface has {F['ipv4_prefix']}")
        if have_ip and o["yiaddr"] != F["ipv4"]:
            R.add("INFO", "DHCP address", f"router would hand out {o['yiaddr']} but the interface has {F['ipv4']} "
                  "(static config, or the lease was lost)")
        if o["lease"] is not None and o["lease"] < 600:
            problems.append(f"very short lease ({o['lease']} s) - frequent renewals; any DHCP hiccup drops clients")
        if o["mtu"] and o["mtu"] != 1500:
            problems.append(f"pushes MTU {o['mtu']}")
        if F.get("gateway") and o["server"] != F["gateway"]:
            R.add("INFO", "DHCP server", f"{o['server']} is not the gateway {F['gateway']} (separate DHCP server or a second router)")
        if not o["dns"]:
            problems.append("no DNS servers in the offer")
        for p in problems:
            R.add("WARN", "DHCP offer consistency", p)
        if not problems:
            R.add("PASS", "DHCP offer consistency", "router, mask, lease and options match the link configuration")
    if len(servers) > 1:
        F["dhcp_multi"] = servers
        R.add("WARN", "Multiple DHCP servers", ", ".join(servers) +
              " - two devices hand out addresses (double NAT / modem in router mode / rogue DHCP)")
    if new:
        R.add("PASS", "DHCP for a new device", f"a random new MAC is offered {new[0]['yiaddr']} - the address pool is not exhausted")
    elif std:
        F["dhcp_pool_issue"] = True
        R.add("WARN", "DHCP for a new device", "no offer for an unknown MAC although the computer gets one - address pool "
              "full or a MAC allow-list: new devices cannot join")
    else:
        R.add("FAIL", "DHCP for a new device", "no offer either")
    if bog:
        b = bog[0]
        if b["type"] == "NAK":
            R.add("PASS", "DHCP authority (bogus REQUEST)", f"NAK from {b['server']}" + (f" '{b['message']}'" if b["message"] else "")
                  + " - stale addresses from other networks are rejected at once")
        else:
            F["dhcp_bogus_ack"] = True
            R.add("WARN", "DHCP authority (bogus REQUEST)", f"server answered {b['type']} for 192.0.2.123 (outside its network) - misconfigured")
    elif std:
        R.add("INFO", "DHCP authority (bogus REQUEST)", "no NAK - server is non-authoritative; a device coming from "
              "another network waits ~1 min before getting an address")
    if inf is not None:
        report_inform(inf)
    if std:
        if uni:
            how = "as broadcast" if uni[0]["dst_mac"] == "ff:ff:ff:ff:ff:ff" else "as unicast"
            R.add("PASS", "DHCP without broadcast flag", f"{uni[0]['type']} delivered {how} - clients that ask for "
                  "unicast replies (Linux, Android) are served")
        else:
            F["dhcp_unicast_issue"] = True
            R.add("WARN", "DHCP without broadcast flag", "server answers only when the broadcast flag is set - "
                  "some devices may fail to get an address")


def arp_frame(mac, sip, tip, op=1):
    f = (b"\xff" * 6 + mac + struct.pack("!H", ETH_P_ARP) + struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) +
         mac + sip + bytes(6) + tip)
    return f + bytes(60 - len(f))


def arp_parse(data):
    if len(data) < 42 or data[12:14] != b"\x08\x06":
        return None
    a = data[14:42]
    return {"op": struct.unpack("!H", a[6:8])[0], "sha": macstr(a[8:14]), "spa": socket.inet_ntoa(a[14:18]),
            "tpa": socket.inet_ntoa(a[24:28]), "dst": macstr(data[0:6])}


def arp_probe(target_ip, src_ip, mac, count=5, interval=0.2, wait=1.0):
    s = packet_socket(ETH_P_ARP)
    frame = arp_frame(mac, socket.inet_aton(src_ip) if src_ip else bytes(4), socket.inet_aton(target_ip))
    replies, sent, last_sent = [], 0, 0.0
    next_send = time.monotonic()
    end = None
    try:
        while True:
            now = time.monotonic()
            if sent < count and now >= next_send:
                s.send(frame)
                last_sent, sent, next_send = now, sent + 1, now + interval
                if sent == count:
                    end = now + wait
            if end and now >= end:
                break
            tmo = (next_send - now) if sent < count else (end - now)
            r, _, _ = select.select([s], [], [], max(0.0, tmo))
            if not r:
                continue
            p = arp_parse(s.recv(128))
            if p and p["op"] == 2 and p["spa"] == target_ip:
                replies.append(((time.monotonic() - last_sent) * 1000, p["sha"]))
    finally:
        s.close()
    macs = {}
    for _, m in replies:
        macs[m] = macs.get(m, 0) + 1
    return {"sent": sent, "replies": len(replies), "macs": macs,
            "avg": mean([r for r, _ in replies]), "loss": max(0.0, 100.0 * (sent - max(macs.values() or [0])) / sent)}


_sysctl_restore = {}


def restore_sysctls():
    while _sysctl_restore:
        path, old = _sysctl_restore.popitem()
        try:
            with open(path, "w") as f:
                f.write(old)
        except OSError:
            pass


def arp_flux_guard():
    """Linux answers ARP for any local address on every interface ('ARP flux'). With Wi-Fi in the same
    subnet the router may map this interface's IP to the Wi-Fi MAC, so every reply to our probes goes to
    Wi-Fi and the cable looks dead. As root, pin ARP to the owning interface for the duration of the test."""
    if not F.get("ipv4_prefix") or F.get("apipa"):
        return
    net = ipaddress.ip_interface(F["ipv4_prefix"]).network
    others = dedupe([l.get("ifname") for l in ipj("addr") if l.get("ifname") not in (IFACE, "lo")
                     for a in l.get("addr_info", [])
                     if a.get("family") == "inet" and ipaddress.ip_address(a["local"]) in net])
    if not others:
        return
    F["arp_flux_ifaces"] = others

    def eff(key):
        return max(int(sysread(f"/proc/sys/net/ipv4/conf/{n}/{key}", "0") or 0) for n in ["all"] + others)

    ign, ann = eff("arp_ignore"), eff("arp_announce")
    if ign >= 1 and ann >= 2:
        R.add("PASS", "ARP flux", f"{', '.join(others)} shares the subnet {net}, but ARP is already pinned per "
              f"interface (arp_ignore={ign}, arp_announce={ann})")
        return
    if not ROOT:
        F["arp_flux_risk"] = True
        R.add("WARN", "ARP flux", f"{', '.join(others)} is in the same subnet {net} and answers ARP for {F['ipv4']} "
              f"too - the router may send this interface's replies there, so results can show false loss. "
              f"Disconnect {others[0]}, or run as root (the tool then pins ARP for the duration of the test)")
        return
    for key, val in (("arp_ignore", "1"), ("arp_announce", "2")):
        path = f"/proc/sys/net/ipv4/conf/all/{key}"
        old = sysread(path)
        if old is not None and int(old) < int(val):
            try:
                _sysctl_restore.setdefault(path, old)   # recorded first, so a signal cannot lose the old value
                with open(path, "w") as f:
                    f.write(val)
            except OSError as e:
                R.add("WARN", "ARP flux", f"cannot set {path}: {describe_exc(e)}")
                return
    atexit.register(restore_sysctls)
    mac, ip = my_mac(), socket.inet_aton(F["ipv4"])
    try:     # gratuitous ARP: make the router re-learn this interface's real MAC
        s = packet_socket(ETH_P_ARP)
        for _ in range(3):
            s.send(arp_frame(mac, ip, ip))
            time.sleep(0.6)
        s.close()
    except OSError:
        pass
    R.add("WARN", "ARP flux", f"{', '.join(others)} shares the subnet {net}; ARP is pinned to the owning interface "
          "for this run (net.ipv4.conf.all.arp_ignore=1, arp_announce=2, restored at exit) and the router was "
          f"re-told {IFACE}'s MAC by gratuitous ARP")


def test_datalink():
    R.section("L2", "L2  IPv4 DATA LINK  (DHCP, ARP)")
    arp_flux_guard()
    mac = my_mac()
    mtu = int(sysread(f"/sys/class/net/{IFACE}/mtu", "0") or 0)
    F["mtu"] = mtu
    R.add("INFO", "MAC address", macstr(mac) + (" (locally administered / randomized)" if mac[0] & 2 else "")
          + (f" {vendor(macstr(mac))}" if not mac[0] & 2 else ""))
    normal = mtu == 1500 or F.get("iface_kind") not in WIRED_KINDS + ("wifi",)
    R.add("PASS" if normal else "WARN", "Interface MTU", f"{mtu}" + ("" if normal else " (expected 1500 on Ethernet)"))
    if not ROOT or ARGS.no_dhcp_probe:
        R.add("SKIP", "DHCP probes", "needs root" if not ROOT else "disabled by --no-dhcp-probe")
    else:
        try:
            dhcp4_checks()
        except OSError as e:
            R.add("SKIP", "DHCP probes", describe_exc(e))

    gw = F.get("gateway")
    if not gw:
        R.add("FAIL", "ARP to router", "no gateway known (no default route on this interface and no DHCP offer)")
        F["gw_arp"] = None
        return
    if not ROOT:
        R.add("SKIP", "ARP to router", "needs root")
    else:
        try:
            a = arp_probe(gw, F.get("ipv4"), mac)
        except OSError as e:
            a = None
            R.add("SKIP", "ARP to router", describe_exc(e))
        if a:
            F["gw_arp"] = a["replies"] > 0
            F["gw_mac"] = list(a["macs"])
            if not a["replies"]:
                R.add("FAIL", "ARP to router", f"{gw} did not answer {a['sent']} ARP requests - the router is not "
                      "on this network segment (wrong port, dead switch/port, VLAN) or it is hung")
            else:
                R.add("PASS" if a["loss"] == 0 else "WARN", "ARP to router",
                      f"{gw} is-at {', '.join(f'{m} {vendor(m)}'.strip() for m in a['macs'])}  "
                      f"{a['replies']}/{a['sent']} replies, avg {fmt_ms(a['avg'])} ms")
                if len(a["macs"]) > 1:
                    F["ip_conflict"] = True
                    R.add("FAIL", "IP conflict", f"{len(a['macs'])} devices answer for {gw}: {a['macs']}")
            if F.get("ipv4") and not F.get("apipa"):
                try:
                    d = arp_probe(F["ipv4"], None, mac, count=3, wait=0.8)
                    others = [m for m in d["macs"] if m != macstr(mac)]
                    if others:
                        F["ip_conflict"] = True
                        R.add("FAIL", "Duplicate address", f"another device ({', '.join(others)}) also uses {F['ipv4']}")
                    else:
                        R.add("PASS", "Duplicate address check", f"nobody else answers for {F['ipv4']}")
                except OSError:
                    pass
    neigh = [n for n in ipj("neigh", "show", "dev", IFACE) if n.get("dst") == gw]
    if neigh:
        n = neigh[0]
        R.add("INFO", "Kernel neighbor entry", f"{gw} {n.get('lladdr', '-')} state={','.join(n.get('state', []))}")


# --------------------------------------------------------------------------- L2 IPv6: NDP, RA, DHCPv6

def icmp6_sock():
    s = bsock(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)   # NDP requires hop limit 255
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, IFINDEX)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    return s


def solicited_node(addr):
    b = socket.inet_pton(socket.AF_INET6, addr.split("%")[0])
    return f"ff02::1:ff{b[13]:02x}:{b[14]:02x}{b[15]:02x}"


def nd_options(b):
    out, i = [], 0
    while i + 2 <= len(b):
        t, ln = b[i], b[i + 1] * 8
        if ln == 0:
            break
        out.append((t, b[i:i + ln]))
        i += ln
    return out


def parse_ra(data, src):
    flags = data[5]
    ra = {"src": src, "hop_limit": data[4], "M": bool(flags & 0x80), "O": bool(flags & 0x40),
          "prf": {0: "medium", 1: "high", 3: "low", 2: "reserved"}[(flags >> 3) & 3],
          "lifetime": struct.unpack("!H", data[6:8])[0], "reachable": struct.unpack("!I", data[8:12])[0],
          "mac": None, "prefixes": [], "mtu": None, "rdnss": [], "dnssl": [], "routes": []}
    for t, o in nd_options(data[16:]):
        if t == 1:
            ra["mac"] = macstr(o[2:8])
        elif t == 3 and len(o) >= 32:
            pfx = socket.inet_ntop(socket.AF_INET6, o[16:32])
            ra["prefixes"].append({"prefix": f"{pfx}/{o[2]}", "plen": o[2], "L": bool(o[3] & 0x80), "A": bool(o[3] & 0x40),
                                   "valid": struct.unpack("!I", o[4:8])[0], "preferred": struct.unpack("!I", o[8:12])[0]})
        elif t == 5:
            ra["mtu"] = struct.unpack("!I", o[4:8])[0]
        elif t == 25:
            ra["rdnss"] += [socket.inet_ntop(socket.AF_INET6, o[j:j + 16]) for j in range(8, len(o) - 15, 16)]
        elif t == 31:
            ra["dnssl"] += dns_names_plain(o[8:])
        elif t == 24:
            ra["routes"].append(f"{o[2]}-bit route, lifetime {struct.unpack('!I', o[4:8])[0]} s")
    return ra


def ndp_rs(wait=3.0):
    """Router Solicitation -> collect Router Advertisements from every router on the link."""
    mac = my_mac()
    s = icmp6_sock()
    pkt = struct.pack("!BBHI", 133, 0, 0, 0) + bytes([1, 1]) + mac
    ras = {}
    t0 = time.monotonic()
    resent = False
    try:
        s.sendto(pkt, ("ff02::2", 0, 0, IFINDEX))
        while time.monotonic() - t0 < wait:
            if not resent and time.monotonic() - t0 > 1.2:
                s.sendto(pkt, ("ff02::2", 0, 0, IFINDEX))
                resent = True
            r, _, _ = select.select([s], [], [], 0.2)
            if not r:
                continue
            data, addr = s.recvfrom(4096)
            try:
                if data and data[0] == 134 and len(data) >= 16:
                    src = norm6(addr[0])
                    ra = parse_ra(data, src)
                    ra["ms"] = ms(t0)
                    ras[src] = ra
            except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                continue
    finally:
        s.close()
    return list(ras.values())


def ndp_ns(targets, rounds=1, interval=0.3, wait=1.0):
    """Neighbor Solicitation (IPv6 'ARP') to each target; returns {target: {...}}."""
    mac = my_mac()
    s = icmp6_sock()
    res = {norm6(t): {"sent": 0, "replies": 0, "macs": {}, "router": False, "rtts": []} for t in targets}
    sent_at = {}
    try:
        for rnd in range(rounds):
            for t in res:
                pkt = struct.pack("!BBHI", 135, 0, 0, 0) + socket.inet_pton(socket.AF_INET6, t) + bytes([1, 1]) + mac
                try:
                    s.sendto(pkt, (solicited_node(t), 0, 0, IFINDEX))
                except OSError:
                    continue
                res[t]["sent"] += 1
                sent_at[t] = time.monotonic()
            end = time.monotonic() + (wait if rnd == rounds - 1 else interval)
            while time.monotonic() < end:
                r, _, _ = select.select([s], [], [], max(0.0, end - time.monotonic()))
                if not r:
                    continue
                data, _ = s.recvfrom(2048)
                try:
                    if not data or data[0] != 136 or len(data) < 24:
                        continue
                    tgt = socket.inet_ntop(socket.AF_INET6, data[8:24])
                    if tgt not in res:
                        continue
                    m = next((macstr(o[2:8]) for t, o in nd_options(data[24:]) if t == 2), None) or "?"
                    e = res[tgt]
                    e["replies"] += 1
                    e["macs"][m] = e["macs"].get(m, 0) + 1
                    e["router"] = e["router"] or bool(data[4] & 0x80)
                    e["rtts"].append((time.monotonic() - sent_at.get(tgt, time.monotonic())) * 1000)
                except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                    continue
    finally:
        s.close()
    return res


DHCP6_STATUS = {0: "Success", 1: "UnspecFail", 2: "NoAddrsAvail", 3: "NoBinding", 4: "NotOnLink", 5: "UseMulticast",
                6: "NoPrefixAvail"}


def d6opts(b):
    out, i = [], 0
    while i + 4 <= len(b):
        code, ln = struct.unpack("!HH", b[i:i + 4])
        out.append((code, b[i + 4:i + 4 + ln]))
        i += 4 + ln
    return out


def dhcp6_exchange(msg_type, wait=3.0):
    """SOLICIT (1) or INFORMATION-REQUEST (11) to all DHCPv6 servers; replies are sniffed at L2
    because NetworkManager's own DHCPv6 client usually owns UDP port 546."""
    mac = my_mac()
    sn = packet_socket(ETH_P_IPV6)
    s = bsock(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, IFINDEX)
    xid = os.urandom(3)

    def o(code, val):
        return struct.pack("!HH", code, len(val)) + val

    opts = o(1, struct.pack("!HH", 3, 1) + mac) + o(8, b"\0\0") + o(6, struct.pack("!HH", 23, 24))
    if msg_type == 1:
        opts += o(3, mac[-4:] + bytes(8))
    out = []
    t0 = time.monotonic()
    try:
        s.sendto(bytes([msg_type]) + xid + opts, ("ff02::1:2", 547, 0, IFINDEX))
        while time.monotonic() - t0 < wait:
            r, _, _ = select.select([sn], [], [], max(0.0, wait - (time.monotonic() - t0)))
            if not r:
                continue
            data = sn.recv(4096)
            try:
                if data[12:14] != b"\x86\xdd" or len(data) < 14 + 48 + 4:
                    continue
                ip6 = data[14:]
                if ip6[6] != 17 or struct.unpack("!H", ip6[40:42])[0] != 547:
                    continue
                p = ip6[48:]
                if p[0] not in (2, 7) or p[1:4] != xid:
                    continue
                r6 = {"type": "ADVERTISE" if p[0] == 2 else "REPLY", "server": socket.inet_ntop(socket.AF_INET6, ip6[8:24]),
                      "src_mac": macstr(data[6:12]), "ms": ms(t0), "dns": [], "domains": [], "addrs": [], "status": None,
                      "ia_status": None, "pref": None}
                for code, v in d6opts(p[4:]):
                    if code == 23:
                        r6["dns"] = [socket.inet_ntop(socket.AF_INET6, v[j:j + 16]) for j in range(0, len(v) - 15, 16)]
                    elif code == 24:
                        r6["domains"] = dns_names_plain(v)
                    elif code == 7 and v:
                        r6["pref"] = v[0]
                    elif code == 13 and len(v) >= 2:
                        r6["status"] = (DHCP6_STATUS.get(struct.unpack("!H", v[:2])[0], "?"), v[2:].decode(errors="replace"))
                    elif code == 3 and len(v) >= 12:
                        for c2, v2 in d6opts(v[12:]):
                            if c2 == 5 and len(v2) >= 24:
                                pl, vl = struct.unpack("!II", v2[16:24])
                                r6["addrs"].append((socket.inet_ntop(socket.AF_INET6, v2[:16]), pl, vl))
                            elif c2 == 13 and len(v2) >= 2:
                                r6["ia_status"] = (DHCP6_STATUS.get(struct.unpack("!H", v2[:2])[0], "?"),
                                                   v2[2:].decode(errors="replace"))
                out.append(r6)
            except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                continue
    finally:
        s.close()
        sn.close()
    return out


def test_datalink6():
    R.section("L2-v6", "L2  IPv6 LINK  (router advertisements, NDP, DHCPv6, duplicate addresses)")
    if sysread(f"/proc/sys/net/ipv6/conf/{IFACE}/disable_ipv6") == "1":
        R.add("INFO", "IPv6", f"disabled on {IFACE} (net.ipv6.conf.{IFACE}.disable_ipv6=1)")
        F["v6"] = "disabled"
        return
    F["v6"] = "enabled"
    if not F.get("v6_ll"):
        R.add("WARN", "Link-local address", "none yet - IPv6 has not started on this interface")
    else:
        R.add("PASS", "Link-local address", ", ".join(F["v6_ll"]))
    for a in F.get("v6_addr_info", []):
        if a.get("scope") != "global":
            continue
        flags = [k for k in ("temporary", "mngtmpaddr", "dynamic", "deprecated", "tentative", "dadfailed", "noprefixroute")
                 if a.get(k)]
        pl = a.get("preferred_life_time")
        R.note(f"  {a['local']}/{a.get('prefixlen')}  {addr_class(a['local'])}  {' '.join(flags)}"
               + (f"  preferred {pl} s" if isinstance(pl, int) else ""))
    if F.get("v6_dadfailed"):
        R.add("FAIL", "Duplicate address detection", f"kernel DAD failed for {', '.join(F['v6_dadfailed'])} - "
              "another device uses the same IPv6 address")
    if F.get("v6_deprecated_addrs"):
        R.add("INFO", "Deprecated addresses", f"{len(F['v6_deprecated_addrs'])} global address(es) are deprecated - "
              "the router got a new prefix from the ISP (WAN reconnect); many of these hint at frequent WAN drops")
    if not ROOT:
        R.add("SKIP", "Router solicitation / NDP / DHCPv6", "needs root")
        if F.get("gateway6"):
            R.add("INFO", "IPv6 default route", f"via {F['gateway6']}")
        return

    R.progress("Router Solicitation, collecting Router Advertisements (3 s) …")
    try:
        ras = ndp_rs()
    except OSError as e:
        R.add("SKIP", "Router Advertisements", describe_exc(e))
        return
    F["v6_ras"] = ras
    if not ras:
        if F.get("v6_global_addrs") or F.get("v6_ula_addrs"):
            R.add("WARN", "Router Advertisements", "no router answered the solicitation although addresses exist "
                  "(static IPv6 config, or the router stopped sending RAs)")
        else:
            R.add("INFO", "Router Advertisements", "no answer - but nothing at all is received on this link, so this "
                  "says nothing about IPv6" if F.get("link_state") == "carrier-only" else
                  "no IPv6 router on this link - the router does not offer IPv6")
            F["v6_router_absent"] = True
    adv_global = []
    for ra in ras:
        pfx = ", ".join(f"{p['prefix']}[{'A' if p['A'] else '-'}{'L' if p['L'] else '-'} "
                        f"pref {p['preferred']} s]" for p in ra["prefixes"]) or "none"
        R.add("PASS" if ra["lifetime"] else "WARN", f"RA from {ra['src']}",
              f"{ra['mac'] or '?'} {vendor(ra['mac']) if ra['mac'] else ''} | default-router lifetime {ra['lifetime']} s, "
              f"M={int(ra['M'])} O={int(ra['O'])}, preference {ra['prf']}, hop limit {ra['hop_limit']}"
              + (f", MTU {ra['mtu']}" if ra["mtu"] else ""))
        R.note(f"prefixes: {pfx}")
        R.note(f"RDNSS: {', '.join(ra['rdnss']) or '-'}   DNSSL: {', '.join(ra['dnssl']) or '-'}"
               + (f"   routes: {'; '.join(ra['routes'])}" if ra["routes"] else ""))
        if ra["lifetime"] == 0:
            F["v6_ra_lifetime0"] = True
            R.add("WARN", "RA router lifetime 0", f"{ra['src']} does NOT offer itself as default gateway - "
                  "typically its IPv6 uplink (WAN) is down or not provided")
        for p in ra["prefixes"]:
            cls = addr_class(p["prefix"].split("/")[0])
            if p["A"] and p["plen"] != 64:
                R.add("WARN", "RA prefix length", f"{p['prefix']} has the autoconf flag but is not /64 - SLAAC will not work")
            if p["preferred"] == 0 and p["valid"] > 0:
                F["v6_deprecated"] = True
                R.add("WARN", "Deprecated prefix", f"{p['prefix']} is being withdrawn (preferred lifetime 0)")
            if cls == "public" and p["valid"] > 0:
                adv_global.append(p)
        if ra["mtu"] and ra["mtu"] < 1280:
            R.add("FAIL", "RA MTU", f"{ra['mtu']} is below the IPv6 minimum of 1280")
    if len(ras) > 1:
        F["v6_ra_multi"] = [r["src"] for r in ras]
        R.add("WARN", "Multiple IPv6 routers", f"{len(ras)} routers advertise ({', '.join(r['mac'] or r['src'] for r in ras)}) - "
              "second router or rogue RA; clients may pick a dead one")
    if ras and not adv_global:
        F["v6_no_global_prefix"] = True
        R.add("WARN", "Global IPv6 prefix", "the router only advertises ULA/no prefixes - it has no IPv6 from the ISP "
              "(IPv6 WAN down or not provided)")
    for p in adv_global:
        net = ipaddress.ip_network(p["prefix"], strict=False)
        if p["A"] and p["preferred"] > 0 and not any(ipaddress.ip_address(a) in net for a in F.get("v6_all_addrs", [])):
            F["v6_slaac_fail"] = p["prefix"]
            R.add("FAIL", "SLAAC", f"prefix {p['prefix']} is advertised but this interface has no address in it")
    F["v6_ra_dns"] = dedupe([norm6(d) for ra in ras for d in ra["rdnss"]])
    F["v6_M"] = any(r["M"] for r in ras)
    F["v6_O"] = any(r["O"] for r in ras)
    if not F.get("gateway6"):
        live = [r for r in ras if r["lifetime"]]
        if live:
            F["gateway6"] = live[0]["src"]
            R.add("WARN", "IPv6 default route", f"none installed on {IFACE} although {live[0]['src']} advertises one - "
                  "NetworkManager/kernel ignores RAs (accept_ra / IPv6 method 'ignore'?)")
            F["v6_route_missing"] = True

    gw6 = F.get("gateway6")
    if gw6:
        res = ndp_ns([gw6], rounds=3)
        e = res[norm6(gw6)]
        F["v6_gw_ndp"] = e["replies"] > 0
        if e["replies"]:
            R.add("PASS" if e["replies"] >= e["sent"] else "WARN", "NDP to IPv6 router",
                  f"{gw6} is-at {', '.join(e['macs'])}  {e['replies']}/{e['sent']} replies, avg {fmt_ms(mean(e['rtts']))} ms"
                  + ("" if e["router"] else " (NA without router flag)"))
            if F.get("gw_mac") and not set(e["macs"]) & set(F["gw_mac"]):
                R.add("INFO", "Routers", f"the IPv6 router ({', '.join(e['macs'])}) is a different device than the "
                      f"IPv4 gateway ({', '.join(F['gw_mac'])})")
        else:
            R.add("FAIL", "NDP to IPv6 router", f"{gw6} does not answer neighbor solicitations")

    if ARGS.no_dhcp_probe:
        R.add("SKIP", "DHCPv6", "disabled by --no-dhcp-probe")
    else:
        skip_solicit = bool(F.get("v6_global_addrs")) and not ARGS.active_dhcp
        if skip_solicit:
            R.add("SKIP", "DHCPv6 SOLICIT", "this interface already has a global IPv6 address: skipped to leave it "
                  "alone (--active-dhcp runs it)")
        R.progress("DHCPv6 INFORMATION-REQUEST (3 s) …" if skip_solicit else "DHCPv6 SOLICIT and INFORMATION-REQUEST (3 s each) …")
        try:
            with cf.ThreadPoolExecutor(max_workers=2) as ex:
                fs, fi = None if skip_solicit else ex.submit(dhcp6_exchange, 1), ex.submit(dhcp6_exchange, 11)
                sol, inf = fs.result() if fs else [], fi.result()
        except OSError as e:
            sol, inf = None, None
            R.add("SKIP", "DHCPv6", describe_exc(e))
        if sol is not None:
            F["v6_dhcp_servers"] = dedupe([r["server"] for r in sol + inf])
            for r in sol:
                got = ", ".join(a for a, _, _ in r["addrs"]) or (r["ia_status"][0] if r["ia_status"] else "no address")
                R.add("PASS", "DHCPv6 SOLICIT", f"{r['type']} from {r['server']} ({r['src_mac']}) in {r['ms']:.0f} ms: "
                      f"address {got}, dns {', '.join(r['dns']) or '-'}" + (f", pref {r['pref']}" if r["pref"] is not None else ""))
            if not sol and not skip_solicit:
                if F.get("v6_M"):
                    F["v6_dhcp6_missing"] = True
                    R.add("FAIL", "DHCPv6 SOLICIT", "the router sets the M flag (get addresses via DHCPv6) but no DHCPv6 server answers")
                else:
                    R.add("INFO", "DHCPv6 SOLICIT", "no stateful DHCPv6 server - normal for SLAAC-only networks")
            for r in inf:
                R.add("PASS", "DHCPv6 INFORMATION-REQUEST", f"REPLY from {r['server']}: dns {', '.join(r['dns']) or '-'}"
                      + (f", domains {', '.join(r['domains'])}" if r["domains"] else ""))
            if not inf:
                st = "WARN" if F.get("v6_O") and not F.get("v6_ra_dns") else "INFO"
                R.add(st, "DHCPv6 INFORMATION-REQUEST", "no answer" + (" although the O flag asks clients to use it "
                      "and no RDNSS is advertised: no IPv6 DNS config" if st == "WARN" else " (DNS comes from RA/IPv4 instead)"))
            if len(F["v6_dhcp_servers"]) > 1:
                F["v6_dhcp_multi"] = True
                R.add("WARN", "Multiple DHCPv6 servers", ", ".join(F["v6_dhcp_servers"]))
            F["v6_dhcp_dns"] = dedupe([norm6(d) for r in sol + inf for d in r["dns"]])

    mine = F.get("v6_global_addrs", []) + F.get("v6_ula_addrs", []) + F.get("v6_ll", [])
    if mine:
        res = ndp_ns(mine, rounds=1, wait=1.0)
        own = macstr(my_mac())
        dups = {t: [m for m in e["macs"] if m != own] for t, e in res.items()}
        dups = {t: m for t, m in dups.items() if m}
        if dups:
            F["v6_dup"] = dups
            for t, m in dups.items():
                R.add("FAIL", "Duplicate IPv6 address", f"{t} is also used by {', '.join(m)}")
        else:
            R.add("PASS", "Duplicate IPv6 address check", f"nobody else answers for this interface's {len(mine)} address(es)")


# --------------------------------------------------------------------------- LAN discovery

def passive_sniff(secs):
    s = packet_socket(ETH_P_ALL)
    own = my_mac()
    st = {"frames": 0, "bcast": 0, "mcast": 0, "flood": 0, "types": {}, "macs": {}, "lldp": {}, "stp": set(),
          "cdp": set(), "vlan": set(), "dhcp_servers": {}, "dhcp_clients": set(), "ra": {}, "dhcp6_servers": set(),
          "mdns": set(), "ssdp": set(), "llmnr": set(), "netbios": set(), "arp_req": 0, "garp": set(), "pppoe": set(),
          "malformed": 0, "hostnames": {}}
    end = time.monotonic() + secs
    try:
        while time.monotonic() < end:
            r, _, _ = select.select([s], [], [], max(0.0, end - time.monotonic()))
            if not r:
                continue
            data, addr = s.recvfrom(65535)
            try:
                if addr[2] == socket.PACKET_OUTGOING or len(data) < 14:
                    continue
                dst, src = data[0:6], macstr(data[6:12])
                et, off = struct.unpack("!H", data[12:14])[0], 14
                if et == 0x8100 and len(data) >= 18:
                    st["vlan"].add(struct.unpack("!H", data[14:16])[0] & 0xFFF)
                    et, off = struct.unpack("!H", data[16:18])[0], 18
                st["frames"] += 1
                if dst == b"\xff" * 6:
                    st["bcast"] += 1
                elif dst[0] & 1:
                    st["mcast"] += 1
                elif dst != own:
                    st["flood"] += 1
                st["macs"][src] = st["macs"].get(src, 0) + 1
                name = ETHERTYPES.get(et, "802.3/LLC" if et < 0x0600 else f"0x{et:04x}")
                st["types"][name] = st["types"].get(name, 0) + 1
                p = data[off:]
                if et < 0x0600:
                    if dst[:6] == b"\x01\x80\xc2\x00\x00\x00":
                        st["stp"].add(src)
                    elif dst[:6] == b"\x01\x00\x0c\xcc\xcc\xcc":
                        st["cdp"].add(src)
                elif et == 0x88CC:
                    tl, i = {}, 0
                    while i + 2 <= len(p):
                        hdr = struct.unpack("!H", p[i:i + 2])[0]
                        t, ln = hdr >> 9, hdr & 0x1FF
                        v = p[i + 2:i + 2 + ln]
                        if t == 0:
                            break
                        if t in (1, 2):
                            tl[{1: "chassis", 2: "port"}[t]] = (macstr(v[1:7]) if len(v) == 7 and v[0] in (3, 4) and t == 1
                                                               else v[1:].decode(errors="replace"))
                        elif t in (4, 5, 6):
                            tl[{4: "port_desc", 5: "system", 6: "description"}[t]] = v.decode(errors="replace")[:80]
                        i += 2 + ln
                    st["lldp"][src] = tl
                elif et in (0x8863, 0x8864):
                    st["pppoe"].add(src)
                elif et == 0x0806:
                    a = arp_parse(data[:12] + data[16:] if off == 18 else data)
                    if a and a["op"] == 1:
                        st["arp_req"] += 1
                        if a["spa"] == a["tpa"]:
                            st["garp"].add((src, a["spa"]))
                elif et == 0x0800 and len(p) >= 28 and p[9] == 17:
                    ihl = (p[0] & 0x0F) * 4
                    sport, dport = struct.unpack("!HH", p[ihl:ihl + 4])
                    sip = socket.inet_ntoa(p[12:16])
                    if sport == 67 and dport == 68:
                        st["dhcp_servers"][sip] = src
                    elif dport == 67:
                        st["dhcp_clients"].add(src)
                        bp = p[ihl + 8:]
                        if len(bp) > 240 and bp[236:240] == b"\x63\x82\x53\x63":
                            i = 240
                            while i + 1 < len(bp) and bp[i] != 255:
                                if bp[i] == 0:
                                    i += 1
                                    continue
                                if bp[i] == 12:       # client hostname
                                    st["hostnames"][src] = bp[i + 2:i + 2 + bp[i + 1]].decode(errors="replace")
                                i += 2 + bp[i + 1]
                    elif 5353 in (sport, dport):
                        st["mdns"].add(sip)
                    elif dport == 1900 or sport == 1900:
                        st["ssdp"].add(sip)
                    elif dport == 5355:
                        st["llmnr"].add(sip)
                    elif dport in (137, 138):
                        st["netbios"].add(sip)
                elif et == 0x86DD and len(p) >= 48:
                    nh, sip = p[6], socket.inet_ntop(socket.AF_INET6, p[8:24])
                    if nh == 58 and p[40] == 134:
                        st["ra"][sip] = src
                    elif nh == 17:
                        sport, dport = struct.unpack("!HH", p[40:44])
                        if sport == 547:
                            st["dhcp6_servers"].add(sip)
                        elif 5353 in (sport, dport):
                            st["mdns"].add(sip)
            except (IndexError, struct.error, ValueError, UnicodeDecodeError):  # malformed packet: skip it
                st["malformed"] += 1
                continue
    finally:
        s.close()
    return st


def test_discovery():
    R.section("DISC", "LAN DISCOVERY  (what can be seen on the network)")
    if not ROOT or ARGS.no_scan:
        R.add("SKIP", "Discovery", "needs root" if not ROOT else "disabled by --no-scan")
        neigh = [n for n in ipj("neigh", "show", "dev", IFACE) if n.get("lladdr")]
        if neigh:
            R.note("kernel neighbor table instead:")
            for n in neigh:
                R.note(f"  {n['dst']:<28} {n['lladdr']}  {vendor(n['lladdr'])[:30]:<30} {','.join(n.get('state', []))}")
        return
    hosts = {}   # mac -> {"v4": set, "v6": set, "roles": set}

    def host(mac):
        return hosts.setdefault(mac, {"v4": set(), "v6": set(), "roles": set()})

    secs = ARGS.passive
    R.progress(f"listening passively for {secs} s …")
    st = passive_sniff(secs)
    F["sniff"] = {k: (sorted(v) if isinstance(v, set) else v) for k, v in st.items() if k != "macs"}
    bps, mps, fps = st["bcast"] / secs, st["mcast"] / secs, st["flood"] / secs
    R.add("INFO", "Traffic seen", f"{st['frames']} frames from {len(st['macs'])} MACs in {secs} s: broadcast {bps:.1f}/s, "
          f"multicast {mps:.1f}/s, unicast for others {fps:.1f}/s | " + ", ".join(
              f"{k} {v}" for k, v in sorted(st["types"].items(), key=lambda x: -x[1])))
    if st["malformed"]:
        R.add("INFO", "Malformed frames", f"{st['malformed']} frames could not be parsed and were skipped "
              "(a device on the LAN sends broken packets)")
    if bps > 500:
        F["bcast_storm"] = "FAIL"
        R.add("FAIL", "Broadcast storm", f"{bps:.0f} broadcasts/s - a switching loop (cable plugged in twice, powerline/mesh "
              "loop) is flooding the LAN")
    elif bps > 100:
        F["bcast_storm"] = "WARN"
        R.add("WARN", "Broadcast level", f"{bps:.0f} broadcasts/s is high for a home LAN (loop or a misbehaving device)")
    else:
        R.add("PASS", "Broadcast level", f"{bps:.1f}/s - no storm")
    if fps > 50:
        R.add("WARN", "Unicast flooding", f"{fps:.0f} frames/s meant for other devices reach this port - a hub, or a "
              "switch whose MAC table is overflowing")
    F["eapol_seen"] = st["types"].get("802.1X", 0)
    for mac, tl in st["lldp"].items():
        R.add("INFO", "LLDP neighbor", f"{tl.get('system', '?')} port {tl.get('port', '?')} "
              f"({tl.get('port_desc', '')}) chassis {tl.get('chassis', '?')} - {tl.get('description', '')}")
        host(mac)["roles"].add("LLDP switch/router")
    if st["stp"]:
        R.add("INFO", "Spanning tree", f"STP BPDUs from {', '.join(st['stp'])} - a managed switch/bridge is on the path")
    if st["cdp"]:
        R.add("INFO", "CDP", f"Cisco discovery from {', '.join(st['cdp'])}")
    if st["vlan"]:
        R.add("INFO", "VLAN tags", f"tagged frames for VLAN(s) {sorted(st['vlan'])} reach this port")
    if st["pppoe"]:
        R.add("WARN", "PPPoE on the LAN", f"PPPoE frames from {', '.join(st['pppoe'])} - a WAN/modem connection is "
              "bridged into the LAN (cable in the wrong port?)")
    for ip, mac in st["dhcp_servers"].items():
        host(mac)["roles"].add("DHCP server")
        host(mac)["v4"].add(ip)
    if len(st["dhcp_servers"]) > 1:
        F["dhcp_multi"] = sorted(st["dhcp_servers"])
        R.add("WARN", "DHCP servers (passive)", f"replies from several servers: {', '.join(st['dhcp_servers'])}")
    for ip, mac in st["ra"].items():
        host(mac)["roles"].add("IPv6 router")
        host(mac)["v6"].add(ip)
    if st["garp"]:
        R.add("INFO", "Gratuitous ARP", ", ".join(f"{ip} ({m})" for m, ip in sorted(st["garp"])[:8]))
    R.note(f"mDNS speakers {len(st['mdns'])}, SSDP/UPnP {len(st['ssdp'])}, LLMNR {len(st['llmnr'])}, "
           f"NetBIOS {len(st['netbios'])}, DHCP clients seen {len(st['dhcp_clients'])}, ARP requests {st['arp_req']}")

    # ARP scan
    if F.get("ipv4_prefix") and not F.get("apipa"):
        net = ipaddress.ip_interface(F["ipv4_prefix"]).network
        hold_back = (None if ARGS.arp_scan else "skipped by --quick" if ARGS.quick
                     else "network looks managed (STP/CDP/LLDP/VLAN seen or larger than a /24), where switches can "
                          "shut a port for ARP bursts" if st["stp"] or st["cdp"] or st["lldp"] or st["vlan"] or net.prefixlen < 24
                     else None)
        if net.prefixlen < 22:
            net = ipaddress.ip_interface(f"{F['ipv4']}/24").network
            R.note(f"subnet is large - scanning only {net}")
        targets = [str(h) for h in net.hosts() if str(h) != F["ipv4"]]
        if targets and hold_back:
            R.add("SKIP", "ARP scan", f"{hold_back} (--arp-scan runs it anyway)")
        elif targets:
            R.progress(f"ARP scan of {net} ({len(targets)} addresses, about {len(targets) * ARP_SCAN_GAP:.0f} s) …")
            try:
                found = arp_scan(targets, F["ipv4"], my_mac())
            except OSError as e:
                found = {}
                R.add("SKIP", "ARP scan", describe_exc(e))
            F["arp_scan"] = {ip: list(m) for ip, m in found.items()}
            conflicts = {ip: m for ip, m in found.items() if len(m) > 1}
            by_mac = {}
            for ip, m in found.items():
                for mac in m:
                    by_mac.setdefault(mac, []).append(ip)
                    host(mac)["v4"].add(ip)
            R.add("PASS" if found else "WARN", "ARP scan", f"{len(found)} devices answer in {net}"
                  + ("" if found else " - nothing answers (client isolation / the router filters ARP?)"))
            for ip, m in conflicts.items():
                F["ip_conflict"] = True
                R.add("FAIL", "IP conflict", f"{ip} is claimed by {', '.join(f'{x} {vendor(x)}'.strip() for x in m)}")
            for mac, ips in by_mac.items():
                if len(ips) > max(8, len(targets) // 3):
                    F["proxy_arp"] = mac
                    R.add("WARN", "Proxy ARP", f"{mac} {vendor(mac)} answers for {len(ips)} addresses - a device replies "
                          "for IPs it does not own; conflicts and DHCP checks become unreliable")
                elif len(ips) > 1:
                    R.note(f"{mac} answers for {', '.join(ips)} (multi-homed device)")
            if F.get("gateway") and F["gateway"] not in found and ipaddress.ip_address(F["gateway"]) in net:
                R.add("WARN", "Gateway in scan", f"{F['gateway']} did not answer the scan")
    # IPv6 neighbours
    if F.get("v6") == "enabled" and F.get("v6_ll"):
        R.progress("IPv6 all-nodes / all-routers multicast ping …")
        try:
            nodes = multicast_echo("ff02::1")
            routers = multicast_echo("ff02::2")
        except OSError as e:
            nodes, routers = {}, {}
            R.add("SKIP", "IPv6 neighbour scan", describe_exc(e))
        if nodes or routers:
            res = ndp_ns(list(set(nodes) | set(routers)), rounds=1, wait=1.0)
            for a, e in res.items():
                for mac in e["macs"]:
                    host(mac)["v6"].add(a)
                    if a in routers or e["router"]:
                        host(mac)["roles"].add("IPv6 router")
            R.add("INFO", "IPv6 neighbour scan", f"{len(nodes)} nodes answer ff02::1, {len(routers)} answer ff02::2 "
                  "(Windows and many phones ignore multicast ping)")
    # roles and table
    for mac in F.get("gw_mac") or []:
        host(mac)["roles"].add("IPv4 gateway")
    for o in F.get("dhcp_offer_list") or []:
        host(o["src_mac"])["roles"].add("DHCP server")
        host(o["src_mac"])["v4"].add(o["src_ip"])
    mine = own_macs()
    for mac in hosts:
        if mac in mine:
            hosts[mac]["roles"].add(f"this computer ({mine[mac]})")
    if not hosts:
        return
    names = {}
    dns_srv = F.get("gateway")
    if dns_srv:
        ips = [ip for h in hosts.values() for ip in h["v4"]]
        names = dict(parallel(lambda ip: (ip, rdns(ip, dns_srv)), ips, workers=16))
    F["lan_hosts"] = {m: {"v4": sorted(h["v4"]), "v6": sorted(h["v6"]), "roles": sorted(h["roles"]), "vendor": vendor(m)}
                      for m, h in hosts.items()}
    R.add("INFO", "Devices on the LAN", f"{len(hosts)} (union of ARP scan, IPv6 scan and passive listening)")
    R.note(f"{'MAC':<18} {'vendor':<26} {'IPv4':<16} {'IPv6 (first)':<28} {'name / role'}")

    def sortkey(item):
        v4 = sorted(item[1]["v4"], key=lambda x: ipaddress.ip_address(x))
        return (0, ipaddress.ip_address(v4[0])) if v4 else (1, ipaddress.ip_address("0.0.0.0"))

    for mac, h in sorted(hosts.items(), key=sortkey):
        v4 = sorted(h["v4"], key=lambda x: ipaddress.ip_address(x))
        v6 = sorted(h["v6"], key=lambda a: (addr_class(a) != "public", a))
        nm = next((names[i] for i in v4 if names.get(i)), "") or st["hostnames"].get(mac, "")
        tag = "; ".join([x for x in [nm] + sorted(h["roles"]) if x])
        R.note(f"{mac:<18} {vendor(mac)[:26]:<26} {(v4[0] if v4 else '-'):<16} {(v6[0] if v6 else '-')[:28]:<28} {tag}")
        for extra in v4[1:]:
            R.note(f"{'':<18} {'':<26} {extra}")


ARP_SCAN_GAP = 0.08     # 12.5 requests/s: below the 15/s at which switch ARP inspection commonly disables a port


def arp_scan(targets, src_ip, mac, passes=1, gap=ARP_SCAN_GAP, wait=1.5):
    s = packet_socket(ETH_P_ARP)
    s.setblocking(False)
    sip = socket.inet_aton(src_ip)
    found = {}

    def drain():
        while True:
            try:
                data = s.recv(128)
            except (BlockingIOError, InterruptedError):
                return
            p = arp_parse(data)
            if p and p["op"] == 2 and p["dst"] == macstr(mac):
                found.setdefault(p["spa"], {})
                found[p["spa"]][p["sha"]] = found[p["spa"]].get(p["sha"], 0) + 1

    try:
        for n in range(passes):
            for ip in targets:
                if n and ip in found:
                    continue
                try:
                    s.send(arp_frame(mac, sip, socket.inet_aton(ip)))
                except OSError:
                    time.sleep(0.02)
                drain()
                time.sleep(gap)
            end = time.monotonic() + wait
            while time.monotonic() < end:
                select.select([s], [], [], 0.1)
                drain()
    finally:
        s.close()
    return found


# --------------------------------------------------------------------------- L3 LAN

def test_lan():
    R.section("L3-LAN", "L3  LAN  (addressing, routing, router reachability - IPv4 and IPv6)")
    if not F.get("ipv4"):
        R.add("FAIL", "IPv4 address", f"none on {IFACE} - DHCP did not complete"
              + (" (but a DHCP server does answer - check NetworkManager/dhclient)" if F.get("dhcp_offers") else ""))
    elif F["apipa"]:
        R.add("FAIL", "IPv4 address", f"{F['ipv4_prefix']} is a 169.254 self-assigned address - DHCP failed")
    else:
        R.add("PASS", "IPv4 address", f"{', '.join(F['ipv4_all'])} ({addr_class(F['ipv4'])})")
    dr = F.get("default_route")
    if dr:
        R.add("PASS", "IPv4 default route", f"via {dr.get('gateway')} dev {IFACE} metric {dr.get('metric', 0)} "
              f"({dr.get('protocol', 'static')})")
    elif F.get("gateway"):
        R.add("WARN", "IPv4 default route", f"none via {IFACE}; using {F['gateway']} for LAN tests only - internet "
              "tests through this interface will fail (NetworkManager did not install a gateway)")
    else:
        R.add("FAIL", "IPv4 default route", f"none via {IFACE}")
    if dr:
        mine = dr.get("metric", 0)
        better = [r for r in F["all_default_routes"] if r.get("dev") != IFACE and r.get("metric", 0) < mine]
        rpf = max(int(sysread("/proc/sys/net/ipv4/conf/all/rp_filter", "0") or 0),
                  int(sysread(f"/proc/sys/net/ipv4/conf/{IFACE}/rp_filter", "0") or 0))
        if better:
            R.add("INFO", "Route priority", f"normal system traffic prefers {better[0]['dev']} "
                  f"(metric {better[0].get('metric', 0)} < {mine}); this tool still forces {IFACE}")
            if rpf == 1:
                F["rpf_risk"] = True
                R.add("WARN", "Reverse-path filter", f"strict rp_filter=1 with a better route on {better[0]['dev']} - "
                      f"replies arriving on {IFACE} may be dropped by the kernel (false failures). Disconnect "
                      "the other link, or: sudo sysctl net.ipv4.conf.all.rp_filter=2")
    gw = F.get("gateway")
    if gw and F.get("ipv4_prefix") and ipaddress.ip_address(gw) not in ipaddress.ip_interface(F["ipv4_prefix"]).network:
        R.add("WARN", "Gateway subnet", f"gateway {gw} is outside {ipaddress.ip_interface(F['ipv4_prefix']).network}")
    if F.get("v6") == "enabled":
        g = F.get("v6_global_addrs") or []
        if g:
            R.add("PASS", "IPv6 global address", ", ".join(g[:3]) + (f" (+{len(g) - 3})" if len(g) > 3 else ""))
        elif F.get("v6_ula_addrs"):
            R.add("WARN", "IPv6 global address", f"only ULA ({F['v6_ula_addrs'][0]}) - local IPv6 only, no IPv6 internet")
        else:
            R.add("INFO", "IPv6 global address", "none")
        if F.get("default_route6"):
            R.add("PASS", "IPv6 default route", f"via {F['gateway6']} dev {IFACE} metric {F['default_route6'].get('metric', 0)}")
        elif g:
            R.add("FAIL", "IPv6 default route", f"global address but no IPv6 default route via {IFACE}")
    F["iface_dns"] = iface_dns_servers()
    R.add("INFO", "DNS servers for this link", ", ".join(F["iface_dns"]) or "none reported")
    rc = sysread("/etc/resolv.conf", "")
    ns = re.findall(r"^nameserver\s+(\S+)", rc, re.M)
    R.add("INFO", "System resolv.conf", ", ".join(ns) + (" (systemd-resolved stub)" if "127.0.0.53" in ns else ""))

    if not gw:
        R.add("FAIL", "Router ping", "no IPv4 gateway to test")
        F["gw_ok"] = False
    else:
        R.progress(f"pinging router {gw} …")
        p = ping(gw, count=30, interval=0.05)
        F["gw_ping"] = p
        F["gw_ping_ok"] = p["rx"] > 0
        if p["rx"] == 0 and F.get("gw_arp"):
            R.add("WARN", "Router ping", f"{ping_summary(p)} - router answers ARP but not ping (ICMP blocked or router CPU stuck)")
        else:
            R.add(ping_status(p, warn_loss=1, fail_loss=10, warn_rtt=5), "Router ping",
                  ping_summary(p) + (" - high latency on a wired LAN" if p["avg"] and p["avg"] > 5 else ""))
        if p["rx"] and not ARGS.quick:
            b = ping(gw, count=300, interval=0.01 if ROOT else 0.2, wait=0.5)
            F["gw_burst"] = b
            R.add(ping_status(b, warn_loss=1, fail_loss=5), "Router ping burst (300 @ 10 ms)", ping_summary(b))
            L = ping(gw, count=20, interval=0.05, size=1472, df=True)
            F["gw_large"] = L
            R.add(ping_status(L, warn_loss=1, fail_loss=10), "Router ping 1500-byte frames (DF)", ping_summary(L)
                  + (" - small packets pass but full-size frames do not: MTU/frame problem" if not L["rx"] else ""))
        services = parallel(lambda port: (port, tcp_connect(gw, port, 2)), [53, 80, 443, 22])
        open_ports = [str(pt) for pt, (s, _) in services if s in ("open", "refused")]
        R.add("INFO", "Router TCP stack", ("responds on " + ", ".join(f"{pt}/{s}" for pt, (s, _) in services))
              if open_ports else "no TCP response on 53/80/443/22")
        F["gw_tcp_alive"] = bool(open_ports)
        F["gw_ok"] = F["gw_ping_ok"] or bool(F.get("gw_arp")) or F["gw_tcp_alive"]
    gw6 = F.get("gateway6")
    if gw6:
        p6 = ping(gw6, count=30, interval=0.05, v6=True)
        F["v6_gw_ping"] = p6
        R.add(ping_status(p6, warn_loss=1, fail_loss=10, warn_rtt=5), f"IPv6 router ping {gw6}", ping_summary(p6))
        if p6["rx"] and not ARGS.quick:
            L6 = ping(gw6, count=20, interval=0.05, size=1452, df=True, v6=True)
            R.add(ping_status(L6, warn_loss=1, fail_loss=10), "IPv6 router ping 1500-byte packets", ping_summary(L6))


# --------------------------------------------------------------------------- L3 WAN

def test_wan(v6=False):
    fk = "v6_" if v6 else ""
    fam = "IPv6" if v6 else "IPv4"
    R.section("L3-WAN" + ("-v6" if v6 else ""), f"L3  WAN {fam}  (beyond the router: ISP path, routing, MTU)")
    if v6:
        if F.get("v6") != "enabled" or not F.get("v6_global_addrs"):
            R.add("SKIP", "IPv6 internet", "no global IPv6 address on this link")
            return
        if not F.get("default_route6"):
            R.add("FAIL", "IPv6 internet route", f"no IPv6 default route via {IFACE}")
            F["v6_inet_ok"] = False
            return
    elif not F.get("default_route"):
        R.add("FAIL", "Internet route", f"no default route via {IFACE} - cannot test beyond the LAN")
        F["inet_ok"] = False
        return
    R.progress(f"pinging public anycast {fam} addresses (no DNS involved) …")
    targets = PUBLIC_V6 if v6 else PUBLIC_V4
    res = parallel(lambda t: (t, ping(t[0], count=20, interval=0.1, v6=v6)), targets)
    ok, losses = 0, []
    for (ip, name), p in res:
        R.add(ping_status(p, warn_loss=2, fail_loss=25, warn_rtt=150), f"Ping {ip} ({name})", ping_summary(p))
        ok += p["rx"] > 0
        losses.append(p["loss"])
    F[fk + "inet_ping"] = {ip: p for (ip, _), p in res}
    F[fk + "inet_ok"] = ok > 0
    F[fk + "inet_all_ok"] = ok == len(res)
    F[fk + "inet_loss"] = mean(losses)
    for _, p in res:
        for e in p["errors"]:
            m = re.search(r"From ([0-9a-fA-F:.]+)\S*\s+icmp_seq=\d+\s+(.*)", e)
            if m:
                F.setdefault(fk + "ping_unreach", {})[m.group(1)] = m.group(2).strip()
    if not ok:
        tp = parallel(lambda c: (c, tcp_connect(c[0], c[1], 3)), TCP_CHECKS[v6][:3])
        opened = [f"{ip}:{pt}" for (ip, pt), (st, _) in tp if st == "open"]
        if opened:
            F[fk + "icmp_filtered"] = True
            F[fk + "inet_ok"] = True
            R.add("WARN", "ICMP filtered", f"no ping replies, but TCP to {', '.join(opened)} works - ping is blocked "
                  "somewhere; the internet itself is reachable")

    target = next((ip for (ip, _), p in res if p["rx"]), targets[0][0])
    wait = path_wait(max([p["max"] for _, p in res if p["max"]] or [0]))
    F["path_wait"] = max(F.get("path_wait", 1.0), wait)
    if wait > 1.0:
        R.note(f"slow path (up to {max(p['max'] or 0 for _, p in res):.0f} ms): traces wait {wait:.1f} s per round")
    if ROOT:
        rounds = 4 if ARGS.quick else 12
        R.progress(f"mtr-style trace to {target}, {rounds} rounds (~{rounds * (wait + 0.1):.0f} s) …")
        try:
            hops, dest_ttl = mtr(target, rounds=rounds, wait=wait, v6=v6)
            analyze_trace(hops, dest_ttl, target, fk)
            if not dest_ttl:
                R.progress(f"ICMP trace did not arrive - TCP SYN trace to {target}:443 …")
                th, tdest = tcp_trace(target, 443, v6, rounds=1 if ARGS.quick else 2, wait=max(1.5, wait))
                show_tcp_trace(th, tdest, hops, target, fk)
        except OSError as e:
            R.add("SKIP", "Traceroute", describe_exc(e))
    elif shutil.which("mtr"):
        R.progress(f"mtr report to {target} …")
        rc, out, err = run(["mtr", "-6" if v6 else "-4", "-n", "-r", "-c", "5", "-I", IFACE, target], timeout=60)
        if rc == 0 and re.search(r"^\s*\d+\.", out, re.M):
            R.add("INFO", "Traceroute (mtr)", "raw output follows")
            for l in out.splitlines():
                R.note(l)
        else:
            R.add("SKIP", "Traceroute (mtr)", f"mtr could not run ({(err or out).strip().splitlines()[0][:80] if (err or out).strip() else f'exit {rc}'})"
                  + (" - run as root for a trace" if not ROOT else ""))
    else:
        R.add("SKIP", "Traceroute", "needs root (or mtr)")
    pu = F.get(fk + "ping_unreach") or {}
    if pu and not F.get(fk + "router_no_route"):
        hop1 = next((h["addr"] for h in F.get(fk + "trace") or [] if h["ttl"] == 1), None)
        routers = {x.split("%")[0] for x in (F.get("gateway"), F.get("gateway6"), hop1) if x}
        for src, txt in pu.items():
            if src in routers and not re.search(r"prohibit|policy", txt, re.I) and not ok:
                F[fk + "router_no_route"] = True
                R.add("FAIL", f"Router answers '{txt}'", f"{src} says it has no way to the internet - its WAN "
                      "interface / mobile data session is down")
            elif src in routers and not re.search(r"prohibit|policy", txt, re.I):
                R.add("WARN", f"Router answers '{txt}'", f"{src} rejects some destinations while others work - "
                      "a partial routing problem, not a dead WAN")
            else:
                R.add("INFO", "Unreachable reply", f"{src} answers '{txt}'")

    w = F.get(fk + "wan_hop")
    if w:
        p = ping(w, count=30, interval=0.1, v6=v6)
        F[fk + "wan_hop_ping"] = p
        if p["rx"]:
            F[fk + "wan_hop_echo"] = w
            R.add(ping_status(p, warn_loss=2, fail_loss=15), f"Ping ISP edge {w}", ping_summary(p)
                  + "  (= your WAN line: router -> ISP)")
        else:
            R.add("INFO", f"Ping ISP edge {w}", "does not answer echo (common; trace hop data is used instead)")
    if F[fk + "inet_ok"] and not F.get(fk + "icmp_filtered"):
        pmtu_discovery(target, v6)
    if F[fk + "inet_ok"]:
        diversity_check(v6)


def show_tcp_trace(th, tdest, icmp_hops, target, fk):
    R.note(f"TCP SYN trace to {target}:443")
    for h in th:
        R.note(f"{h['ttl']:>3}  {h['addr'] or '* * *':<39} {h['recv']}/{h['sent']}  {fmt_ms(h['avg']):>7}")
    icmp_last = max([h["ttl"] for h in icmp_hops if h["addr"]] or [0])
    tcp_last = max([h["ttl"] for h in th if h["addr"]] or [0])
    if tdest:
        F[fk + "tcp_trace_reached"] = True
        R.add("WARN", "TCP trace", f"TCP reaches {target} in {tdest} hops although ICMP does not - only ICMP is "
              "filtered, the path works")
    elif tcp_last > icmp_last:
        R.add("INFO", "TCP trace", f"TCP gets to hop {tcp_last}, ICMP only to hop {icmp_last} - ICMP is filtered "
              f"partway, but TCP also stops after hop {tcp_last}")
    elif tcp_last == 0:
        R.add("FAIL", "TCP trace", "no hop answers TCP probes either - the path really ends at the router")
    else:
        R.add("FAIL", "TCP trace", f"TCP stops at the same place (hop {tcp_last}) - the path really ends there")


def diversity_check(v6=False):
    """Reach non-anycast destinations in different regions; partial failure points to ISP upstream/peering."""
    fk = "v6_" if v6 else ""

    def probe(t):
        ips = resolve(t[0], v6)
        if not ips:
            return t, None, None, None
        tc = tcp_connect(ips[0], 443, 3)
        if tc[0] not in ("open", "refused"):
            tc = tcp_connect(ips[0], 80, 3)
        return t, ips[0], tc, ping(ips[0], count=4, interval=0.2, v6=v6)

    R.progress(f"reaching {len(DIVERSE_TARGETS)} non-anycast destinations in other regions …")
    ok = tested = 0
    for (host, label), ip, tc, p in parallel(probe, DIVERSE_TARGETS):
        if ip is None:
            R.add("SKIP", f"Reach {host} ({label})", "no AAAA record" if v6 else "cannot resolve")
            continue
        tested += 1
        good = tc[0] in ("open", "refused") or p["rx"] > 0
        ok += good
        R.add("PASS" if good else "FAIL", f"Reach {host} ({label})",
              f"{ip}: tcp {tc[0]}" + (f" {tc[1]:.0f} ms" if tc[1] else "") + f", ping {p['rx']}/{p['tx']}"
              + (f" avg {fmt_ms(p['avg'])} ms" if p["avg"] else ""))
    F[fk + "diverse_ok"], F[fk + "diverse_total"] = ok, tested
    if tested and 0 < ok < tested:
        R.add("WARN", "Partial reachability", f"{tested - ok} of {tested} distant destinations fail while others work - "
              "an ISP upstream/peering problem, not your line")


def analyze_trace(hops, dest_ttl, target, fk=""):
    for h in hops:
        h["class"] = addr_class(h["addr"]) if h["addr"] else None
    names = dict(parallel(lambda h: (h["addr"], rdns(h["addr"])), [h for h in hops if h["addr"]], workers=10))
    R.add("PASS" if dest_ttl else "FAIL", f"Traceroute to {target}",
          f"destination reached in {dest_ttl} hops" if dest_ttl else "destination NOT reached")
    w = 39 if fk else 16
    R.note(f"{'hop':>3}  {'address':<{w}} {'loss':>5} {'snt':>4} {'avg':>7} {'best':>7} {'worst':>7}  class      name")
    for h in hops:
        if not h["addr"]:
            R.note(f"{h['ttl']:>3}  {'* * *':<{w}} {h['loss']:>4.0f}% {h['sent']:>4}")
            continue
        extra = (" (+" + ",".join(a for a in h["all_addrs"] if a != h["addr"])[:40] + ")") if len(h["all_addrs"]) > 1 else ""
        R.note(f"{h['ttl']:>3}  {h['addr']:<{w}} {h['loss']:>4.0f}% {h['sent']:>4} {fmt_ms(h['avg']):>7} "
               f"{fmt_ms(h['best']):>7} {fmt_ms(h['worst']):>7}  {h['class']:<10} {(names.get(h['addr']) or '')[:45]}{extra}")
    F[fk + "trace"] = hops
    F[fk + "trace_dest_ttl"] = dest_ttl
    codes = UNREACH6 if fk else UNREACH4
    for h in hops:
        for src, code, _n in h.get("unreach", []):
            if src == target.split("%")[0]:
                continue
            what = codes.get(code, f"unreachable code {code}")
            F.setdefault(fk + "unreach", []).append({"ttl": h["ttl"], "src": src, "code": code, "what": what})
            blocked = re.search(r"prohibit|policy|reject", what)
            if h["ttl"] == 1 and not blocked and F.get(fk + "inet_ok"):
                R.add("WARN", f"ICMP '{what}' from hop 1 ({src})", f"the router has no route to {target}, but other "
                      "destinations work - a partial routing problem, not a dead WAN")
                continue
            if h["ttl"] == 1 and not blocked:
                F[fk + "router_no_route"] = True
                msg = "the router itself has no route to the internet - its WAN interface / data session is down"
            elif h["ttl"] == 1:
                msg = "the router's own firewall rejects this traffic"
            else:
                msg = "blocked by a filter in the ISP network" if blocked else \
                      f"the ISP network (hop {h['ttl']}) has no route onward - ISP-side outage"
            R.add("FAIL", f"ICMP '{what}' from hop {h['ttl']} ({src})", msg)
    resp = [h for h in hops if h["addr"]]
    gw = F.get("gateway")
    if not fk and resp and resp[0]["ttl"] == 1 and gw and resp[0]["addr"] != gw:
        R.add("INFO", "First hop", f"hop 1 is {resp[0]['addr']}, not the configured gateway {gw}")
    beyond = [h for h in resp if h["ttl"] >= 2]
    if beyond:
        F[fk + "wan_hop"] = beyond[0]["addr"]
    if not beyond and not dest_ttl:
        R.add("FAIL", "Path beyond router", "nothing past the router answers - router's WAN/uplink is down or the ISP is not routing")
        F[fk + "trace_stop_hop"] = 1
    elif not dest_ttl and resp:
        F[fk + "trace_stop_hop"] = resp[-1]["ttl"]
        R.add("FAIL", "Path", f"the path dies after hop {resp[-1]['ttl']} ({resp[-1]['addr']})")
    if not fk:
        h1 = next((h for h in resp if h["ttl"] == 1), None)
        h2 = next((h for h in beyond if h["ttl"] == 2), None)
        if h2 and h2["class"] == "private" and h2["addr"] != gw:
            a = ipaddress.ip_address(h2["addr"])
            near = h1 and h1["best"] is not None and h2["best"] is not None and h2["best"] - h1["best"] < 3
            if a in DSLITE_NET:
                F["dslite"] = True
                R.add("INFO", "DS-Lite", f"hop 2 is {h2['addr']} (the ISP's AFTR): IPv4 is tunnelled over IPv6 and "
                      "shared (CGNAT) - IPv4-only problems with working IPv6 point at the ISP's AFTR")
            elif near:
                F["double_nat"] = h2["addr"]
                R.add("WARN", "Double NAT", f"hop 2 ({h2['addr']}) is a private router only "
                      f"{h2['best'] - h1['best']:.1f} ms behind yours - a second NAT device in the house "
                      "(ISP modem/router in router mode?)")
            else:
                F["carrier_private"] = h2["addr"]
                R.add("INFO", "ISP-internal network", f"hop 2 ({h2['addr']}) is a private address inside the ISP "
                      f"(+{(h2['best'] or 0) - (h1['best'] or 0) if h1 else 0:.0f} ms) - normal for mobile (LTE/5G) "
                      "and many CGNAT ISPs; IPv4 is shared, inbound connections will not work")
        cg = [h for h in beyond if h["class"] == "CGNAT"]
        if cg:
            F["cgnat_hop"] = cg[0]["addr"]
            R.add("INFO", "Carrier-grade NAT", f"hop {cg[0]['ttl']} {cg[0]['addr']} is in 100.64/10 - ISP uses CGNAT")
    # loss onset: a hop whose loss persists through all later hops is real loss
    real = None
    for i, h in enumerate(resp):
        if h["loss"] < 10:
            continue
        if all(r["loss"] >= min(h["loss"], 10) * 0.6 for r in resp[i + 1:]):
            real = h
            break
    if real:
        F[fk + "trace_loss_onset"] = real["ttl"]
        where = ("between computer and router" if real["ttl"] == 1 else
                 "on the router's WAN link / ISP access network" if real["ttl"] <= 3 else
                 "inside the ISP or beyond")
        R.add("WARN" if real["loss"] < 30 else "FAIL", "Packet loss location",
              f"loss starts at hop {real['ttl']} ({real['addr']}, {real['loss']:.0f}%) and continues to the end - {where}")
    elif resp:
        if any(h["loss"] >= 10 for h in resp):
            R.add("INFO", "Hop loss", "intermediate hops show loss but later hops don't - that is ICMP rate "
                  "limiting, not real loss")
        else:
            R.add("PASS", "Packet loss location", "no persistent loss along the path")
    prev = None
    for h in resp:
        if prev and h["avg"] and prev["avg"] and h["avg"] - prev["avg"] > 40 and \
                all((r["avg"] or 0) >= h["avg"] * 0.7 for r in resp if r["ttl"] > h["ttl"]):
            R.add("INFO", "Latency jump", f"+{h['avg'] - prev['avg']:.0f} ms between hop {prev['ttl']} and {h['ttl']} "
                  f"({h['addr']})" + (" - the access link (LTE/DSL/cable) adds this" if h["ttl"] <= 3 else ""))
            F[fk + "latency_jump_hop"] = h["ttl"]
            break
        prev = h


def pmtu_discovery(target, v6=False):
    fk = "v6_" if v6 else ""
    hdr = 48 if v6 else 28
    R.progress(f"path MTU discovery to {target} …")

    def passes(size):
        p = ping(target, count=2, interval=0.2, size=size, df=True, wait=1, v6=v6)
        return p["rx"] > 0, p["mtu_hint"]

    ok, hint = passes(1500 - hdr)
    if ok:
        F[fk + "pmtu"] = 1500
        R.add("PASS", f"Path MTU{' (IPv6)' if v6 else ''}", "1500 (full-size packets pass unfragmented)")
        return
    lo, hi = (1280 if v6 else 576) - hdr, 1500 - hdr
    if not passes(lo)[0]:
        R.add("SKIP", "Path MTU", "even small DF pings fail - cannot measure")
        return
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if passes(mid)[0]:
            lo = mid
        else:
            hi = mid
    pmtu = lo + hdr
    F[fk + "pmtu"] = pmtu
    known = {1492: "PPPoE", 1480: "PPPoA/6in4 tunnel", 1460: "LTE/tunnel", 1450: "VXLAN/LTE", 1440: "LTE/GTP",
             1420: "WireGuard", 1400: "tunnel", 1280: "IPv6 minimum / tunnel"}
    detail = f"{pmtu}" + (f" (typical for {known[pmtu]})" if pmtu in known else "")
    name = f"Path MTU{' (IPv6)' if v6 else ''}"
    if hint:
        R.add("INFO", name, detail + f"; a router reported mtu={hint} - smaller than 1500 but signalled correctly")
    else:
        F[fk + "pmtu_blackhole"] = True
        R.add("WARN", name, detail + " - no 'too big' message came back: possible PMTU black hole "
              "(large transfers/HTTPS may stall; router should clamp TCP MSS"
              + (f" and advertise MTU {pmtu} in its RAs)" if v6 else ")"))


# --------------------------------------------------------------------------- DNS

def test_dns():
    R.section("DNS", "DNS  (name resolution over IPv4 and IPv6)")
    iface = F.get("iface_dns") or []
    local4 = dedupe([s for s in iface if ":" not in s] + (F.get("dhcp_dns") or []) + ([F["gateway"]] if F.get("gateway") else []))
    local6 = dedupe([s for s in iface if ":" in s] + (F.get("v6_dhcp_dns") or []) + (F.get("v6_ra_dns") or []))
    # public resolvers only where the internet is reachable - otherwise they just add identical failures
    pub4 = [s for s in PUBLIC_DNS if s not in local4] if F.get("inet_ok") else []
    pub6 = [s for s in PUBLIC_DNS6 if s not in local6] if v6_route_ok() and F.get("v6_inet_ok") else []
    if F.get("default_route") and not F.get("inet_ok"):
        R.add("SKIP", "Public resolvers (IPv4)", "not tested - no internet over IPv4 (see L3 WAN)")
    local6 = [s for s in local6 if addr_class(s) == "link-local" or v6_route_ok() or addr_class(s) == "ULA"]
    servers = local4 + pub4 + local6 + pub6
    local = local4 + local6
    if not servers:
        R.add("FAIL", "DNS", "no DNS server to test")
        F["dns_ok"] = False
        return

    def probe(srv):
        out = {"server": srv, "udp": [], "tcp": None, "nx": None}
        for name in DNS_TEST_NAMES[:3]:
            try:
                r = dns_query(srv, name, "A", timeout=2)
                out["udp"].append((name, RCODES.get(r["rcode"], r["rcode"]), r["ms"],
                                   [v for t, v, _ in r["answers"] if t == 1]))
            except DNS_ERRORS as e:
                out["udp"].append((name, describe_exc(e), None, []))
        try:
            r = dns_query(srv, "example.com", "AAAA", tcp=True, timeout=3)
            out["tcp"] = (RCODES.get(r["rcode"], r["rcode"]), r["ms"])
        except (DNS_ERRORS + (NetError,)) as e:
            out["tcp"] = (describe_exc(e), None)
        try:
            junk = "".join(random.choices(string.ascii_lowercase, k=18)) + ".com"
            r = dns_query(srv, junk, "A", timeout=2)
            out["nx"] = RCODES.get(r["rcode"], r["rcode"]), [v for t, v, _ in r["answers"] if t == 1]
        except DNS_ERRORS:
            pass
        return out

    R.progress(f"querying {len(servers)} resolvers ({len(local4) + len(pub4)} via IPv4, {len(local6) + len(pub6)} via IPv6) "
               "over UDP and TCP …")
    results = parallel(probe, servers)
    working = []
    for r in results:
        srv = r["server"]
        good = [u for u in r["udp"] if u[1] == "NOERROR" and u[3]]
        times = [u[2] for u in good]
        tcp = r["tcp"]
        if good:
            working.append(srv)
            st = "PASS" if len(good) == len(r["udp"]) and (mean(times) or 0) < 300 else "WARN"
        else:
            st = "FAIL"
        detail = (f"UDP {len(good)}/{len(r['udp'])} ok" + (f", avg {mean(times):.0f} ms" if times else "")
                  + (f" ({r['udp'][0][1]})" if not good else "") + f"; TCP {tcp[0]}" + (f" {tcp[1]:.0f} ms" if tcp[1] else ""))
        R.add(st, f"DNS {srv} ({'router/ISP' if srv in local else 'public'}, {'IPv6' if ':' in srv else 'IPv4'})", detail)
        if r["nx"] and r["nx"][0] == "NOERROR" and r["nx"][1]:
            F["dns_hijack"] = srv
            R.add("WARN", f"NXDOMAIN hijack at {srv}", f"non-existent names resolve to {r['nx'][1][0]} - "
                  "ISP/router redirects typos (breaks some apps)")
    for r in results:
        codes = {u[1] for u in r["udp"]}
        if r["server"] in local and codes and codes <= {"SERVFAIL", "REFUSED"}:
            F["router_dns_servfail"] = True
            t = mean([u[2] for u in r["udp"] if u[2]])
            R.add("WARN", f"DNS {r['server']} answer type", f"answers {'/'.join(sorted(codes))} in {fmt_ms(t)} ms: the "
                  "DNS server is alive but cannot resolve - it cannot reach its upstream (WAN down / ISP DNS down)")
    F["dns_results"] = results
    F["dns_working"] = working
    F["dns4_working"] = [s for s in working if ":" not in s]
    F["dns6_working"] = [s for s in working if ":" in s]
    F["dns_local"] = local
    F["dns_local_working"] = [s for s in working if s in local]
    F["dns_local4"] = local4
    F["dns_local6"] = local6
    F["resolvers"] = ([s for s in F["dns4_working"] if s in local] + [s for s in F["dns4_working"] if s not in local]
                      + F["dns6_working"]) or PUBLIC_DNS
    if local4 and not [s for s in local4 if s in working] and F["dns4_working"]:
        R.add("WARN", "Router/ISP DNS (IPv4)", "the DNS servers this link uses do not work but public resolvers do - "
              "set DNS to 1.1.1.1 / 8.8.8.8 or reboot the router")
    if local6 and not [s for s in local6 if s in working]:
        R.add("WARN", "Router/ISP DNS (IPv6)", f"advertised IPv6 DNS server(s) {', '.join(local6)} do not answer - "
              "dual-stack clients may see slow lookups")
    if v6_route_ok() and not F["dns6_working"]:
        R.add("WARN", "DNS over IPv6", "no resolver reachable over IPv6 (IPv4 DNS still answers AAAA queries)")
    if working:
        try:
            r = dns_query(F["resolvers"][0], "google.com", "AAAA", timeout=2)
            aaaa = [v for t, v, _ in r["answers"] if t == 28]
            R.add("PASS" if aaaa else "WARN", "AAAA lookup", f"google.com -> {aaaa[0] if aaaa else 'no AAAA records (resolver filters AAAA?)'}")
        except DNS_ERRORS as e:
            R.add("WARN", "AAAA lookup", describe_exc(e))
    t0 = time.monotonic()
    try:
        ai = socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        R.add("INFO", "System resolver (getaddrinfo)", f"example.com -> {ai[0][4][0]} in {ms(t0):.0f} ms "
              "(not bound to the interface - uses the system's preferred route)")
    except OSError as e:
        R.add("WARN" if working else "INFO", "System resolver (getaddrinfo)", describe_exc(e)
              + (" - local resolver setup is broken" if working else " (expected: no resolver works)"))
    dots = [(REFERENCE_V4, False)] if F.get("inet_ok") else []
    dots += [("2606:4700:4700::1111", True)] if F.get("v6_inet_ok") else []
    for ip, _ in dots:
        try:
            fam, sa = sockaddr(ip, 853)
            s = bsock(fam, socket.SOCK_STREAM)
            s.settimeout(4)
            t0 = time.monotonic()
            s.connect(sa)
            ss = ssl.create_default_context().wrap_socket(s, server_hostname="cloudflare-dns.com")
            R.add("PASS", f"DNS-over-TLS {ip}", f"{ss.version()} handshake in {ms(t0):.0f} ms")
            ss.close()
        except (OSError, ssl.SSLError) as e:
            R.add("WARN", f"DNS-over-TLS {ip}", describe_exc(e))
    F["dns_ok"] = bool(working)


# --------------------------------------------------------------------------- L4

def ntp_query(ip, timeout=2.0):
    fam, sa = sockaddr(ip, 123)
    s = bsock(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t1 = time.time()
        s.sendto(b"\x1b" + bytes(47), sa)
        data, _ = s.recvfrom(512)
        t4 = time.time()
    finally:
        s.close()
    if len(data) < 48:
        raise NetError("short NTP reply")

    def ts(o):
        sec, frac = struct.unpack("!II", data[o:o + 8])
        return sec - 2208988800 + frac / 2 ** 32

    t2, t3 = ts(32), ts(40)
    return {"offset": ((t2 - t1) + (t3 - t4)) / 2, "delay": (t4 - t1) - (t3 - t2), "stratum": data[1]}


def tcp_mss(ip, port):
    """Effective TCP MSS of a real connection (the router's MSS clamping shows up here)."""
    fam, sa = sockaddr(ip, port)
    s = bsock(fam, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(sa)
        return s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    except OSError:
        return None
    finally:
        s.close()


def test_transport():
    R.section("L4", "L4  TRANSPORT  (TCP/UDP reachability, filtering, MSS, time - IPv4 and IPv6)")
    for v6 in (False, True):
        fk, fam = ("v6_", "IPv6") if v6 else ("", "IPv4")
        if not F.get(fk + "inet_ok"):
            R.add("SKIP", f"{fam} transport", "not tested - no internet over " + fam + " (see L3 WAN)")
            continue
        res = parallel(lambda c: (c, tcp_connect(*c)), TCP_CHECKS[v6])
        good = 0
        for (ip, port), (st, t) in res:
            good += st == "open"
            R.add("PASS" if st == "open" else "FAIL", f"TCP {'[' + ip + ']' if v6 else ip}:{port}",
                  st + (f" in {t:.0f} ms" if t else ""))
        F[fk + "tcp_ok"] = good > 0
        F[fk + "tcp_all_ok"] = good == len(res)
        if F.get(fk + "inet_ok") and not good:
            R.add("FAIL", f"TCP vs ICMP ({fam})", "ping works but no TCP connection succeeds - firewall/filtering or broken NAT")
        mss = tcp_mss(TCP_CHECKS[v6][0][0], 443)
        pm, hdr = F.get(fk + "pmtu"), (60 if v6 else 40)
        if mss and pm and mss > pm - hdr:
            F[fk + "mss_unclamped"] = True
            R.add("WARN", f"TCP MSS ({fam})", f"{mss} bytes, but the path MTU {pm} only fits {pm - hdr} - the router does "
                  "not clamp the MSS: full-size TCP packets get dropped (stalling downloads, hanging HTTPS)")
        elif mss:
            F[fk + "mss_ok"] = bool(pm)
            R.add("PASS", f"TCP MSS ({fam})", f"{mss} bytes" + (f" - fits the path MTU {pm}" if pm else "")
                  + (" (the router clamps MSS, so TCP is safe; UDP/QUIC can still hit the MTU limit)"
                     if pm and pm < 1500 else ""))
        if not ARGS.quick:
            pq = resolve("portquiz.net", v6)
            if pq:
                R.progress(f"{fam} port filter scan against portquiz.net ({pq[0]}) …")
                # gently, and failures twice: the server drops bursts of connections, which looks like filtering
                pr = dict(parallel(lambda p: (p, tcp_connect(pq[0], p, 3)), PORTQUIZ_PORTS, workers=4))
                failed = [p for p, (st, _) in pr.items() if st != "open"]
                pr.update(parallel(lambda p: (p, tcp_connect(pq[0], p, 4)), failed, workers=3))
                blocked = [str(p) for p, (st, _) in pr.items() if st != "open"]
                if "443" in blocked and tcp_connect(TCP_CHECKS[v6][0][0], 443, 3)[0] == "open":
                    # port 443 demonstrably leaves this network, so the test server is what is not answering
                    F[fk + "blocked_ports"] = []
                    R.add("INFO", f"Outbound TCP port filter ({fam})", f"inconclusive - portquiz.net answered only "
                          f"{len(pr) - len(blocked)}/{len(pr)} ports and not 443, although 443 works to other hosts; "
                          f"the test server is limiting connections. No answer on: {', '.join(blocked)}")
                else:
                    F[fk + "blocked_ports"] = blocked
                    R.add("PASS" if not blocked else ("WARN" if len(blocked) < len(pr) else "FAIL"), f"Outbound TCP port filter ({fam})",
                          f"{len(pr) - len(blocked)}/{len(pr)} ports open" + (f"; blocked/filtered: {', '.join(blocked)}"
                          + (" (port 25 blocking is normal for consumer ISPs)" if blocked == ["25"] else "") if blocked else ""))
            elif not v6:
                R.add("SKIP", "Outbound TCP port filter", "cannot resolve portquiz.net")
        for host in ("time.cloudflare.com", "time.google.com", "pool.ntp.org"):
            ips = resolve(host, v6)
            if not ips:
                continue
            try:
                n = ntp_query(ips[0])
                off = n["offset"]
                if not v6:
                    F["clock_offset"] = off
                st = "PASS" if abs(off) < 2 else "WARN" if abs(off) < 60 else "FAIL"
                R.add(st, f"NTP/UDP {host} ({fam})", f"reply from {ips[0]} stratum {n['stratum']}, delay "
                      f"{n['delay'] * 1000:.0f} ms, local clock offset {off:+.3f} s"
                      + (" - clock is wrong, TLS may fail" if st == "FAIL" else ""))
                break
            except (OSError, NetError) as e:
                R.add("WARN", f"NTP/UDP {host} ({fam})", f"{describe_exc(e)} - UDP 123 blocked or lost")


# --------------------------------------------------------------------------- L7

def test_application():
    R.section("L7", "L7  APPLICATION  (HTTP, HTTPS/TLS, captive portal, public IP - IPv4 and IPv6)")
    for v6 in (False, True):
        fk, fam = ("v6_", "IPv6") if v6 else ("", "IPv4")
        if not F.get(fk + "inet_ok"):
            R.add("SKIP", f"{fam} application tests", "not tested - no internet over " + fam + " (see L3 WAN)")
            continue
        sfx = " (IPv6)" if v6 else ""
        for url, code, body in CONNECTIVITY_CHECKS:
            host = urlparse(url).hostname
            if v6 and not resolve(host, True):
                R.add("SKIP", f"HTTP {host}{sfx}", "no AAAA record")
                continue
            try:
                r = http_request(url, timeout=6, v6=v6)
                if r["status"] in (301, 302, 303, 307, 308):
                    F[fk + "captive"] = r["headers"].get("location")
                    R.add("WARN", f"HTTP {host}{sfx}", f"redirected to {r['headers'].get('location')} - "
                          "captive portal, ISP block page or transparent proxy")
                elif r["status"] == code and (body is None or body in r["body"]):
                    R.add("PASS", f"HTTP {host}{sfx}", f"{r['status']} in {r['timing']['total_ms']:.0f} ms")
                    F[fk + "http_ok"] = True
                else:
                    R.add("WARN", f"HTTP {host}{sfx}", f"unexpected answer {r['status']} {r['reason']} "
                          f"({len(r['body'])} bytes) - content is being modified/intercepted")
            except HTTP_FAILURES as e:
                R.add("FAIL", f"HTTP {host}{sfx}", describe_exc(e))

        def fetch(url):
            if v6 and not resolve(urlparse(url).hostname, True):
                return url, None, "noaaaa"
            try:
                return url, http_request(url, timeout=10, max_body=64 * 1024, v6=v6), None
            except HTTP_FAILURES as e:
                return url, None, e

        R.progress(f"HTTPS handshakes over {fam} …")
        ok = tested = 0
        for url, r, e in parallel(fetch, HTTPS_SITES):
            host = urlparse(url).hostname
            if e == "noaaaa":
                R.add("SKIP", f"HTTPS {host}{sfx}", "site has no IPv6 address")
                continue
            tested += 1
            if r:
                ok += 1
                t, tl = r["timing"], r["tls"]
                R.add("PASS" if t["total_ms"] < 3000 else "WARN", f"HTTPS {host}{sfx}",
                      f"{r['status']} | tcp {t['connect_ms']:.0f} ms, tls {t['tls_ms']:.0f} ms, first byte {t['ttfb_ms']:.0f} ms"
                      f" | {tl['version']} issuer: {tl['issuer']}")
            else:
                if isinstance(e, ssl.SSLCertVerificationError):
                    F["tls_errors"] = F.get("tls_errors", 0) + 1
                R.add("FAIL", f"HTTPS {host}{sfx}", describe_exc(e)
                      + (" - broken IPv6 makes apps hang before falling back to IPv4" if v6 else ""))
        F[fk + "https_ok"] = ok
        F[fk + "https_total"] = tested
        try:
            r = http_request("https://api6.ipify.org?format=json" if v6 else "https://api.ipify.org?format=json",
                             timeout=6, v6=v6)
            ip = json.loads(r["body"]).get("ip")
            F[fk + "public_ip"] = ip
            name = rdns(ip) if ip else None
            R.add("INFO", f"Public {fam}", f"{ip}" + (f"  ({name})" if name else ""))
            if v6 and ip and ip not in [norm6(a) for a in F.get("v6_global_addrs", [])]:
                R.note("(differs from the interface addresses: an IPv6 NAT/proxy is in the path)")
        except HTTP_FAILURES as e:
            R.add("WARN", f"Public {fam} (ipify)", describe_exc(e))
    if F.get("inet_ok"):
        try:
            r = http_request("https://cloudflare-dns.com/dns-query?name=example.com&type=AAAA",
                             headers={"Accept": "application/dns-json"}, timeout=6)
            ans = json.loads(r["body"] or b"{}").get("Answer", [])
            R.add("PASS" if ans else "WARN", "DNS-over-HTTPS (Cloudflare)", f"{r['status']}, example.com AAAA -> "
                  f"{ans[-1]['data'] if ans else 'no answer'}")
        except HTTP_FAILURES as e:
            R.add("WARN", "DNS-over-HTTPS (Cloudflare)", describe_exc(e))


# --------------------------------------------------------------------------- router / WAN info

def xml_leaves(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}
    return {el.tag.split("}")[-1]: (el.text or "").strip() for el in root.iter() if len(el) == 0}


def on_local_subnet(url):
    """UPnP answers can come from any device on the LAN: only follow URLs that stay on this subnet."""
    try:
        return ipaddress.ip_address(urlparse(url).hostname) in ipaddress.ip_interface(F["ipv4_prefix"]).network
    except (KeyError, TypeError, ValueError):
        return False


def upnp_igd(extra_locs=()):
    s = bsock(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(F["ipv4"]))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.5)
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    locs = set(extra_locs)
    try:
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        t_end = time.monotonic() + 3
        while time.monotonic() < t_end:
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m and on_local_subnet(m.group(1).decode(errors="replace")):
                locs.add(m.group(1).decode(errors="replace"))
    finally:
        s.close()
    info = {}
    for loc in locs:
        try:
            r = http_request(loc, timeout=4, max_body=256 * 1024)
            root = ET.fromstring(r["body"])
        except (OSError, NetError, ET.ParseError):
            continue
        base = loc
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag == "URLBase" and el.text:
                base = el.text.strip()
            if tag == "modelName" and el.text and "model" not in info:
                info["model"] = el.text.strip()
            if tag == "manufacturer" and el.text and "manufacturer" not in info:
                info["manufacturer"] = el.text.strip()
        for svc in root.iter():
            if svc.tag.split("}")[-1] != "service":
                continue
            kids = {c.tag.split("}")[-1]: (c.text or "").strip() for c in svc}
            stype, ctrl = kids.get("serviceType", ""), kids.get("controlURL", "")
            if not ctrl:
                continue
            url = urljoin(base, ctrl)
            if not on_local_subnet(url):
                continue
            acts = []
            if "WANIPConnection" in stype or "WANPPPConnection" in stype:
                acts = ["GetStatusInfo", "GetExternalIPAddress"]
            elif "WANCommonInterfaceConfig" in stype:
                acts = ["GetCommonLinkProperties", "GetTotalBytesReceived", "GetTotalBytesSent"]
            elif "WANDSLInterfaceConfig" in stype:
                acts = ["GetInfo"]
            for act in acts:
                body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                        f'<u:{act} xmlns:u="{stype}"/></s:Body></s:Envelope>').encode()
                try:
                    r = http_request(url, method="POST", body=body, timeout=4,
                                     headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#{act}"'})
                    for k, v in xml_leaves(r["body"]).items():
                        if k.startswith("New"):
                            info[k[3:]] = v
                except (OSError, NetError):
                    pass
    return info


HILINK_STATUS = {"900": "connecting", "901": "connected", "902": "disconnected", "903": "disconnecting",
                 "112": "no auto-connect", "113": "roaming auto-connect off", "114": "roaming reconnect off"}
HILINK_NET = {"0": "no service", "1": "GSM", "2": "GPRS", "3": "EDGE", "4": "WCDMA", "5": "HSDPA", "6": "HSUPA",
              "7": "HSPA", "9": "HSPA+", "19": "LTE", "101": "LTE", "1011": "LTE-A (CA)", "111": "5G NSA", "112": "5G SA"}


def _num(v):
    m = re.search(r"-?\d+(\.\d+)?", v or "")
    return float(m.group(0)) if m else None


HILINK_EPS = ("/api/monitoring/status", "/api/device/signal", "/api/net/current-plmn", "/api/pin/status",
              "/api/dialup/mobile-dataswitch", "/api/dialup/connection", "/api/monitoring/traffic-statistics",
              "/api/monitoring/month_statistics", "/api/monitoring/start_date", "/api/monitoring/check-notifications")


def hilink(gw, endpoints=HILINK_EPS):
    """Read-only status pages a Huawei HiLink router serves without a login."""
    r = http_request(f"http://{gw}/api/webserver/SesTokInfo", timeout=3)
    leaves = xml_leaves(r["body"])
    if r["status"] != 200 or "SesInfo" not in leaves:
        return None
    hdr = {"Cookie": leaves["SesInfo"], "__RequestVerificationToken": leaves.get("TokInfo", "")}
    out = {}
    for ep in endpoints:
        try:
            rr = http_request(f"http://{gw}{ep}", headers=hdr, timeout=3)
            lv = xml_leaves(rr["body"])
            out[ep] = {"error": lv.get("code")} if "code" in lv and len(lv) <= 2 else lv
        except (OSError, NetError):
            pass
    return out


def test_router():
    R.section("ROUTER", "ROUTER / WAN STATUS  (what the router itself reports)")
    gw = F.get("gateway")
    if not gw or not F.get("gw_ok"):
        R.add("SKIP", "Router queries", "router not reachable")
        return
    try:
        r = http_request(f"http://{gw}/", timeout=4, max_body=64 * 1024)
        title = re.search(rb"(?is)<title[^>]*>(.*?)</title>", r["body"])
        R.add("INFO", "Router web UI", f"HTTP {r['status']} server='{r['headers'].get('server', '-')}' "
              f"title='{title.group(1).decode(errors='replace').strip()[:60] if title else '-'}'"
              + (f" -> {r['headers']['location']}" if "location" in r["headers"] else ""))
    except (OSError, NetError) as e:
        R.add("INFO", "Router web UI", describe_exc(e))
    if F.get("ipv4"):
        R.progress("UPnP-IGD / TR-064 discovery …")
        extra = []
        if tcp_connect(gw, 49000, 1.5)[0] == "open":     # AVM FRITZ!Box and other TR-064 routers
            extra = [f"http://{gw}:49000/igddesc.xml", f"http://{gw}:49000/tr64desc.xml"]
        try:
            u = upnp_igd(extra)
        except OSError as e:
            u = {}
            R.add("SKIP", "UPnP-IGD", describe_exc(e))
        if u:
            F["upnp"] = u
            st = u.get("ConnectionStatus")
            R.add("FAIL" if st and st != "Connected" else "PASS" if st else "INFO", "UPnP WAN status",
                  f"{u.get('manufacturer', '')} {u.get('model', '')}: connection={st or '?'}, "
                  f"physical={u.get('PhysicalLinkStatus') or '?'}, type={u.get('WANAccessType', '?')}, "
                  f"uptime={u.get('Uptime', '?')} s, last error={u.get('LastConnectionError', '-')}")
            if u.get("Layer1DownstreamMaxBitRate", "").isdigit():
                R.note(f"line rate down {int(u['Layer1DownstreamMaxBitRate']) / 1e6:.1f} Mb/s, "
                       f"up {int(u.get('Layer1UpstreamMaxBitRate', '0') or 0) / 1e6:.1f} Mb/s")
            if u.get("PhysicalLinkStatus") and u["PhysicalLinkStatus"] != "Up":
                F["wan_phys_down"] = u["PhysicalLinkStatus"]
                R.add("FAIL", "WAN physical link", f"router reports '{u['PhysicalLinkStatus']}' - no DSL sync / "
                      "no fibre or cable signal on the router's WAN side")
            if u.get("DownstreamCurrRate"):
                R.add("INFO", "DSL line", f"status {u.get('Status', '?')}, sync down {u.get('DownstreamCurrRate')} / "
                      f"up {u.get('UpstreamCurrRate')} kb/s, noise margin {u.get('DownstreamNoiseMargin', '?')}/"
                      f"{u.get('UpstreamNoiseMargin', '?')} (0.1 dB)")
            if u.get("ExternalIPAddress"):
                wip = u["ExternalIPAddress"]
                F["router_wan_ip"] = wip
                cls = addr_class(wip) if is_ip(wip) else "?"
                R.add("WARN" if cls in ("private", "CGNAT") else "INFO", "Router WAN IP",
                      f"{wip} ({cls})" + (" - the router is behind another NAT (ISP CGNAT or a modem in router mode)"
                                          if cls in ("private", "CGNAT") else ""))
        else:
            R.add("INFO", "UPnP-IGD", "router does not answer UPnP (disabled - fine)")
    try:
        h = hilink(gw)
    except (OSError, NetError):
        h = None
    if h:
        F["hilink"] = h
        ms_ = h.get("/api/monitoring/status", {})
        sig = h.get("/api/device/signal", {})
        plmn = h.get("/api/net/current-plmn", {})
        cs = ms_.get("ConnectionStatus")
        if cs:
            net = ms_.get("CurrentNetworkTypeEx") or ms_.get("CurrentNetworkType")
            R.add("PASS" if cs == "901" else "FAIL", "Mobile (HiLink) connection",
                  f"{HILINK_STATUS.get(cs, cs)}, network {HILINK_NET.get(net, net)}, signal {ms_.get('SignalIcon', '?')}/5, "
                  f"operator {plmn.get('FullName') or plmn.get('ShortName') or '?'}"
                  + (f", WAN ip {ms_.get('WanIPAddress')}" if ms_.get("WanIPAddress") else "")
                  + (f", WAN IPv6 {ms_.get('WanIPv6Address')}" if ms_.get("WanIPv6Address") else ""))
            F["hilink_connected"] = cs == "901"
        elif ms_.get("error"):
            R.add("INFO", "Mobile (HiLink) router", f"Huawei HiLink detected; status needs login (error {ms_['error']})")
        if sig and not sig.get("error") and sig.get("rsrp"):
            rsrp, rsrq, sinr = _num(sig.get("rsrp")), _num(sig.get("rsrq")), _num(sig.get("sinr"))
            bad = []
            if rsrp is not None and rsrp < -105:
                bad.append("RSRP poor")
            if sinr is not None and sinr < 3:
                bad.append("SINR poor")
            if rsrq is not None and rsrq < -15:
                bad.append("RSRQ poor")
            R.add("WARN" if bad else "PASS", "Mobile signal",
                  f"RSRP {sig.get('rsrp')} (>-90 good, <-105 poor), RSRQ {sig.get('rsrq')} (>-10 good), "
                  f"SINR {sig.get('sinr')} (>13 good, <3 poor), RSSI {sig.get('rssi')}, band {sig.get('band', '?')}, "
                  f"cell {sig.get('cell_id', '?')}" + (f" - {', '.join(bad)}: move/aim the router or add an antenna" if bad else ""))
            F["mobile_signal_bad"] = bool(bad)
        elif sig.get("error"):
            R.note("signal details (RSRP/SINR) are only shown in the router's own web UI after login")
        report_hilink_extra(h)
    probe_upstream_devices()


def _bytes(text):
    m = re.match(r"\s*([\d.]+)\s*([KMGT]?)B", text or "", re.I)
    return float(m.group(1)) * 1024 ** "_KMGT".index(m.group(2).upper() or "_") if m else 0


def report_hilink_extra(h):
    pin = h.get("/api/pin/status", {})
    ss = pin.get("SimState")
    if ss:
        F["hilink_sim_bad"] = ss != "257"
        R.add("PASS" if ss == "257" else "FAIL", "SIM card", "ready" if ss == "257" else
              f"not ready (state {ss}: missing SIM, PIN/PUK lock or SIM error) - the router cannot get online")
    ds = h.get("/api/dialup/mobile-dataswitch", {}).get("dataswitch")
    if ds == "0":
        F["hilink_data_off"] = True
        R.add("FAIL", "Mobile data switch", "OFF in the router settings - it will not connect to the internet")
    elif ds == "1":
        R.add("PASS", "Mobile data switch", "on")
    conn = h.get("/api/dialup/connection", {})
    if conn.get("auto_dial_switch") == "0" or conn.get("ConnectMode") not in (None, "0"):
        F["hilink_no_autodial"] = True
        R.add("WARN", "Auto-connect", "off / manual - after a drop the router does not reconnect by itself")
    elif conn:
        R.add("INFO", "Dial-up settings", f"auto-connect on, MTU {conn.get('MTU', '?')}, roaming auto-connect "
              f"{'on' if conn.get('RoamAutoConnectEnable') == '1' else 'off'}")
    ms_ = h.get("/api/monitoring/status", {})
    if ms_.get("EndcStatus") == "1":
        R.add("INFO", "5G NSA (EN-DC)", "active - LTE <-> 5G handovers can cause short stalls or drops")
    ts = h.get("/api/monitoring/traffic-statistics", {})
    ct = ts.get("CurrentConnectTime", "")
    if ct.isdigit():
        secs = int(ct)
        F["wan_session_age"] = secs
        since = datetime.datetime.now() - datetime.timedelta(seconds=secs)
        R.add("WARN" if secs < 3600 else "INFO", "Mobile data session age",
              f"connected for {fmt_dur(secs)} (since {since:%Y-%m-%d %H:%M}) - every WAN reconnect restarts this"
              + (" - it reconnected recently" if secs < 3600 else ""))
        if secs < 3600 and F.get("v6_deprecated_addrs"):
            R.note("this matches the deprecated IPv6 prefix found on L2: the router re-dialled and got a new prefix")
    sd = h.get("/api/monitoring/start_date", {})
    mst = h.get("/api/monitoring/month_statistics", {})
    if mst.get("CurrentMonthDownload", "").isdigit():
        used = int(mst["CurrentMonthDownload"]) + int(mst.get("CurrentMonthUpload", "0") or 0)
        lim = _bytes(sd.get("DataLimit"))
        R.add("INFO", "Data volume this month", f"{used / 1e9:.1f} GB" + (f" of a {sd['DataLimit']} limit set in the router"
              if lim else " (no limit set in the router; the operator may still slow you down after your plan's volume)"))
        if lim and used >= lim:
            if sd.get("turnoffdataenable") == "1":
                F["hilink_limit_off"] = True
                R.add("FAIL", "Data limit", "reached - the router is set to switch mobile data off at the limit")
            else:
                R.add("WARN", "Data limit", "reached the volume limit configured in the router")
        elif lim and used >= lim * 0.9:
            R.add("WARN", "Data limit", "over 90% of the configured volume used")
    ev = h.get("/api/monitoring/check-notifications", {}).get("SimOperEvent")
    if ev and ev != "0":
        R.add("INFO", "SIM/operator event", f"router reports an operator event ({ev}) - check its message inbox")


def probe_upstream_devices():
    """Look for a modem / ONT / upstream router's management page behind the router."""
    gw = F.get("gateway")
    net = ipaddress.ip_interface(F["ipv4_prefix"]).network if F.get("ipv4_prefix") else None
    cands = [ip for ip in MODEM_IPS if ip != gw and not (net and ipaddress.ip_address(ip) in net)]
    res = parallel(lambda ip: (ip, tcp_connect(ip, 80, 1.5)), cands, workers=10)
    found = [ip for ip, (st, _) in res if st == "open"]
    F["upstream_devices"] = found
    if not found:
        R.add("INFO", "Upstream devices", "no modem/ONT/upstream router management page at the usual addresses")
        return
    for ip in found:
        try:
            r = http_request(f"http://{ip}/", timeout=4, max_body=64 * 1024)
            title = re.search(rb"(?is)<title[^>]*>(.*?)</title>", r["body"])
            desc = f"HTTP {r['status']} title '{title.group(1).decode(errors='replace').strip()[:60] if title else '-'}'"
        except HTTP_FAILURES as e:
            desc = describe_exc(e)
        R.add("INFO", f"Upstream device {ip}", f"{desc} - a modem/ONT or second router answers behind your router; "
              "if it still answers while the internet is down, the fault is beyond it")


# --------------------------------------------------------------------------- performance

def transfer(kind, secs, streams, v6=False, url=None, tcp_log=None):
    total = [0]
    lock = threading.Lock()
    samples, errors, loaded = [], [], {}
    start = time.monotonic()
    stop_at = start + secs

    def sink(n):
        with lock:
            total[0] += n

    def worker():
        while time.monotonic() < stop_at:
            try:
                if kind == "down":
                    r = http_request(url or SPEED_DOWN_URL + "50000000", timeout=10,
                                     sink=sink, stop_at=stop_at, v6=v6, tcp_log=tcp_log)
                else:
                    r = http_request(SPEED_UP_URL, method="POST", upload_size=25_000_000,
                                     timeout=10, sink=sink, stop_at=stop_at, v6=v6, tcp_log=tcp_log)
                if r.get("status") and not 200 <= r["status"] < 300:
                    raise NetError(f"speed server answered HTTP {r['status']}")
            except HTTP_FAILURES as e:
                errors.append(describe_exc(e))
                time.sleep(0.5)

    def load_ping():
        loaded["p"] = ping(PUBLIC_V6[0][0] if v6 else REFERENCE_V4, count=max(1, int((secs - 2) / 0.2)), interval=0.2, v6=v6)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(streams)]
    pt = threading.Thread(target=load_ping, daemon=True)
    for t in threads:
        t.start()
    time.sleep(1.5)
    pt.start()
    last = (time.monotonic(), 0)
    while time.monotonic() < stop_at:
        time.sleep(1)
        now = time.monotonic()
        with lock:
            cur = total[0]
        samples.append((cur - last[1]) * 8 / (now - last[0]) / 1e6)
        last = (now, cur)
    for t in threads:
        t.join(timeout=12)
    pt.join(timeout=15)
    return total[0] * 8 / (time.monotonic() - start) / 1e6, samples, loaded.get("p"), errors


def rate_limit_note(label, samples):
    """A short burst followed by a flat line is what a token-bucket rate limit looks like."""
    body = samples[1:-1]        # the last sample is a partial second
    if len(body) < 5:
        return
    med = statistics.median(body)
    if med > 0 and samples[0] >= med * 1.4 and statistics.pstdev(body) / med <= 0.15:
        R.add("INFO", f"{label} pattern", f"burst of {samples[0]:.0f} Mb/s, then flat at about {med:.0f} Mb/s - typical of "
              "a rate limit (ISP plan, router QoS or the test server)")


def test_performance():
    R.section("PERF", "PERFORMANCE  (throughput, latency under load)")
    if not F.get("https_ok"):
        R.add("SKIP", "Throughput", "HTTPS over IPv4 is not working")
        return
    idle = ping(REFERENCE_V4, count=10, interval=0.2)
    F["idle_rtt"] = idle["avg"]
    R.add("INFO", "Idle latency 1.1.1.1", ping_summary(idle))
    secs = 8 if ARGS.quick else 12
    for kind, streams in (("down", 4), ("up", 3)):
        label = "Download" if kind == "down" else "Upload"
        R.progress(f"{label.lower()} test, {streams} streams, {secs} s …")
        tcp_log, counters = [], kernel_net_counters()
        mbps, samples, lp, errors = transfer(kind, secs, streams, tcp_log=tcp_log)
        F[f"{kind}_mbps"] = mbps
        if mbps < 0.1:
            R.add("FAIL", label, "no data transferred" + (f" ({errors[0]})" if errors else ""))
            continue
        peak = max(samples) if samples else mbps
        worst = min(samples[1:]) if len(samples) > 2 else mbps
        R.add("PASS" if mbps > 5 else "WARN", label, f"{mbps:.1f} Mb/s average, {peak:.1f} peak, {worst:.1f} worst second"
              + (f"; {len(errors)} stream errors ({errors[0]})" if errors else ""))
        R.note("per second: " + " ".join(f"{s:.0f}" for s in samples))
        rate_limit_note(label, samples)
        report_tcp_health(kind, tcp_log, counters)
        if lp and idle["rx"] and lp["loss"] >= 2:
            F["loss_under_load"] = max(F.get("loss_under_load", 0), lp["loss"])
            R.add("WARN", f"Loss under {label.lower()} load", f"{lp['loss']:.0f}% of pings lost while the line is busy "
                  f"(idle loss {idle['loss']:.0f}%) - something on the path drops packets when busy "
                  "(congested link or a rate limiter)")
        if lp and lp["avg"] and idle["avg"]:
            inc = lp["avg"] - idle["avg"]
            F[f"bloat_{kind}"] = inc
            grade = "A" if inc < 20 else "B" if inc < 60 else "C" if inc < 150 else "D" if inc < 400 else "F"
            lossy = lp["loss"] >= 10
            R.add("PASS" if grade in "AB" and not lossy else "WARN", f"Latency under {label.lower()} load",
                  f"{fmt_ms(lp['avg'])} ms (+{inc:.0f} ms vs idle, loss {lp['loss']:.0f}%) bufferbloat grade {grade}"
                  + (" - queues fill up; enable SQM/QoS on the router" if grade not in "AB" else "")
                  + (" - optimistic: only pings that survived are timed" if lossy else ""))
    if F.get("v6_https_ok"):
        R.progress("IPv6 download test, 2 streams, 6 s …")
        mbps, samples, _, errors = transfer("down", 6, 2, v6=True)
        F["v6_down_mbps"] = mbps
        ref = F.get("down_mbps") or 0
        st = "FAIL" if mbps < 0.1 else "WARN" if ref and mbps < ref * 0.4 else "PASS"
        R.add(st, "Download over IPv6", f"{mbps:.1f} Mb/s" + (f" (IPv4 {ref:.1f} Mb/s with 4 streams)" if ref else "")
              + (" - IPv6 path is much slower than IPv4" if st == "WARN" else "") + (f" ({errors[0]})" if errors and st == "FAIL" else ""))
    ls = F.get("link_speed")
    if ls and F.get("down_mbps") and F["down_mbps"] > ls * 0.85:
        R.add("INFO", "Bottleneck", f"download is near the {ls} Mb/s link speed - the LAN link is the limit")
    w = wifi_link() if F.get("iface_kind") == "wifi" else {}
    if w.get("rx_rate") and w.get("tx_rate") and F.get("down_mbps"):
        used = max(F["down_mbps"] / w["rx_rate"], (F.get("up_mbps") or 0) / w["tx_rate"])
        if used >= 0.5:
            R.add("INFO", "Bottleneck", f"throughput is near what the Wi-Fi radio can carry (rx {w['rx_rate']:.0f} / tx "
                  f"{w['tx_rate']:.0f} Mb/s negotiated) - the radio is probably the limit")
        elif used < 0.2:
            R.add("INFO", "Bottleneck", f"not the Wi-Fi radio: it negotiated rx {w['rx_rate']:.0f} / tx {w['tx_rate']:.0f} "
                  "Mb/s, far above the measured throughput - the limit is further along the path")
    if F.get("usb_speed") == 480 and F.get("down_mbps", 0) > 250:
        R.add("INFO", "Bottleneck", "close to the USB 2.0 ceiling - use a USB 3 port for more")


# --------------------------------------------------------------------------- comparison with another link

def link_snapshot():
    """Compact reachability measurement over the current IFACE."""
    gw = next((r.get("gateway") for r in ipj("route", "show", "default") if r.get("dev") == IFACE), None)
    gw6 = next((r.get("gateway") for r in ipj("-6", "route", "show", "default") if r.get("dev") == IFACE), None)
    jobs = {"router": (gw, False), "router6": (gw6, True), "1.1.1.1": ("1.1.1.1", False),
            "8.8.8.8": ("8.8.8.8", False), "IPv6 2606:4700:4700::1111": ("2606:4700:4700::1111", True)}
    pings = dict(parallel(lambda kv: (kv[0], ping(kv[1][0], count=10, interval=0.1, v6=kv[1][1]) if kv[1][0] else None),
                          jobs.items()))
    out = {"gateway": gw, "pings": pings}
    try:
        out["dns_ms"] = dns_query(REFERENCE_V4, "example.com", timeout=2)["ms"]
    except DNS_ERRORS:
        out["dns_ms"] = None
    try:
        out["https_ms"] = http_request("https://www.google.com/", timeout=8, max_body=4096)["timing"]["total_ms"]
    except HTTP_FAILURES:
        out["https_ms"] = None
    return out


def compare_interfaces(spec):
    global IFACE, IFINDEX
    main = IFACE
    other = spec
    if spec == "auto":
        cands = [r.get("dev") for r in F.get("all_default_routes", []) if r.get("dev") != main]
        other = cands[0] if cands else None
    R.section("CMP", f"COMPARISON  ({main} vs {other or '?'})")
    if not other or other not in os.listdir("/sys/class/net") or other == main:
        R.add("SKIP", "Comparison", "no other usable interface (connect Wi-Fi or a phone hotspot, or name one with --compare IFACE)")
        return
    R.progress(f"measuring the same targets over {main} and over {other} …")
    a = link_snapshot()
    IFACE, IFINDEX = other, socket.if_nametoindex(other)
    try:
        b = link_snapshot()
    finally:
        IFACE, IFINDEX = main, socket.if_nametoindex(main)

    def cell(p):
        if p is None:
            return "-"
        return f"{p['loss']:.0f}% loss" + (f", {fmt_ms(p['avg'])} ms" if p["avg"] else "")

    R.note(f"{'':<28} {main:<26} {other:<26}")
    for k in a["pings"]:
        R.note(f"{k:<28} {cell(a['pings'][k]):<26} {cell(b['pings'][k]):<26}")
    for k, label in (("dns_ms", "DNS 1.1.1.1"), ("https_ms", "HTTPS www.google.com")):
        R.note(f"{label:<28} {(fmt_ms(a[k]) + ' ms') if a[k] else 'fail':<26} {(fmt_ms(b[k]) + ' ms') if b[k] else 'fail':<26}")

    def inet(x):
        return any(x["pings"][t] and x["pings"][t]["rx"] for t in ("1.1.1.1", "8.8.8.8")) or bool(x["https_ms"])

    def loss(x):
        return mean([x["pings"][t]["loss"] for t in ("1.1.1.1", "8.8.8.8") if x["pings"][t]]) or 0

    same = a["gateway"] and a["gateway"] == b["gateway"]
    via = f" (both use router {a['gateway']})" if same else ""
    if not inet(a) and not inet(b):
        v, st = f"both links fail{via} - the problem is upstream of the computer: router / WAN / ISP", "FAIL"
    elif not inet(a):
        v, st = (f"only {main} fails, {other} works{via} - the problem is on the {main} side: its adapter, cable or "
                 "radio, the router port, or that link's configuration"), "FAIL"
    elif not inet(b):
        v, st = f"{main} works, only {other} fails - the tested path is fine", "INFO"
    elif loss(a) > loss(b) + 5:
        v, st = f"{main} loses more ({loss(a):.0f}% vs {loss(b):.0f}%) - look at that link and its adapter", "WARN"
    elif same:
        v, st = f"both behave alike{via} - any remaining problem is shared: router/WAN/ISP, not this link", "INFO"
    else:
        v, st = "both links work", "PASS"
    F["comparison"] = {"other": other, "verdict": v, "main": a, "other_result": b}
    R.add(st, "Comparison result", v)


# --------------------------------------------------------------------------- final counters & verdict

def counters_delta():
    if "stats_start" not in F:
        return
    R.section("L1-POST", "L1  ERROR COUNTERS DURING THE TEST")
    a, b = F["stats_start"], read_stats()
    d = {k: b[k] - a[k] for k in STAT_KEYS}
    F["stats_delta"] = d
    R.add("INFO", "Traffic during test", f"rx {d['rx_packets']} pkts, tx {d['tx_packets']} pkts, rx_dropped +{d['rx_dropped']}")
    bad = {k: d[k] for k in SERIOUS_STATS if d.get(k)}
    if bad:
        F["phy_errors_live"] = True
        R.add("FAIL", "New errors during test", ", ".join(f"{k}+{v}" for k, v in bad.items()) +
              (" - radio errors right now: check for interference or move closer to the access point" if F.get("iface_kind") == "wifi"
               else " - errors on the wire right now: replace the cable / try another router port / another adapter"))
    else:
        R.add("PASS", "New errors during test", "none")
    cc = sysread(f"/sys/class/net/{IFACE}/carrier_changes")
    if cc is not None and F.get("carrier_changes") is not None and int(cc) > F["carrier_changes"]:
        F["link_flaps_live"] = F.get("link_flaps_live", 0) + int(cc) - F["carrier_changes"]
        R.add("FAIL", "Link flaps during test", f"{int(cc) - F['carrier_changes']} carrier changes while testing")


ADVICE = {
    "Adapter & driver": "Check the driver messages in `dmesg -w`. For a USB adapter, re-plug it (another USB port, "
                            "no hub), check `lsusb`, try another adapter.",
    "Wi-Fi link (radio)": "Move closer to the access point or hotspot, check for interference or a crowded channel, "
                          "forget and re-join the network. Use a cable to tell the Wi-Fi apart from the uplink.",
    "Physical link": "Check that the interface is connected and configured (VPN, modem or tunnel up).",
    "Physical link (cable/port)": "Swap the Ethernet cable, try another LAN port on the router, check port LEDs. "
                                  "Speed drops / CRC errors / flapping almost always mean cable or connector.",
    "LAN data link (DHCP/ARP)": "On a wired link make sure the cable goes to a LAN port (not WAN) and power-cycle the router. For a conflict, "
                                "find the device with the MAC shown above (device table / router client list) and give it "
                                "another address; switch off any second router/DHCP server; remove loops (a switch "
                                "connected twice, powerline/mesh units bridging the same LAN).",
    "Router / LAN IP": "The computer has no working IP path to the router: renew DHCP (`nmcli device reapply IFACE`), "
                       "check router DHCP settings, reboot the router.",
    "WAN uplink (router -> ISP)": "The router is fine but its uplink is not: check the router's WAN/Internet LED and "
                                  "status page (DSL sync, LTE signal, fibre ONT light, PPPoE login), reboot modem/ONT, "
                                  "then call the ISP with the hop/loss data in this report.",
    "Internet routing": "Traffic leaves the house but is lost further away: ISP routing / peering problem. Give the "
                        "traceroute table to the ISP.",
    "DNS": "Names fail although IPs work: set DNS manually to 1.1.1.1 / 8.8.8.8 (router or computer) or reboot the router.",
    "TCP / HTTP(S)": "IP works but connections/HTTPS fail: check router firewall/parental filters, MTU/MSS clamping "
                     "(PPPoE/LTE), proxies, and the computer clock.",
    "Performance & stability": "The link works but is slow or bloated: compare with the plan's speed, enable SQM/QoS "
                               "on the router, check LTE signal / line sync rate; run --monitor to catch drops.",
    "IPv6 router (RA/NDP)": "The router's IPv6 side: check that IPv6 is enabled in the router (LAN and WAN/APN type "
                            "IPv4v6), remove any second router that sends RAs, reboot the router.",
    "IPv6 addressing": "Addresses are not configured correctly: check the interface's IPv6 method in NetworkManager "
                       "(automatic), look for duplicate addresses, and whether the router's DHCPv6 is required but off.",
    "IPv6 prefix from ISP": "Check the router's WAN IPv6 status (APN/PDP type IPv4v6 on LTE, DHCPv6-PD on cable/fibre). "
                            "If the ISP offers no IPv6, this is expected; otherwise reboot the router or ask the ISP.",
    "IPv6 router reachability":"The IPv6 router does not answer reliably: reboot the router; check the layers above.",
    "IPv6 internet": "The local IPv6 network works but public addresses do not answer. Usually the ISP/APN gives no "
                     "working IPv6 or the router drops it: check the router's WAN IPv6 status and firewall (APN type "
                     "IPv4v6 on mobile links). Until fixed, disabling IPv6 on the router avoids slow fallbacks in apps.",
    "IPv6 DNS": "IPv6 DNS servers do not answer: use public ones (2606:4700:4700::1111) or rely on IPv4 DNS.",
    "IPv6 TCP / HTTPS": "IPv6 pings work but connections fail: firewall or MTU problem on the IPv6 path; apps will stall "
                        "before falling back to IPv4. Disable IPv6 on the router until the ISP fixes it.",
}


def v4_ladder():
    rows = []

    def row(name, status, why):
        rows.append((name, status, why))

    if not F.get("iface_found"):
        row("Adapter & driver", "FAIL", "no network interface found")
        return rows
    phys = ("Wi-Fi link (radio)" if F.get("iface_kind") == "wifi" else
            "Physical link (cable/port)" if F.get("iface_kind") in WIRED_KINDS else "Physical link")
    if F.get("usb_speed") and F["usb_speed"] <= 12:
        row("Adapter & driver", "FAIL", "adapter runs at USB 1.1 speed")
    elif F.get("link_cause") == "adapter":
        row("Adapter & driver", "FAIL", "the far end negotiates but this adapter never brings the link up, "
            "not even at 100 Mb/s - adapter chip/driver (cable probably fine)")
    elif F.get("generic_driver") and F.get("link_state") == "carrier-only" and F.get("driver_suspect") == "proven":
        row("Adapter & driver", "FAIL", f"the adapter passes data over USB but the generic {F['generic_driver']} "
            "driver delivers no frames - the driver, not the cable")
    elif F.get("generic_driver") and F.get("link_state") == "carrier-only" and F.get("driver_suspect"):
        row("Adapter & driver", "WARN", f"vendor chip on the generic {F['generic_driver']} driver - could be why "
            "nothing is received, but a silent far end looks identical (--fix-driver rules it out)")
    elif F.get("generic_driver") and F.get("driver_rx_history"):
        row("Adapter & driver", "PASS", f"{IFACE} via the generic {F['generic_driver']} driver - it received "
            f"frames on this adapter before ({F['driver_rx_history']})")
    elif F.get("generic_driver"):
        row("Adapter & driver", "WARN", f"vendor chip on the generic {F['generic_driver']} driver "
            f"({F.get('driver_info', {}).get('module')} is preferred)")
    elif F.get("klog_errors"):
        row("Adapter & driver", "WARN", f"{F['klog_errors']} reset/error lines in the kernel log")
    else:
        row("Adapter & driver", "PASS", f"{IFACE} via {F.get('driver')}"
            + (" (switched by --fix-driver)" if F.get("driver_fixed") else ""))
    wifi = F.get("iface_kind") == "wifi"
    past_flaps = not wifi and (F.get("carrier_changes") or 0) > 2
    if not F.get("admin_up"):
        row(phys, "FAIL", "interface administratively down")
    elif not F.get("carrier") and F.get("link_cause") == "adapter":
        row(phys, "WARN", "far end negotiates on the cable (10/100 pairs work) - but see the adapter row")
    elif not F.get("carrier") and F.get("link_state") == "negotiated-no-link":
        row(phys, "FAIL", "far end negotiates but the gigabit link never comes up"
            + (" - broken wire pair in the cable/port (works at 100 Mb/s)" if F.get("link_cause") == "pair"
               else " - broken pair, bad port or adapter (run as root to tell apart)"))
    elif not F.get("carrier"):
        row(phys, "FAIL", "not associated with an access point" if wifi else
            "no link - cable unplugged/broken, other end off or its port dead")
    elif F.get("link_state") == "carrier-only":
        row(phys, "FAIL" if ROOT else "WARN",
            "associated but no frames arrive from the access point" if wifi else
            "carrier up but no frames arrive from the other side (far device silent - e.g. WAN down -, hung, "
            "passive, or its port blocks traffic)")
    elif F.get("link_flaps_live") or F.get("half_duplex") or F.get("phy_errors_live"):
        row(phys, "FAIL", "Wi-Fi connection dropped during the test" if wifi else
            "link flapping / half duplex / errors during the test")
    elif F.get("link_degraded") or F.get("phy_errors") or past_flaps:
        row(phys, "WARN",
            "; ".join(x for x in (F.get("link_degraded") and f"degraded speed {F['link_degraded']}",
                                  F.get("phy_errors") and "historic error counters",
                                  past_flaps and f"{F['carrier_changes']} past carrier changes") if x))
    elif wifi:
        sig = (F.get("wifi") or {}).get("signal")
        row(phys, "WARN" if F.get("wifi_weak") else "PASS", ("weak signal, " if F.get("wifi_weak") else "")
            + "associated" + (f" at {sig} dBm" if sig is not None else "") + ", no drops during the test")
    else:
        row(phys, "PASS", f"{F.get('link_speed') or '?'} Mb/s, clean")
    if not (F.get("carrier") and F.get("admin_up")):
        return rows
    if F.get("bcast_storm") == "FAIL":
        row("LAN data link (DHCP/ARP)", "FAIL", "broadcast storm on the LAN (switching loop)")
    elif F.get("ip_conflict"):
        row("LAN data link (DHCP/ARP)", "FAIL", "IP address conflict on the LAN")
    elif F.get("gw_arp") is False:
        row("LAN data link (DHCP/ARP)", "FAIL", "router does not answer ARP")
    elif F.get("dhcp_offers") == 0 and not F.get("ipv4"):
        row("LAN data link (DHCP/ARP)", "FAIL", "no DHCP server answers and no address configured")
    else:
        issues = [x for x in (
            F.get("dhcp_offers") == 0 and "DHCP server did not answer the probe (existing lease still works)",
            F.get("dhcp_multi") and f"several DHCP servers: {', '.join(F['dhcp_multi'])}",
            F.get("dhcp_pool_issue") and "DHCP gives no address to new devices",
            F.get("dhcp_unicast_issue") and "DHCP ignores clients without the broadcast flag",
            F.get("proxy_arp") and f"proxy ARP by {F['proxy_arp']}",
            F.get("bcast_storm") == "WARN" and "high broadcast level") if x]
        if issues:
            row("LAN data link (DHCP/ARP)", "WARN", "; ".join(issues))
        elif F.get("gw_arp") is None and not ROOT:
            row("LAN data link (DHCP/ARP)", "SKIP", "not tested (needs root)")
        else:
            row("LAN data link (DHCP/ARP)", "PASS", ("DHCP answers correctly, " if F.get("dhcp_offers") else
                                                     "DHCP not probed, ") + "router resolves via ARP, no conflicts")
    gp = F.get("gw_ping")
    if not F.get("ipv4") or F.get("apipa"):
        row("Router / LAN IP", "FAIL", "no valid IPv4 address")
    elif not F.get("gateway"):
        row("Router / LAN IP", "FAIL", "no gateway")
    elif not F.get("gw_ok"):
        row("Router / LAN IP", "FAIL", f"router {F['gateway']} unreachable")
    elif gp and (gp["loss"] >= 1 or (F.get("gw_burst") and F["gw_burst"]["loss"] >= 1)):
        row("Router / LAN IP", "WARN", f"packet loss to the router ({gp['loss']:.0f}% / burst "
            f"{F.get('gw_burst', {}).get('loss', 0):.0f}%) - local link or overloaded router")
    elif gp and gp["avg"] and gp["avg"] > 5:
        row("Router / LAN IP", "WARN", f"slow router responses ({gp['avg']:.1f} ms)")
    else:
        row("Router / LAN IP", "PASS", f"router {F['gateway']} " + (f"{fmt_ms(gp['avg'])} ms, 0% loss" if gp and gp["rx"] else "reachable"))
    if not F.get("gw_ok"):
        return rows
    wp = F.get("wan_hop_ping")
    onset = F.get("trace_loss_onset")
    if not F.get("default_route"):
        row("WAN uplink (router -> ISP)", "FAIL", f"no default route via {IFACE}")
        return rows
    cause = next((t for c, t in (
        (F.get("hilink_sim_bad"), "the mobile router's SIM card is not ready"),
        (F.get("hilink_data_off"), "mobile data is switched off in the router"),
        (F.get("hilink_limit_off"), "the router switched mobile data off at its volume limit"),
        (F.get("wan_phys_down"), f"the router reports its WAN physical link as '{F.get('wan_phys_down')}'"),
        (F.get("router_no_route"), "the router says it has no route to the internet - its WAN / data session is down"),
    ) if c), None)
    if cause and not F.get("inet_ok"):
        row("WAN uplink (router -> ISP)", "FAIL", cause)
    elif not F.get("inet_ok") and (F.get("trace_stop_hop") == 1 or not F.get("wan_hop")):
        row("WAN uplink (router -> ISP)", "FAIL", "router reachable but nothing beyond it answers"
            + ("; its DNS answers SERVFAIL (alive, but no upstream)" if F.get("router_dns_servfail") else ""))
    elif F.get("upnp", {}).get("ConnectionStatus") not in (None, "Connected"):
        row("WAN uplink (router -> ISP)", "FAIL", f"router reports WAN '{F['upnp']['ConnectionStatus']}'")
    elif F.get("hilink_connected") is False:
        row("WAN uplink (router -> ISP)", "FAIL", "mobile router reports it is not connected")
    elif (wp and wp["rx"] and wp["loss"] >= 2) or (onset and 1 < onset <= 3):
        row("WAN uplink (router -> ISP)", "WARN", "packet loss starts on the router's uplink"
            + (f" (ISP edge loss {wp['loss']:.0f}%)" if wp and wp["rx"] else f" (hop {onset})"))
    elif F.get("mobile_signal_bad"):
        row("WAN uplink (router -> ISP)", "WARN", "mobile signal quality is poor")
    elif F.get("inet_ok") and (F.get("wan_session_age") or 1e9) < 3600:
        row("WAN uplink (router -> ISP)", "WARN", f"works, but the WAN session is only {fmt_dur(F['wan_session_age'])} "
            "old - it reconnected recently (run --monitor to catch the next drop)")
    elif F.get("hilink_no_autodial"):
        row("WAN uplink (router -> ISP)", "WARN", "router auto-connect is off - it stays offline after any drop")
    elif F.get("inet_ok"):
        row("WAN uplink (router -> ISP)", "PASS", "ISP edge reachable" + (f" ({F['wan_hop']})" if F.get("wan_hop") else ""))
    else:
        row("WAN uplink (router -> ISP)", "WARN", "first ISP hops answer but the internet does not")
    if not F.get("inet_ok"):
        row("Internet routing", "FAIL", "no public IP answers" + (f"; path dies after hop {F['trace_stop_hop']}"
                                                                    if (F.get("trace_stop_hop") or 0) > 1 else ""))
        return rows
    if F.get("icmp_filtered"):
        row("Internet routing", "WARN", "ping is filtered, but TCP reaches the internet")
    elif F.get("diverse_total") and F.get("diverse_ok", 0) < F["diverse_total"]:
        row("Internet routing", "WARN", f"{F['diverse_total'] - F['diverse_ok']} of {F['diverse_total']} distant "
            "destinations unreachable - ISP upstream/peering problem")
    elif onset and onset > 3:
        row("Internet routing", "WARN", f"persistent loss starts at hop {onset}")
    elif not F.get("inet_all_ok") or (F.get("inet_loss") or 0) >= 2:
        row("Internet routing", "WARN", f"average loss to public IPs {F.get('inet_loss', 0):.1f}%")
    else:
        row("Internet routing", "PASS", f"public IPs reachable, loss {F.get('inet_loss', 0):.1f}%")
    if "dns_ok" in F:
        if not F.get("dns4_working") and not F.get("dns_working"):
            row("DNS", "FAIL", "no resolver answers")
        elif F.get("dns_local4") and not [s for s in F["dns_local4"] if s in F.get("dns_working", [])]:
            row("DNS", "WARN", "router/ISP DNS broken, public DNS works")
        elif F.get("dns_hijack"):
            row("DNS", "WARN", f"NXDOMAIN hijacking at {F['dns_hijack']}")
        else:
            row("DNS", "PASS", f"working: {', '.join(F.get('dns4_working', [])) or ', '.join(F['dns_working'])}")
    if F.get("tcp_ok") is False:
        row("TCP / HTTP(S)", "FAIL", "TCP connections fail although ping works")
    elif F.get("https_total") and F.get("https_ok") == 0:
        row("TCP / HTTP(S)", "FAIL", "all HTTPS sites fail" + (" (certificate errors - check clock / interception)"
                                                              if F.get("tls_errors") else ""))
    elif F.get("captive"):
        row("TCP / HTTP(S)", "WARN", f"HTTP is redirected to {F['captive']}")
    elif F.get("https_total") and F.get("https_ok", 0) < F["https_total"]:
        row("TCP / HTTP(S)", "WARN", f"{F['https_total'] - F['https_ok']} of {F['https_total']} HTTPS sites failed")
    elif F.get("mss_unclamped"):
        row("TCP / HTTP(S)", "WARN", f"path MTU {F.get('pmtu')} and the router does not clamp TCP MSS - large transfers stall")
    elif F.get("pmtu_blackhole") and not F.get("mss_ok"):
        row("TCP / HTTP(S)", "WARN", f"path MTU {F.get('pmtu')} without ICMP signalling (black hole risk)")
    elif abs(F.get("clock_offset") or 0) > 60:
        row("TCP / HTTP(S)", "WARN", f"system clock off by {F['clock_offset']:.0f} s")
    elif F.get("https_ok") is not None:
        row("TCP / HTTP(S)", "PASS", f"{F['https_ok']}/{F['https_total']} HTTPS sites OK")
    if "down_mbps" in F:
        bloat = max(F.get("bloat_down") or 0, F.get("bloat_up") or 0)
        txt = f"down {F['down_mbps']:.1f} / up {F.get('up_mbps', 0):.1f} Mb/s, +{bloat:.0f} ms under load" + (
            f", {F['loss_under_load']:.0f}% loss under load" if F.get("loss_under_load") else "")
        row("Performance & stability", "WARN" if bloat > 60 or F["down_mbps"] < 5 or F.get("loss_under_load") else "PASS", txt)
    return rows


def v6_ladder():
    rows = []

    def row(name, status, why):
        rows.append((name, status, why))

    if not (F.get("carrier") and F.get("admin_up")) or "v6" not in F:
        return rows
    if F["v6"] == "disabled":
        row("IPv6 on this interface", "INFO", "disabled")
        return rows
    if F.get("link_state") == "carrier-only":
        row("IPv6 router (RA/NDP)", "SKIP", "not judged - no frames at all arrive on this link (see IPv4 / link)")
        return rows
    ras = F.get("v6_ras")
    if F.get("v6_router_absent") and not F.get("v6_global_addrs"):
        row("IPv6 router (RA/NDP)", "INFO", "the router does not offer IPv6 on the LAN")
        return rows
    if F.get("v6_gw_ndp") is False:
        row("IPv6 router (RA/NDP)", "FAIL", "router does not answer neighbor solicitation")
    elif F.get("v6_ra_lifetime0") and not [r for r in ras or [] if r["lifetime"]]:
        row("IPv6 router (RA/NDP)", "FAIL", "router advertises lifetime 0: it has no IPv6 upstream")
    elif F.get("v6_ra_multi"):
        row("IPv6 router (RA/NDP)", "WARN", f"{len(F['v6_ra_multi'])} routers send RAs (rogue/second router)")
    elif ras:
        row("IPv6 router (RA/NDP)", "PASS", f"router advertises (M={int(F.get('v6_M'))} O={int(F.get('v6_O'))})")
    elif F.get("gateway6"):
        row("IPv6 router (RA/NDP)", "PASS" if ROOT else "SKIP", f"default route via {F['gateway6']}"
            + ("" if ROOT else " (RA not inspected - needs root)"))
    if F.get("v6_dadfailed") or F.get("v6_dup"):
        row("IPv6 addressing", "FAIL", "duplicate IPv6 address")
    elif F.get("v6_slaac_fail"):
        row("IPv6 addressing", "FAIL", f"no address from advertised prefix {F['v6_slaac_fail']}")
    elif F.get("v6_dhcp6_missing") and not F.get("v6_global_addrs"):
        row("IPv6 addressing", "FAIL", "M flag set but no DHCPv6 server answers")
    elif not F.get("v6_global_addrs"):
        if F.get("v6_no_global_prefix") or F.get("v6_ula_addrs"):
            row("IPv6 prefix from ISP", "FAIL", "the router runs IPv6 on the LAN but has no global prefix "
                "(its IPv6 WAN does not work or the ISP/APN provides none)")
        else:
            row("IPv6 addressing", "INFO", "no global IPv6 address")
        return rows
    elif F.get("v6_dhcp_multi"):
        row("IPv6 addressing", "WARN", "several DHCPv6 servers answer")
    elif F.get("v6_deprecated"):
        row("IPv6 addressing", "WARN", "the router is withdrawing an advertised prefix")
    else:
        row("IPv6 addressing", "PASS", f"{len(F['v6_global_addrs'])} global address(es)")
    gp = F.get("v6_gw_ping")
    if gp:
        if not gp["rx"]:
            row("IPv6 router reachability", "FAIL", f"{F['gateway6']} does not answer ping")
        elif gp["loss"] >= 1:
            row("IPv6 router reachability", "WARN", f"{gp['loss']:.0f}% loss")
        else:
            row("IPv6 router reachability", "PASS", f"{fmt_ms(gp['avg'])} ms, 0% loss")
    if not F.get("default_route6"):
        row("IPv6 internet", "FAIL", "no IPv6 default route")
        return rows
    if not F.get("v6_inet_ok"):
        row("IPv6 internet", "FAIL", "no public IPv6 address answers"
            + (" - the router reports it has no IPv6 route" if F.get("v6_router_no_route") else
               " - stops at the router" if F.get("v6_trace_stop_hop") == 1 else
               " (run as root to trace where it stops)" if not ROOT else ""))
        return rows
    onset = F.get("v6_trace_loss_onset")
    if F.get("v6_icmp_filtered"):
        row("IPv6 internet", "WARN", "ping is filtered, but TCP over IPv6 works")
    elif onset or (F.get("v6_inet_loss") or 0) >= 2:
        row("IPv6 internet", "WARN", f"loss {F.get('v6_inet_loss', 0):.1f}%" + (f", starts at hop {onset}" if onset else ""))
    else:
        row("IPv6 internet", "PASS", f"public IPv6 reachable, loss {F.get('v6_inet_loss', 0):.1f}%")
    if "dns_ok" in F:
        if F.get("dns6_working"):
            row("IPv6 DNS", "PASS", f"working over IPv6: {', '.join(F['dns6_working'])}")
        else:
            row("IPv6 DNS", "WARN", "no resolver answers over IPv6 (IPv4 DNS still serves AAAA)")
    if F.get("v6_tcp_ok") is False:
        row("IPv6 TCP / HTTPS", "FAIL", "TCP over IPv6 fails although ping works")
    elif F.get("v6_https_total") and not F.get("v6_https_ok"):
        row("IPv6 TCP / HTTPS", "FAIL", "all HTTPS sites fail over IPv6")
    elif F.get("v6_https_total") and F["v6_https_ok"] < F["v6_https_total"]:
        row("IPv6 TCP / HTTPS", "WARN", f"{F['v6_https_total'] - F['v6_https_ok']} of {F['v6_https_total']} sites fail over IPv6")
    elif F.get("v6_mss_unclamped"):
        row("IPv6 TCP / HTTPS", "WARN", f"IPv6 path MTU {F.get('v6_pmtu')} and TCP MSS is not clamped - large transfers stall")
    elif F.get("v6_pmtu_blackhole") and not F.get("v6_mss_ok"):
        row("IPv6 TCP / HTTPS", "WARN", f"IPv6 path MTU {F.get('v6_pmtu')} without signalling")
    elif F.get("v6_https_total"):
        row("IPv6 TCP / HTTPS", "PASS", f"{F['v6_https_ok']}/{F['v6_https_total']} HTTPS sites OK over IPv6")
    return rows


def verdict():
    R.section("SUM", "DIAGNOSIS")
    rows4, rows6 = v4_ladder(), v6_ladder()

    def show(rows):
        for name, st, why in rows:
            why = clean(why)
            F["diagnosis_failed"] = F.get("diagnosis_failed") or st == "FAIL"
            R._emit(Color.c(STATUS_COLOR[st], f"  [{st:<4}] ") + f"{name:<30} {why}", f"  [{st:<4}] {name:<30} {why}")

    R.note("IPv4 / link:")
    show(rows4)
    if rows6:
        R.note("IPv6:")
        show(rows6)
    F["ladder"], F["ladder6"] = rows4, rows6
    fails4 = [r for r in rows4 if r[1] == "FAIL"]
    fails6 = [r for r in rows6 if r[1] == "FAIL"]
    warns = [r for r in rows4 + rows6 if r[1] == "WARN"]
    print()
    R.text.append("")

    def headline(text, color):
        text = clean(text)
        R._emit(Color.c(color, "  >>> " + text), "  >>> " + text)

    if fails4:
        name, _, why = fails4[0]
        headline(f"MOST LIKELY PROBLEM: {name.upper()} - {why}", "31;1")
        R.note("Layers listed above it passed; everything after it depends on it, so fix this first.")
        R.note("What to do: " + ADVICE.get(name, "").replace("IFACE", IFACE or "IFACE"))
        if name == "Adapter & driver" and F.get("generic_driver"):
            R.note("  " + (f"Try the vendor driver:  sudo python3 {sys.argv[0]} --fix-driver" if F.get("driver_fixable")
                           else "The firmware offers no vendor-driver interface: try a newer kernel or another adapter."))
        elif F.get("driver_suspect") == "possible" and F.get("driver_fixable"):
            R.note(f"  To rule out the generic driver:  sudo python3 {sys.argv[0]} --fix-driver")
    if fails6:
        name, _, why = fails6[0]
        headline(("IPv4 works, but IPv6 is broken: " if not fails4 else "Also IPv6: ") + f"{name.upper()} - {why}", "31;1")
        R.note("What to do: " + ADVICE.get(name, ""))
        if not fails4:
            R.note("Broken IPv6 often looks like 'slow or randomly hanging internet', because apps try IPv6 first.")
    if not fails4 and not fails6:
        if warns:
            headline("No hard failure right now. Issues found:", "33;1")
            for name, _, why in warns:
                R.note(f"- {name}: {why}")
                R.note(f"  {ADVICE.get(name, '')}")
        else:
            headline("All layers work right now.", "32;1")
        R.note("If the problem is intermittent, run:  sudo python3 nettest.py --monitor-only 60")
        R.note("The monitor logs every outage (IPv4 and IPv6) and which layer failed at that moment.")
    if F.get("comparison"):
        R.note(f"Comparison with {F['comparison']['other']}: {F['comparison']['verdict']}")
    if F.get("unbound") or F.get("rpf_risk"):
        R.note("CAUTION: some results may be affected by other interfaces (see warnings above). "
               "Disconnect the other network links and re-run as root for clean results.")
    if F.get("cgnat_hop") or F.get("carrier_private") or F.get("dslite") or (
            F.get("router_wan_ip") and addr_class(F["router_wan_ip"]) in ("private", "CGNAT")):
        R.note("Note: IPv4 is behind carrier-grade/double NAT - inbound connections (port forwarding, "
               "some games/VPNs) will not work over IPv4; that is not an outage.")


# --------------------------------------------------------------------------- monitor

def wan_state():
    """What identifies the current WAN session: public IP, IPv6 prefix, router session counters."""
    st = {}
    if F.get("default_route"):
        try:
            r = http_request("https://api.ipify.org?format=json", timeout=5)
            st["public4"] = json.loads(r["body"]).get("ip")
        except HTTP_FAILURES:
            pass
    pfx = sorted({str(ipaddress.ip_interface(f"{a['local']}/64").network)
                  for l in ipj("-6", "addr", "show", "dev", IFACE) for a in l.get("addr_info", [])
                  if a.get("scope") == "global" and is_gua(a["local"]) and not a.get("deprecated")})
    st["prefix6"] = ",".join(pfx) or None
    if F.get("hilink") and F.get("gateway"):
        try:
            h = hilink(F["gateway"], ("/api/monitoring/status", "/api/monitoring/traffic-statistics",
                                      "/api/dialup/mobile-dataswitch"))
        except HTTP_FAILURES:
            h = None
        if h:
            ms_ = h.get("/api/monitoring/status", {})
            ct = h.get("/api/monitoring/traffic-statistics", {}).get("CurrentConnectTime", "")
            st["session"] = int(ct) if ct.isdigit() else None
            net = ms_.get("CurrentNetworkTypeEx") or ms_.get("CurrentNetworkType")
            st["net"] = HILINK_NET.get(net, net) + (" +5G" if ms_.get("EndcStatus") == "1" else "") if net else None
            st["signal"] = int(ms_["SignalIcon"]) if ms_.get("SignalIcon", "").isdigit() else None
            st["conn"] = HILINK_STATUS.get(ms_.get("ConnectionStatus"), ms_.get("ConnectionStatus"))
    return st


class WanTracker:
    """Polls wan_state() in the background and reports reconnects, IP/prefix changes, RAT and signal changes."""

    def __init__(self):
        self.prev, self.events, self.busy = {}, [], False
        self.t_session = None
        self.signal_log = []

    def poll_async(self):
        if not self.busy:
            self.busy = True
            threading.Thread(target=self._poll, daemon=True).start()

    def event(self, now, kind, text):
        self.events.append((now, kind, text))
        text = clean(text)
        R._emit(Color.c("33;1", f"  {now:%H:%M:%S}  ~ {text}"), f"  {now:%H:%M:%S}  ~ {text}")

    def _poll(self):
        try:
            cur, now, p = wan_state(), datetime.datetime.now(), self.prev
            if cur.get("signal") is not None:
                self.signal_log.append((now, cur["signal"], cur.get("net")))
            if p:
                if cur.get("public4") and p.get("public4") and cur["public4"] != p["public4"]:
                    self.event(now, "reconnect", f"public IPv4 changed {p['public4']} -> {cur['public4']} (WAN reconnect)")
                if cur.get("prefix6") and p.get("prefix6") and cur["prefix6"] != p["prefix6"]:
                    self.event(now, "reconnect", f"IPv6 prefix changed {p['prefix6']} -> {cur['prefix6']} (WAN reconnect)")
                if cur.get("session") is not None and p.get("session") is not None and self.t_session:
                    expected = p["session"] + (now - self.t_session).total_seconds()
                    if cur["session"] + 30 < expected:
                        at = now - datetime.timedelta(seconds=cur["session"])
                        self.event(now, "session", f"router's mobile data session restarted at {at:%H:%M:%S}")
                if cur.get("net") and p.get("net") and cur["net"] != p["net"]:
                    self.event(now, "rat", f"mobile network changed {p['net']} -> {cur['net']}")
                if cur.get("signal") is not None and p.get("signal") is not None and cur["signal"] <= p["signal"] - 2:
                    self.event(now, "signal", f"signal dropped {p['signal']}/5 -> {cur['signal']}/5")
                if cur.get("conn") and p.get("conn") and cur["conn"] != p["conn"]:
                    self.event(now, "conn", f"router connection status {p['conn']} -> {cur['conn']}")
            if cur.get("session") is not None:
                self.t_session = now
            for k, v in cur.items():
                if v is not None:
                    self.prev[k] = v
        except Exception as e:  # a failed poll must never stop the monitor
            R.note(f"(WAN state poll failed: {type(e).__name__}: {e})")
        finally:
            self.busy = False


class OutageSnapshot:
    """At the start of an outage, record where the path ends and what the router says - while it is happening."""

    def __init__(self):
        self.lines, self.busy = [], set()

    def start(self, fam, state):
        if fam not in self.busy:
            self.busy.add(fam)
            threading.Thread(target=self._run, args=(fam, state), daemon=True).start()

    def _run(self, fam, state):
        t, parts, v6 = datetime.datetime.now(), [], fam == "IPv6"
        try:
            if ROOT:
                try:
                    hops, dest = mtr(PUBLIC_V6[0][0] if v6 else REFERENCE_V4, rounds=1, max_ttl=12,
                                     wait=F.get("path_wait", 1.0), v6=v6)
                    un = [f"hop {h['ttl']} {s}: {(UNREACH6 if v6 else UNREACH4).get(c, c)}"
                          for h in hops for s, c, _ in h["unreach"]]
                    parts.append("path " + " > ".join(h["addr"] or "*" for h in hops) + (" (arrives)" if dest else "")
                                 + (f" [{'; '.join(un)}]" if un else ""))
                except OSError:
                    pass
            if not v6 and F.get("gateway"):
                try:
                    r = dns_query(F["gateway"], "example.com", timeout=1.5)
                    parts.append(f"router DNS {RCODES.get(r['rcode'], r['rcode'])} in {r['ms']:.0f} ms")
                except DNS_ERRORS:
                    parts.append("router DNS: no answer")
            if F.get("hilink") and F.get("gateway"):
                try:
                    h = hilink(F["gateway"], ("/api/monitoring/status", "/api/dialup/mobile-dataswitch"))
                except HTTP_FAILURES:
                    h = None
                if h:
                    ms_ = h.get("/api/monitoring/status", {})
                    net = ms_.get("CurrentNetworkTypeEx") or ms_.get("CurrentNetworkType")
                    parts.append(f"router: {HILINK_STATUS.get(ms_.get('ConnectionStatus'), ms_.get('ConnectionStatus'))}, "
                                 f"{HILINK_NET.get(net, net)}, signal {ms_.get('SignalIcon', '?')}/5"
                                 + (", DATA OFF" if h.get("/api/dialup/mobile-dataswitch", {}).get("dataswitch") == "0" else ""))
                else:
                    parts.append("router status page: no answer")
            if v6 and ROOT:
                try:
                    ras = ndp_rs(wait=1.5)
                    parts.append("RA: " + (", ".join(f"{r['src']} lifetime {r['lifetime']} s" for r in ras) or "none"))
                except OSError:
                    pass
            line = clean(f"{t:%H:%M:%S} {fam} {state}: " + " | ".join(parts))
            self.lines.append(line)
            R._emit(Color.c("35", "  snapshot " + line), "  snapshot " + line)
        finally:
            self.busy.discard(fam)


def monitor_patterns(targets, stats, real, secs, tracker, snapper):
    """Classify the monitor history: flapping vs. degraded vs. latency spikes vs. stable."""
    hours = max(secs / 3600, 1 / 60)
    spikes, samples = 0, 0
    for l, _, role, _ in targets:
        rtts = stats[l]["rtts"]
        if role == "inet" and len(rtts) >= 10:
            med = statistics.median(rtts)
            spikes += sum(1 for r in rtts if r > max(3 * med, med + 100))
            samples += len(rtts)
    inet_loss = mean([100 * (stats[l]["sent"] - stats[l]["recv"]) / stats[l]["sent"]
                      for l, _, role, _ in targets if role == "inet" and stats[l]["sent"]]) or 0
    reconnects = [e for e in tracker.events if e[1] in ("reconnect", "session")]
    n = len(real)
    if n >= 3 or (n >= 2 and n / hours >= 2):
        pat, st = f"FLAPPING - {n} outages ({n / hours:.1f}/hour): the connection drops and comes back repeatedly", "FAIL"
    elif n:
        pat, st = f"{n} outage(s) in {fmt_dur(secs)}", "WARN"
    elif inet_loss >= 2:
        pat, st = f"DEGRADED - {inet_loss:.1f}% loss without full outages: congestion, weak signal or a lossy line", "WARN"
    elif samples and spikes / samples > 0.05:
        pat, st = f"LATENCY SPIKES - {spikes} of {samples} probes far above normal", "WARN"
    else:
        pat, st = "STABLE", "PASS"
    F["monitor_pattern"] = pat
    R.add(st, "Pattern", pat)
    if samples:
        R.note(f"latency spikes: {spikes}/{samples} probes; average internet loss {inet_loss:.1f}%")
    if tracker.events:
        R.add("WARN" if reconnects else "INFO", "WAN events", f"{len(tracker.events)} events, {len(reconnects)} reconnect(s)")
        for t, _, text in tracker.events:
            R.note(f"  {t:%Y-%m-%d %H:%M:%S}  {text}")
    else:
        R.add("PASS", "WAN events", "no reconnects, IP/prefix changes or network-type changes seen")
    for o in real:
        if o["state"] == "LAN DOWN" and (o["end"] - o["start"]).total_seconds() >= 20 and any(
                e[1] == "session" and o["start"] <= e[0] <= o["end"] + datetime.timedelta(minutes=3) for e in tracker.events):
            R.add("WARN", "Router reboot", f"router unreachable from {o['start']:%H:%M:%S} and its WAN session restarted "
                  "right after - the router most likely rebooted/crashed")
    if tracker.signal_log:
        sig = [s for _, s, _ in tracker.signal_log]
        R.note(f"router signal bars over time: min {min(sig)}/5, max {max(sig)}/5; networks seen: "
               + ", ".join(sorted({n for _, _, n in tracker.signal_log if n})))
    if snapper.lines:
        R.add("INFO", "Outage snapshots", f"{len(snapper.lines)} taken during outages:")
        for l in snapper.lines:
            R.note("  " + l)
    F["wan_events"] = [{"time": t.isoformat(timespec="seconds"), "kind": k, "text": x} for t, k, x in tracker.events]
    F["outage_snapshots"] = snapper.lines


def monitor(minutes):
    global IFINDEX
    R.section("MON", f"MONITOR  ({'until Ctrl-C' if minutes <= 0 else f'{minutes} min'}, 1 probe/s per target, IPv4 + IPv6)")
    targets = []   # (label, ip, role, v6)
    if F.get("gateway"):
        targets.append(("router", F["gateway"], "lan", False))
    if F.get("wan_hop_echo"):
        targets.append(("isp-edge", F["wan_hop_echo"], "wan", False))
    for ip, _ in PUBLIC_V4[:3]:
        targets.append((ip, ip, "inet", False))
    v6 = F.get("v6") == "enabled" and F.get("gateway6")
    if v6:
        targets.append(("router6", F["gateway6"], "lan", True))
        if v6_route_ok():
            if F.get("v6_wan_hop_echo"):
                targets.append(("isp-edge6", F["v6_wan_hop_echo"], "wan", True))
            for ip, name in PUBLIC_V6[:2]:
                targets.append((f"{name.lower()}6", ip, "inet", True))
    dns_srv = None
    for srv in dedupe(list(F.get("resolvers") or []) + PUBLIC_DNS):
        try:
            if dns_query(srv, "example.com", timeout=1.5)["rcode"] == 0:
                dns_srv = srv
                break
        except DNS_ERRORS:
            continue
    R.add("INFO", "Targets", ", ".join(f"{l}={ip}" for l, ip, _, _ in targets)
          + (f"; DNS via {dns_srv} every 5 s" if dns_srv else "; DNS check disabled - no resolver answered at start"))
    stamp = R.started.strftime("%Y%m%d-%H%M%S")
    make_output_dir(ARGS.outdir)
    csv_path = os.path.join(ARGS.outdir, f"monitor-{stamp}.csv")
    csvf = private_open(csv_path)
    csvf.write("time,state4,state6,carrier," + ",".join(l for l, _, _, _ in targets) + ",dns\n")
    ri = {False: RawIcmp(False), True: RawIcmp(True) if v6 else None} if ROOT else None
    stats = {l: {"sent": 0, "recv": 0, "rtts": []} for l, _, _, _ in targets}
    window, outages, cur = [], [], {False: None, True: None}
    end = time.time() + minutes * 60 if minutes > 0 else float("inf")
    i = 0
    down_states = ("LINK DOWN", "LAN DOWN", "WAN DOWN", "INTERNET DOWN", "DNS FAIL")
    R.note(f"{'time':<10}{'state':<15}" + "  ".join(f"{l:>13}" for l, _, _, _ in targets))
    R.note("WAN state (public IP, IPv6 prefix, router session) is polled every 60 s; snapshots are taken when an outage starts")
    R.note("each second is judged 3 s after sending: replies up to 3 s late count as latency, not loss")
    tracker, snapper = WanTracker(), OutageSnapshot()

    def classify(res, fam6, carrier, dns_ok):
        mine = [(l, role) for l, _, role, f6 in targets if f6 == fam6]
        if not mine:
            return None
        inet = [res[l] for l, role in mine if role == "inet"]
        router = next((res[l] for l, role in mine if role == "lan"), "n/a")
        edge = [res[l] for l, role in mine if role == "wan"]
        if not carrier:
            return "LINK DOWN"
        if not inet:
            return "LAN DOWN" if router is None else "OK" if router != "n/a" else None
        if not any(x is not None for x in inet):
            if router is None:
                return "LAN DOWN"
            if edge and edge[0] is not None:
                return "INTERNET DOWN"
            return "WAN DOWN"
        if not fam6 and dns_ok is False:
            return "DNS FAIL"
        if any(res[l] is None for l, _ in mine):
            return "LOSS"
        return "OK"

    # Each second's probes are judged LATE seconds after sending, so slow replies (satellite, a
    # congested LTE uplink) count as high latency instead of loss.
    LATE = 3.0
    samples, inflight = {}, {}     # sample no -> sample; (is_v6, seq) -> (sample no, label, t_sent)
    dns_state = {"ok": None, "busy": False}
    pool = None if ri else cf.ThreadPoolExecutor(max_workers=max(4, 4 * len(targets)))
    ifindex = IFINDEX

    def dns_check():
        try:
            dns_state["ok"] = dns_query(dns_srv, "example.com", timeout=2.5)["rcode"] == 0
        except DNS_ERRORS:
            dns_state["ok"] = False
        finally:
            dns_state["busy"] = False

    def ping_job(n, label, ip, f6):
        p = ping(ip, count=1, wait=LATE, v6=f6)
        s = samples.get(n)
        if s is not None and p["rx"]:
            s["res"][label] = p["avg"]

    def finalize(n):
        nonlocal i, window
        s = samples.pop(n)
        res, carrier, now = s["res"], s["carrier"], s["t"]
        for l in res:
            stats[l]["sent"] += 1
            if res[l] is not None:
                stats[l]["recv"] += 1
                stats[l]["rtts"].append(res[l])
        states = {f6: classify(res, f6, carrier, s["dns"]) for f6 in (False, True)}
        csvf.write(f"{now.isoformat(timespec='seconds')},{states[False] or ''},{states[True] or ''},{int(carrier)},"
                   + ",".join("" if res[l] is None else f"{res[l]:.2f}" for l, _, _, _ in targets)
                   + f",{'' if s['dns'] is None else int(s['dns'])}\n")
        csvf.flush()
        for f6 in (False, True):
            state, fam = states[f6], "IPv6" if f6 else "IPv4"
            if state in down_states:
                if not cur[f6] or cur[f6]["state"] != state:
                    if cur[f6]:
                        cur[f6]["end"] = now
                        outages.append(cur[f6])
                    cur[f6] = {"state": state, "fam": fam, "start": now, "end": None}
                    R._emit(Color.c("31;1", f"  {now:%H:%M:%S}  !!! {fam} {state} begins"),
                            f"  {now:%H:%M:%S}  !!! {fam} {state} begins")
                    if state != "LINK DOWN":
                        snapper.start(fam, state)
            elif cur[f6]:
                cur[f6]["end"] = now
                outages.append(cur[f6])
                dur = (now - cur[f6]["start"]).total_seconds()
                R._emit(Color.c("32", f"  {now:%H:%M:%S}  {fam} recovered after {dur:.0f} s of {cur[f6]['state']}"),
                        f"  {now:%H:%M:%S}  {fam} recovered after {dur:.0f} s of {cur[f6]['state']}")
                cur[f6] = None
        window.append(res)
        if len(window) == 10:
            cells = []
            for l, _, _, _ in targets:
                vals = [w[l] for w in window if w[l] is not None]
                cells.append(f"{(fmt_ms(mean(vals)) + 'ms') if vals else '---':>8} {100 * (10 - len(vals)) / 10:>3.0f}%")
            worst = next((st for st in (states[False], states[True]) if st in down_states), None)
            st = worst or ("OK" if all(c.endswith(" 0%") for c in cells) else "LOSS")
            R.note(f"{now:%H:%M:%S}  {st:<14} " + "  ".join(f"{c:>13}" for c in cells))
            window = []
        i += 1

    n = 0
    try:
        while time.time() < end:
            t_start = time.monotonic()
            try:
                idx_now = socket.if_nametoindex(IFACE)
            except OSError:
                idx_now = None          # adapter unplugged / reset
            if idx_now and idx_now != ifindex:
                # the adapter came back as a new interface: old sockets are bound to the vanished one
                ifindex = IFINDEX = idx_now
                if ri:
                    for r in ri.values():
                        if r:
                            r.close()
                    ri = {False: RawIcmp(False), True: RawIcmp(True) if v6 else None}
                inflight.clear()
                tracker.event(datetime.datetime.now(), "replug", f"{IFACE} re-appeared (adapter reset or re-plugged) "
                              "- probes re-bound to the new interface")
            carrier = bool(idx_now) and has_carrier()
            samples[n] = {"t": datetime.datetime.now(), "mono": t_start, "carrier": carrier,
                          "res": {l: None for l, _, _, _ in targets}, "dns": dns_state["ok"]}
            if carrier:
                for l, ip, _, f6 in targets:
                    if ri:
                        if ri.get(f6):
                            seq, t = ri[f6].send(ip)
                            inflight[(f6, seq)] = (n, l, t)
                    else:
                        pool.submit(ping_job, n, l, ip, f6)
            if n % 60 == 2:
                tracker.poll_async()
            if n % 5 == 0 and carrier and dns_srv and not dns_state["busy"]:
                dns_state["busy"] = True
                threading.Thread(target=dns_check, daemon=True).start()
            if ri:
                socks = {r.s: f6 for f6, r in ri.items() if r}
                recv_end = t_start + 0.95
                while True:
                    left = recv_end - time.monotonic()
                    if left <= 0:
                        break
                    rl, _, _ = select.select(list(socks), [], [], left)
                    for sk in rl:          # IPv4 and IPv6 replies are read side by side
                        f6 = socks[sk]
                        while True:
                            ev = ri[f6].recv(0)
                            if not ev:
                                break
                            key = (f6, ev[2])
                            if ev[0] == "reply" and key in inflight:
                                m, l, t = inflight.pop(key)
                                if m in samples:
                                    samples[m]["res"][l] = (ev[3] - t) * 1000
            for m in [m for m, s in samples.items() if time.monotonic() - s["mono"] >= LATE]:
                finalize(m)
            for k in [k for k, v in inflight.items() if v[0] not in samples]:
                del inflight[k]
            n += 1
            time.sleep(max(0.0, 1.0 - (time.monotonic() - t_start)))
    except KeyboardInterrupt:
        print()
    finally:
        # the last < 3 s are not judged yet; they are dropped rather than counted as loss
        csvf.close()
        if ri:
            for r in ri.values():
                if r:
                    r.close()
        if pool:
            pool.shutdown(wait=False)
    for f6 in (False, True):
        if cur[f6]:
            cur[f6]["end"] = datetime.datetime.now()
            outages.append(cur[f6])
    R.add("INFO", "Monitor duration", f"{i} s, per-second log: {csv_path}")
    for l, ip, _, _ in targets:
        s = stats[l]
        loss = 100 * (s["sent"] - s["recv"]) / s["sent"] if s["sent"] else 0
        R.add("PASS" if loss < 1 else "WARN" if loss < 5 else "FAIL", f"{l} ({ip})",
              f"loss {loss:.1f}% ({s['sent'] - s['recv']}/{s['sent']}), avg {fmt_ms(mean(s['rtts']))} ms, "
              f"max {fmt_ms(max(s['rtts']) if s['rtts'] else None)} ms, jitter {fmt_ms(jitter(s['rtts']))} ms")
    # a link-down hits both families at once: count it once (as IPv4)
    real = [o for o in outages if (o["end"] - o["start"]).total_seconds() >= 2
            and not (o["fam"] == "IPv6" and o["state"] == "LINK DOWN")]
    F["outages"] = [{"family": o["fam"], "state": o["state"], "start": o["start"].isoformat(timespec="seconds"),
                     "seconds": round((o["end"] - o["start"]).total_seconds())} for o in outages]
    if snapper.busy or tracker.busy:
        time.sleep(3)    # let a running snapshot / poll finish so it lands in the report
    if not real:
        R.add("PASS", "Outages", "none lasting 2 s or more")
        monitor_patterns(targets, stats, real, i, tracker, snapper)
        return
    monitor_patterns(targets, stats, real, i, tracker, snapper)
    by = {}
    for o in real:
        by.setdefault((o["fam"], o["state"]), []).append((o["end"] - o["start"]).total_seconds())
    R.add("FAIL", "Outages", f"{len(real)} outages: " + ", ".join(
        f"{f} {k} x{len(v)} (total {sum(v):.0f} s)" for (f, k), v in by.items()))
    for o in real[-25:]:
        R.note(f"  {o['start']:%Y-%m-%d %H:%M:%S}  {o['fam']} {o['state']:<14} {(o['end'] - o['start']).total_seconds():.0f} s")
    fam, worst = max(by, key=lambda k: sum(by[k]))
    where = {"LINK DOWN": "the network link itself (adapter, cable/port or Wi-Fi association)",
             "LAN DOWN": "the router (it stops answering on the LAN - crash/reboot?)",
             "WAN DOWN": "the router's uplink / ISP connection",
             "INTERNET DOWN": "beyond the ISP edge (ISP network)",
             "DNS FAIL": "DNS only"}[worst]
    R._emit(Color.c("31;1", f"  >>> Intermittent failures are mostly at: {where} ({fam})"),
            f"  >>> Intermittent failures are mostly at: {where} ({fam})")


# --------------------------------------------------------------------------- main

def save_reports():
    make_output_dir(ARGS.outdir)
    stamp = R.started.strftime("%Y%m%d-%H%M%S")
    txt = os.path.join(ARGS.outdir, f"nettest-{stamp}.txt")
    js = os.path.join(ARGS.outdir, f"nettest-{stamp}.json")
    with private_open(txt) as f:
        f.write("\n".join(R.text) + "\n")
    facts = {k: v for k, v in F.items() if k not in ("stats_start",)}
    with private_open(js) as f:
        json.dump({"schema_version": REPORT_SCHEMA_VERSION, "version": VERSION, "interface": IFACE, "started": R.started.isoformat(),
                   "results": R.results, "facts": facts}, f, indent=2, default=str)
    page = os.path.join(ARGS.outdir, f"nettest-{stamp}.html")
    with private_open(page) as f:
        f.write(html_report())
    print(f"\nReports saved: {txt}\n               {js}\n               {page}")
    if RECORDER:
        if run_failed():
            cap = os.path.join(ARGS.outdir, f"nettest-{stamp}.pcap")
            print(f"Capture saved: {cap} ({RECORDER.save(cap)} frames, headers only)")
        else:
            RECORDER.halt.set()


def guarded(fn, *a):
    try:
        fn(*a)
    except KeyboardInterrupt:
        raise
    except Exception as e:  # keep going: one broken probe must not hide the other layers
        R.add("FAIL", f"Internal error in {fn.__name__}", f"{type(e).__name__}: {e}")


def monitor_setup():
    F["iface_found"] = True
    gather_addressing()
    F["v6"] = "disabled" if sysread(f"/proc/sys/net/ipv6/conf/{IFACE}/disable_ipv6") == "1" else "enabled"
    F["iface_dns"] = iface_dns_servers()
    F["resolvers"] = [s for s in F["iface_dns"] if ":" not in s] + PUBLIC_DNS
    arp_flux_guard()
    if F.get("gateway"):
        try:
            F["hilink"] = hilink(F["gateway"], ("/api/monitoring/status",))
        except HTTP_FAILURES:
            pass
    if not ROOT:
        return
    for v6, ok, dst in ((False, F.get("default_route"), REFERENCE_V4), (True, v6_route_ok(), PUBLIC_V6[0][0])):
        if not ok:
            continue
        p = ping(dst, count=3, interval=0.2, wait=3, v6=v6)
        F["path_wait"] = max(F.get("path_wait", 1.0), path_wait(p["max"]))
        try:
            hops, _ = mtr(dst, rounds=2, wait=F["path_wait"], v6=v6)
            beyond = [h for h in hops if h["addr"] and h["ttl"] >= 2]
            if beyond and ping(beyond[0]["addr"], count=3, interval=0.2, v6=v6)["rx"]:
                F[("v6_" if v6 else "") + "wan_hop_echo"] = beyond[0]["addr"]
        except OSError:
            pass


# --------------------------------------------------------------------------- extended checks: shared helpers

def parse_tcp_info(b):
    """struct tcp_info fields we use (linux/tcp.h: 8 bytes of u8, then u32s, then u64s, then segs_out/segs_in)."""
    if len(b) < 144:
        return None
    u = struct.unpack("=24I", b[8:104])
    segs_out, segs_in = struct.unpack("=II", b[136:144])
    return {"options": b[5], "rtt_ms": u[15] / 1000, "rttvar_ms": u[16] / 1000, "cwnd": u[18],
            "rcv_rtt_ms": u[21] / 1000, "total_retrans": u[23], "segs_out": segs_out, "segs_in": segs_in}


def kernel_net_counters():
    """/proc/net/netstat and snmp as {'TcpExt.Name': value}. These count the whole system, not one interface."""
    out = {}
    for path in ("/proc/net/netstat", "/proc/net/snmp"):
        try:
            with open(path) as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        for head, vals in zip(lines[::2], lines[1::2]):
            proto, _, names = head.partition(":")
            for k, v in zip(names.split(), vals.partition(":")[2].split()):
                if v.lstrip("-").isdigit():
                    out[f"{proto}.{k}"] = int(v)
    return out


def report_tcp_health(kind, log, before):
    """What the TCP stack saw during a transfer: packet loss, or a clean rate limit?"""
    infos = [i for i in map(parse_tcp_info, log) if i]
    if not infos:
        return
    after = kernel_net_counters()
    label = "download" if kind == "down" else "upload"
    if kind == "up":
        segs = sum(i["segs_out"] for i in infos)
        lost = sum(i["total_retrans"] for i in infos)
        pct = 100.0 * lost / segs if segs else 0.0
        rtt = mean([i["rtt_ms"] for i in infos])
        what = f"{lost} of {segs} segments retransmitted ({pct:.2f}%), smoothed RTT {fmt_ms(rtt)} ms"
    else:
        segs = sum(i["segs_in"] for i in infos)
        ooo = after.get("TcpExt.TCPOFOQueue", 0) - before.get("TcpExt.TCPOFOQueue", 0)
        pct = 100.0 * ooo / segs if segs else 0.0
        rtt = mean([i["rcv_rtt_ms"] for i in infos if i["rcv_rtt_ms"]])
        what = f"{ooo} out-of-order arrivals in {segs} segments, receiver RTT {fmt_ms(rtt)} ms"
    # one lost packet leaves every later packet of its window out of order, so this ratio is not a loss rate
    limit, sign = (2, " - packets are being lost on the path") if kind == "up" else (10, " - suggests packet loss or reordering on the path")
    F[f"tcp_{kind}_{'retrans' if kind == 'up' else 'out_of_order'}_pct"] = round(pct, 3)
    R.add("WARN" if pct >= limit else "PASS", f"TCP health during {label}", what
          + (sign if pct >= limit else " - no sign of heavy packet loss in the data stream"))


def nm_connection():
    rc, out, _ = run(["nmcli", "-t", "-g", "GENERAL.CONNECTION", "device", "show", IFACE])
    return out.strip() if rc == 0 and out.strip() not in ("", "--") else None


# --------------------------------------------------------------------------- extended checks: physical

def parse_wifi_scan(out):
    nets = []
    for block in re.split(r"(?m)^BSS ", out)[1:]:
        ssid = re.search(r"(?m)^\s*SSID: (.*)$", block)
        freq = re.search(r"freq: ([\d.]+)", block)
        sig = re.search(r"signal: (-?[\d.]+)", block)
        auth = re.search(r"Authentication suites: (.*)", block)
        nets.append({"bssid": block[:17], "ssid": ssid.group(1).strip() if ssid else "", "freq": float(freq.group(1)) if freq else None,
                     "signal": float(sig.group(1)) if sig else None, "auth": auth.group(1).strip() if auth else "",
                     "wpa1": bool(re.search(r"(?m)^\s*WPA:", block)), "privacy": "Privacy" in block.split("capability", 1)[-1][:120]})
    return nets


def test_wifi_quality():
    R.section("L1-WIFI", f"WI-FI QUALITY  ({IFACE})")
    _, out, _ = run(["iw", "dev", IFACE, "station", "dump"], timeout=5)

    def num(pat):
        m = re.search(pat + r":\s*(\d+)", out)
        return int(m.group(1)) if m else None

    pkts, retries, failed = num("tx packets"), num("tx retries"), num("tx failed")
    if pkts:
        pct = 100.0 * (retries or 0) / pkts
        F["wifi_retry_pct"] = round(pct, 1)
        R.add("WARN" if pct >= 25 else "PASS", "Wi-Fi transmit retries",
              f"{pct:.1f}% ({retries} retries in {pkts} packets), {failed or 0} failed"
              + (" - many frames need resending: interference or a marginal link" if pct >= 25 else ""))
    bl, br = num("beacon loss"), num("beacon rx")
    if bl is not None:
        R.add("WARN" if bl > 20 else "INFO", "Wi-Fi beacon loss", f"{bl} events" + (f", {br} beacons received" if br else ""))
    m = re.search(r"MFP:\s*(\w+)", out)
    if m:
        R.add("INFO", "Protected management frames", m.group(1))
    _, out2, _ = run(["iw", "dev", IFACE, "get", "power_save"], timeout=5)
    m = re.search(r"Power save: (\w+)", out2)
    if m:
        F["wifi_power_save"] = m.group(1)
        R.add("INFO", "Wi-Fi power save", m.group(1) + (" - can add latency and jitter on a battery-saving radio" if m.group(1) == "on" else ""))
    _, out2, _ = run(["iw", "dev", IFACE, "survey", "dump"], timeout=5)
    block = next((b for b in re.split(r"(?m)^Survey data", out2) if "[in use]" in b), "")
    active = re.search(r"channel active time:\s*(\d+)", block)
    busy = re.search(r"channel busy time:\s*(\d+)", block)
    if active and busy and int(active.group(1)):
        pct = 100.0 * int(busy.group(1)) / int(active.group(1))
        F["wifi_channel_busy_pct"] = round(pct, 1)
        R.add("WARN" if pct >= 70 else "PASS", "Wi-Fi channel utilisation", f"channel busy {pct:.0f}% of the time"
              + (" - the channel is congested" if pct >= 70 else ""))
    else:
        R.add("SKIP", "Wi-Fi channel utilisation", "this driver reports no channel survey")
    if ARGS.wifi_scan and ROOT:
        R.progress("active Wi-Fi scan (the radio briefly leaves its channel) …")
        rc, out2, err = run(["iw", "dev", IFACE, "scan"], timeout=30)
    else:
        rc, out2, err = run(["iw", "dev", IFACE, "scan", "dump"], timeout=10)
    nets = parse_wifi_scan(out2) if rc == 0 else []
    own = next((n for n in nets if n["bssid"].lower() == (F.get("wifi") or {}).get("bssid", "").lower()), None)
    if nets:
        freq = (F.get("wifi") or {}).get("freq") or (own or {}).get("freq")
        same = [n for n in nets if n is not own and n["freq"] == freq]
        strong = [n for n in same if (n["signal"] or -100) >= -75]
        F["wifi_neighbours"] = {"seen": len(nets), "same_channel": len(same), "strong_same_channel": len(strong)}
        R.add("WARN" if len(strong) >= 4 else "INFO", "Neighbouring Wi-Fi networks",
              f"{len(nets)} access points seen, {len(same)} others on this channel ({len(strong)} strong)"
              + ("" if ARGS.wifi_scan and ROOT else "; from the cached list (--wifi-scan refreshes it as root)"))
    if own:
        auth = own["auth"]
        sec = ("WPA3" if "SAE" in auth and "PSK" not in auth else "WPA2/WPA3 mixed" if "SAE" in auth
               else "WPA2/WPA3 Enterprise" if "802.1X" in auth else "WPA2-Personal" if auth
               else "WPA (legacy)" if own["wpa1"] else "WEP or open" if not auth else "?")
        weak = not auth
        F["wifi_security"] = sec
        R.add("WARN" if weak else "PASS", "Wi-Fi security", sec + (" - traffic on this network is poorly protected" if weak else ""))
    _, out2, _ = run(["iw", "reg", "get"], timeout=5)
    m = re.search(r"(?m)^country (\w\w):", out2)
    if m:
        R.add("INFO", "Wi-Fi regulatory domain", m.group(1))
    rc, out2, _ = run(["journalctl", "-k", "-b", "--no-pager", "-g", f"{IFACE}: associate with"], timeout=20)
    if rc == 0:
        seen = re.findall(r"associate with ([0-9a-f:]{17})", out2)
        distinct = list(dict.fromkeys(seen))
        if seen:
            F["wifi_associations"] = len(seen)
            R.add("INFO", "Wi-Fi roaming this boot", f"{len(seen)} associations to {len(distinct)} access point(s)")


def test_physical_extras():
    if F.get("iface_kind") == "wifi" or not shutil.which("ethtool"):
        return
    R.section("L1-EXT", f"L1  ADAPTER DETAILS   ({IFACE})")
    rc, out, _ = run(["ethtool", "-m", IFACE], timeout=8)
    if rc == 0 and out.strip():
        vals = dict((k.strip(), v.strip()) for k, _, v in (l.partition(":") for l in out.splitlines()) if v)
        pick = [f"{k}: {vals[k]}" for k in vals if re.search(r"module temperature|laser output power|receiver signal", k, re.I)
                and "threshold" not in k.lower()]
        alarms = [k for k, v in vals.items() if re.search(r"alarm|warning", k, re.I) and v.lower() == "on"]
        R.add("WARN" if alarms else "INFO", "Optical module (SFP)", "; ".join(pick) or vals.get("Identifier", "present")
              + (f"; active alarms: {', '.join(alarms[:4])}" if alarms else ""))
    else:
        R.add("SKIP", "Optical module (SFP)", "none reported (normal for copper ports)")
    _, out, _ = run(["ethtool", "-S", IFACE], timeout=8)
    queues = {}
    for k, v in re.findall(r"^\s*([\w.\-\[\]]+):\s*(\d+)\s*$", out, re.M):
        q = re.search(r"(?:^|[._\-\[])(?:queue|q)?[._\-]?(\d+)(?:[._\-\]]|$)", k)
        if q and int(v) and re.search(r"err|drop|miss|fail", k, re.I) and re.match(r"(rx|tx|queue)", k, re.I):
            name = f"{'rx' if k.lower().startswith('rx') else 'tx' if k.lower().startswith('tx') else 'q'}{q.group(1)}"
            queues[name] = queues.get(name, 0) + int(v)
    if queues:
        R.add("WARN", "Per-queue NIC errors", ", ".join(f"{k}={v}" for k, v in sorted(queues.items())[:12]))


# --------------------------------------------------------------------------- extended checks: data link

def test_link_extras():
    R.section("L2-EXT", "L2  LINK DETAILS  (802.1X, jumbo frames, client isolation)")
    conn = nm_connection()
    eap = ""
    if conn and F.get("iface_kind") in WIRED_KINDS and shutil.which("nmcli"):
        _, eap, _ = run(["nmcli", "-t", "-g", "802-1x.eap", "connection", "show", conn])
    if eap.strip() or F.get("eapol_seen"):
        R.add("INFO", "802.1X", (f"configured ({eap.strip()})" if eap.strip() else "not configured on this computer")
              + (f"; {F['eapol_seen']} EAPOL frames seen on the link" if F.get("eapol_seen") else ""))
    else:
        R.add("INFO", "802.1X", "no sign of port authentication" if ROOT or eap else "not observed (passive listening needs root)")
    mtu, gw = F.get("mtu") or 1500, F.get("gateway")
    if mtu > 1500 and gw:
        p = ping(gw, count=5, interval=0.2, size=mtu - 28, df=True)
        R.add("PASS" if p["rx"] else "WARN", f"Jumbo frames ({mtu} bytes)", ping_summary(p)
              + ("" if p["rx"] else " - the interface MTU is larger than the path to the router carries"))
    else:
        R.add("SKIP", "Jumbo frames", f"interface MTU is {mtu}; the tool does not change it")
    if ARGS.peer:
        p = ping(ARGS.peer, count=5, interval=0.2)
        R.add("PASS" if p["rx"] else "WARN", f"Client isolation (peer {ARGS.peer})", ping_summary(p)
              + (" - devices can reach each other" if p["rx"] else
                 " - blocked: client isolation, a firewall on that device, or a wrong address"))
    else:
        R.add("SKIP", "Client isolation", "needs a second device: --peer IP")


class GatewayWatch(threading.Thread):
    """During monitoring, alert if the router's MAC changes (ARP spoofing, or the router was replaced)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.halt = threading.Event()
        self.mac = None

    def run(self):
        gw = F.get("gateway")
        while gw and not self.halt.wait(5):
            mac = next((n.get("lladdr") for n in ipj("neigh", "show", "to", gw, "dev", IFACE) if n.get("lladdr")), None)
            if mac and self.mac and mac != self.mac:
                F.setdefault("gw_mac_changes", []).append({"time": datetime.datetime.now().isoformat(timespec="seconds"),
                                                           "from": self.mac, "to": mac})
                line = clean(f"  {datetime.datetime.now():%H:%M:%S}  !!! router {gw} changed MAC {self.mac} -> {mac} "
                             "(ARP spoofing or a replaced router)")
                R._emit(Color.c("31;1", line), line)
            self.mac = mac or self.mac


def watched_monitor(minutes):
    w = GatewayWatch()
    w.start()
    try:
        monitor(minutes)
    finally:
        w.halt.set()


# --------------------------------------------------------------------------- extended checks: network path

def paris_trace(dst, flows=4, max_ttl=12, wait=0.4):
    """UDP traceroute that keeps each flow's 5-tuple constant, so load balancers cannot mix paths within one flow."""
    raw = bsock(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    hops = {}
    try:
        for flow in range(flows):
            port = 33434 + flow
            s = bsock(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0))
            sport = s.getsockname()[1]
            try:
                for ttl in range(1, max_ttl + 1):
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    s.sendto(b"nettest-paris", (dst, port))
                    end, done, reached = time.monotonic() + wait, False, False
                    while time.monotonic() < end and not done:
                        r, _, _ = select.select([raw], [], [], max(0.0, end - time.monotonic()))
                        if not r:
                            break
                        data, addr = raw.recvfrom(2048)
                        try:
                            icmp = data[(data[0] & 0x0F) * 4:]
                            if icmp[0] not in (3, 11) or icmp[8 + 9] != 17:
                                continue
                            inner = icmp[8 + (icmp[8] & 0x0F) * 4:]
                            if struct.unpack("!HH", inner[:4]) != (sport, port):
                                continue
                        except (IndexError, struct.error):
                            continue
                        hops.setdefault(ttl, set()).add(addr[0])
                        done = True
                        reached = icmp[0] == 3
                    if reached:
                        break
            finally:
                s.close()
    finally:
        raw.close()
    return hops


def v6_extension_header_test(dst, count=4, wait=0.5):
    """Echo requests carrying a Destination Options header: many networks silently drop these."""
    ri = RawIcmp(v6=True)
    opts = bytes([0, 0, 1, 4, 0, 0, 0, 0])
    got = 0
    try:
        for _ in range(count):
            ri.seq = (ri.seq + 1) & 0xFFFF
            pkt = struct.pack("!BBHHH", 128, 0, 0, ri.ident, ri.seq) + ri.payload
            ri.s.sendmsg([pkt], [(socket.IPPROTO_IPV6, socket.IPV6_DSTOPTS, opts)], 0, sockaddr(dst, 0)[1])
            ev = ri.recv(wait)
            got += bool(ev and ev[0] == "reply")
    finally:
        ri.close()
    return got, count


def tcp_blackhole(v6):
    """A large response over TCP uses full-size packets; a broken path MTU stalls it after the handshake worked."""
    fam = "IPv6" if v6 else "IPv4"
    size = 300000
    try:
        r = http_request(f"{SPEED_DOWN_URL}{size}", timeout=10, v6=v6)
    except HTTP_FAILURES as e:
        F["v6_mtu_blackhole" if v6 else "mtu_blackhole"] = True
        R.add("WARN", f"Path MTU with real TCP ({fam})", f"a {size // 1000} kB transfer failed ({describe_exc(e)}) although small "
              "requests work - possible path MTU black hole")
        return
    ok = r["bytes"] >= size
    R.add("PASS" if ok else "WARN", f"Path MTU with real TCP ({fam})",
          f"{r['bytes'] // 1000} kB in {r['timing']['total_ms']:.0f} ms" + ("" if ok else " - transfer stopped early"))


def rpki_status(ip):
    info = json.loads(http_request(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}", timeout=8,
                                   max_body=256 * 1024)["body"])["data"]
    if not info.get("asns") or not info.get("prefix"):
        return None
    asn = info["asns"][0]
    status = json.loads(http_request(f"https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{asn}&prefix={info['prefix']}",
                                     timeout=8, max_body=256 * 1024)["body"])["data"].get("status")
    return {"asn": asn, "prefix": info["prefix"], "status": status}


def test_path_extras():
    if not F.get("inet_ok"):
        return
    R.section("L3-EXT", "L3  PATH DETAILS  (real-TCP MTU, load balancing, IPv6 headers, RPKI)")
    if F.get("https_ok"):
        tcp_blackhole(False)
    if F.get("v6_https_ok"):
        tcp_blackhole(True)
    if ROOT and not ARGS.quick:
        R.progress("multipath-aware trace to 1.1.1.1 …")
        try:
            hops = paris_trace(REFERENCE_V4)
            multi = {t: sorted(a) for t, a in hops.items() if len(a) > 1}
            F["paris_trace"] = {str(t): sorted(a) for t, a in hops.items()}
            R.add("INFO", "Load balancing on the path", "; ".join(f"hop {t}: {', '.join(a)}" for t, a in sorted(multi.items()))
                  if multi else f"none seen: each of the {len(hops)} answering hops used one router across 4 flows")
        except OSError as e:
            R.add("SKIP", "Load balancing on the path", describe_exc(e))
    else:
        R.add("SKIP", "Load balancing on the path", "needs root" if not ROOT else "skipped by --quick")
    if F.get("v6_inet_ok") and ROOT:
        try:
            got, n = v6_extension_header_test(PUBLIC_V6[0][0])
            R.add("PASS" if got else "WARN", "IPv6 extension headers", f"{got}/{n} echoes with a Destination Options header answered"
                  + ("" if got else " - the path drops packets with extension headers"))
            p = ping(PUBLIC_V6[0][0], count=3, interval=0.3, size=1600, v6=True)
            R.add("PASS" if p["rx"] else "WARN", "IPv6 fragments", ping_summary(p)
                  + ("" if p["rx"] else " - fragmented IPv6 does not pass"))
        except OSError as e:
            R.add("SKIP", "IPv6 extension headers", describe_exc(e))
    else:
        R.add("SKIP", "IPv6 extension headers", "needs working IPv6 and root")
    ip = F.get("public_ip")
    if ip and not ARGS.quick:
        try:
            st = rpki_status(ip)
        except HTTP_FAILURES + (KeyError, TypeError, IndexError) as e:
            st = None
            R.add("SKIP", "RPKI status", describe_exc(e) if isinstance(e, (OSError, NetError)) else "unexpected reply from RIPEstat")
        if st:
            F["rpki"] = st
            R.add("WARN" if st["status"] == "invalid" else "INFO", "RPKI status of your prefix",
                  f"{st['prefix']} (AS{st['asn']}): {st['status']}"
                  + (" - networks that enforce RPKI may drop your traffic" if st["status"] == "invalid" else ""))


# --------------------------------------------------------------------------- extended checks: DNS

def dns_query_edns(server, name, qtype=1, do=True, bufsize=4096, timeout=3.0):
    qid = random.randint(0, 0xFFFF)
    q = dns_build(name, qtype, qid)
    pkt = q[:10] + struct.pack("!H", 1) + q[12:] + b"\0" + struct.pack("!HHIH", 41, bufsize, 0x8000 if do else 0, 0)
    pkt = pkt[:2] + struct.pack("!H", 0x0120) + pkt[4:]     # recursion desired + authenticated data
    fam, sa = sockaddr(server, 53)
    s = bsock(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect(sa)       # only the queried server's answers are accepted
        s.send(pkt)
        end = time.monotonic() + timeout
        while True:
            data = s.recv(65535)
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                break
            if time.monotonic() > end:
                raise socket.timeout()
    finally:
        s.close()
    flags = struct.unpack("!H", data[2:4])[0]
    return {"rcode": flags & 0xF, "ad": bool(flags & 0x20), "tc": bool(flags & 0x200), "size": len(data),
            "ancount": struct.unpack("!H", data[6:8])[0]}


def test_dns_extras():
    resolvers = [s for s in (F.get("resolvers") or []) if ":" not in s]
    if not resolvers:
        return
    R.section("DNS-EXT", "DNS  DETAILS  (DNSSEC, large answers, rebinding protection, split DNS)")
    srv = resolvers[0]
    try:
        good = dns_query_edns(srv, "cloudflare.com")
        bad = dns_query_edns(srv, "dnssec-failed.org")
        validating = good["ad"] and bad["rcode"] == 2
        F["dnssec_validating"] = validating
        R.add("PASS" if validating else "INFO", f"DNSSEC validation ({srv})", "validates signatures" if validating else
              f"does not validate (signed name AD={int(good['ad'])}, broken name {RCODES.get(bad['rcode'], bad['rcode'])})")
    except DNS_ERRORS as e:
        R.add("WARN", f"DNSSEC validation ({srv})", f"query failed: {describe_exc(e)} - the resolver may not handle EDNS/DO")
    for server in dedupe([srv, REFERENCE_V4]):
        try:
            r = dns_query_edns(server, "google.com", QTYPES["TXT"], do=False)
            R.add("INFO" if r["tc"] else "PASS", f"Large DNS answer ({server})", f"{r['size']} bytes over UDP"
                  + (" - truncated, clients must retry over TCP" if r["tc"] else ""))
        except DNS_ERRORS as e:
            R.add("WARN", f"Large DNS answer ({server})", f"no reply ({describe_exc(e)}) - large or fragmented UDP may be dropped")
    try:
        ans = dns_query(srv, "192.168.1.1.nip.io", "A", timeout=3)
        ref = dns_query(REFERENCE_V4, "192.168.1.1.nip.io", "A", timeout=3)
        local, public = any(t == 1 for t, _, _ in ans["answers"]), any(t == 1 for t, _, _ in ref["answers"])
        if public:
            F["dns_rebind_protection"] = not local
            R.add("PASS" if not local else "INFO", f"DNS rebinding protection ({srv})", "private addresses in public answers are filtered"
                  if not local else "private addresses in public answers are passed through")
    except DNS_ERRORS:
        R.add("SKIP", "DNS rebinding protection", "test name did not resolve")
    rc, out, _ = run(["resolvectl", "status"], timeout=8)
    if rc == 0:
        links = []
        for block in re.split(r"(?m)^Link ", out)[1:]:
            m = re.match(r"\d+ \(([^)]+)\)", block)
            dns = re.search(r"DNS Servers?: (.*)", block)
            dom = re.search(r"DNS Domain: (.*)", block)
            if m and dns:
                links.append((m.group(1), dns.group(1).strip(), dom.group(1).strip() if dom else ""))
        vpn = [l for l in links if l[0] != IFACE and re.match(r"(tun|tap|wg|ppp|vpn|tailscale|nordlynx|proton)", l[0])]
        for name, dns, dom in links:
            R.add("INFO", f"DNS routing: {name}", f"servers {dns}" + (f", domains {dom}" if dom else ""))
        if vpn:
            R.add("WARN", "Split DNS", f"a VPN link ({', '.join(l[0] for l in vpn)}) also provides DNS, so normal lookups may not use {IFACE}")


# --------------------------------------------------------------------------- extended checks: transport

def quic_probe(ip):
    """Unknown-version QUIC Initial: a QUIC server answers with Version Negotiation, proving UDP/443 works both ways."""
    first = bytes([0xC0 | random.getrandbits(4)]) + b"\x1a\x2a\x3a\x4a" + b"\x08" + os.urandom(8) + b"\x08" + os.urandom(8)
    fam, sa = sockaddr(ip, 443)
    s = bsock(fam, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    try:
        s.connect(sa)
        t0 = time.monotonic()
        s.send(first + bytes(1200 - len(first)))
        data = s.recv(2048)
    except OSError:
        return None
    finally:
        s.close()
    return ms(t0) if len(data) >= 5 and data[0] & 0x80 and data[1:5] == bytes(4) else None


def stun_mapped(s, server, timeout=2.0):
    tid = os.urandom(12)
    s.settimeout(timeout)
    for _ in range(2):
        try:
            s.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + tid, server)
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                data, peer = s.recvfrom(2048)
                if peer[0] != server[0] or len(data) < 20 or data[8:20] != tid:
                    continue
                i = 20
                while i + 4 <= len(data):
                    atype, alen = struct.unpack("!HH", data[i:i + 4])
                    v = data[i + 4:i + 4 + alen]
                    if atype == 0x0020 and alen == 8:
                        return (socket.inet_ntoa(bytes(a ^ b for a, b in zip(v[4:8], b"\x21\x12\xa4\x42"))),
                                struct.unpack("!H", v[2:4])[0] ^ 0x2112)
                    if atype == 0x0001 and alen == 8:
                        return socket.inet_ntoa(v[4:8]), struct.unpack("!H", v[2:4])[0]
                    i += 4 + alen + (-alen % 4)
        except socket.timeout:
            continue
    return None


def ecn_probe(ip, port=443, timeout=2.0):
    """TCP SYN asking for ECN; returns True/False from the SYN-ACK, None without an answer. The kernel then resets it."""
    src = socket.inet_aton(F["ipv4"])
    dst = socket.inet_aton(ip)
    sport = random.randint(40000, 60000)
    hdr = struct.pack("!HHIIBBHHH", sport, port, random.getrandbits(32), 0, 5 << 4, 0x02 | 0x40 | 0x80, 64240, 0, 0)
    sum_ = checksum(src + dst + struct.pack("!BBH", 0, 6, len(hdr)) + hdr)
    hdr = hdr[:16] + struct.pack("!H", sum_) + hdr[18:]
    s = bsock(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    try:
        s.sendto(hdr, (ip, 0))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            r, _, _ = select.select([s], [], [], max(0.0, end - time.monotonic()))
            if not r:
                break
            data = s.recv(2048)
            t = data[(data[0] & 0x0F) * 4:]
            if data[12:16] == dst and struct.unpack("!HH", t[:4]) == (port, sport) and t[13] & 0x12 == 0x12:
                return bool(t[13] & 0x40)
    finally:
        s.close()
    return None


def conntrack_stress(limit):
    """Opt-in: open connections in steps until new ones fail, to find how many the router can track."""
    try:
        import resource
        limit = min(limit, resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 64)
    except (ImportError, ValueError, OSError):
        limit = min(limit, 900)
    socks, peak, failed = [], 0, False
    try:
        while len(socks) < limit and not failed:
            batch = []
            for i in range(min(100, limit - len(socks))):
                fam, sa = sockaddr(PUBLIC_V4[i % len(PUBLIC_V4)][0], 443)
                s = bsock(fam, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.connect(sa)
                except BlockingIOError:
                    pass
                except OSError:
                    s.close()
                    continue
                batch.append(s)
            end = time.monotonic() + 4
            pending = set(batch)
            while pending and time.monotonic() < end:
                _, w, _ = select.select([], list(pending), [], max(0.0, end - time.monotonic()))
                for s in w:
                    pending.discard(s)
                    if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                        socks.append(s)
                    else:
                        s.close()
            for s in pending:
                s.close()
            ok = tcp_connect(REFERENCE_V4, 443, 3)[0] == "open"
            if ok:
                peak = len(socks)
            failed = not ok or bool(pending and len(pending) > 50)
            R.progress(f"{len(socks)} connections open, new connection {'works' if ok else 'FAILS'} …")
    finally:
        for s in socks:
            s.close()
    return peak, failed


def inbound_check(helper, token):
    """Ask a helper running `nettest.py --serve` to connect back to a port opened here."""
    host, _, port = helper.rpartition(":")
    ls = bsock(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("", 0))
    ls.listen(1)
    ls.settimeout(10)
    local = ls.getsockname()[1]
    got = {}

    def accept():
        try:
            c, addr = ls.accept()
            got["peer"] = addr[0]
            c.close()
        except OSError:
            pass

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    ip = (resolve(host) or [host])[0]
    fam, sa = sockaddr(ip, int(port))
    s = bsock(fam, socket.SOCK_STREAM)
    s.settimeout(12)
    try:
        s.connect(sa)
        s.sendall(f"NETTEST1 {token} {local}\n".encode())
        answer = s.recv(64).decode(errors="replace").strip()
    finally:
        s.close()
    t.join(11)
    ls.close()
    return answer, got.get("peer"), local


def serve_helper(port, token):
    """Connect-back helper for --inbound. It only ever connects to the address that asked, and needs the token."""
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("", port))
    ls.listen(8)
    print(f"nettest helper listening on TCP port {port} (Ctrl-C stops it)", flush=True)
    try:
        while True:
            c, addr = ls.accept()
            c.settimeout(5)
            try:
                parts = c.recv(128).decode(errors="replace").split()
                if len(parts) == 3 and parts[0] == "NETTEST1" and hmac.compare_digest(parts[1].encode(), token.encode()) \
                        and parts[2].isdigit() and 1024 <= int(parts[2]) <= 65535:
                    try:
                        with socket.create_connection((addr[0], int(parts[2])), timeout=5) as back:
                            back.sendall(b"nettest-ok\n")
                        c.sendall(b"OK\n")
                    except OSError:
                        c.sendall(b"FAIL\n")
                else:
                    time.sleep(1)      # bad token or request: no answer, and guessing is slow
            except OSError:
                pass
            finally:
                c.close()
    except KeyboardInterrupt:
        print()
    finally:
        ls.close()


def test_transport_extras():
    if not F.get("inet_ok"):
        return
    R.section("L4-EXT", "L4  TRANSPORT DETAILS  (QUIC, NAT behaviour, ECN)")
    results = [(h, quic_probe(ip)) for h, ip in [(h, (resolve(h) or [None])[0]) for h in ("www.google.com", "cloudflare-quic.com")] if ip]
    ok = [(h, t) for h, t in results if t is not None]
    if results:
        F["quic_ok"] = bool(ok)
        R.add("PASS" if ok else "WARN", "QUIC / UDP 443", ", ".join(f"{h} {fmt_ms(t)} ms" for h, t in ok) if ok
              else "no QUIC server answered - UDP 443 is probably filtered; browsers fall back to TCP")
    s = bsock(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        local_port = s.getsockname()[1]
        servers = [(ips[0], port) for ips, port in ((resolve(h), p) for h, p in (("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478))) if ips]
        mapped = [m for m in (stun_mapped(s, srv) for srv in servers) if m]
    finally:
        s.close()
    if len(mapped) >= 2:
        nat = "endpoint-independent (easy peer-to-peer)" if mapped[0] == mapped[1] else "symmetric (peer-to-peer usually needs a relay)"
        F["nat_type"] = nat
        F["nat_mapped_ip"] = mapped[0][0]
        R.add("WARN" if mapped[0] != mapped[1] else "PASS", "NAT behaviour (STUN)", f"{nat}; local port {local_port} seen as {mapped[0][1]}")
        if F.get("public_ip") and mapped[0][0] != F["public_ip"]:
            R.add("INFO", "UDP public address", f"{mapped[0][0]} differs from the HTTP public address - several exit addresses")
    else:
        R.add("WARN", "NAT behaviour (STUN)", "no reply from public STUN servers - outbound UDP may be restricted")
    if ROOT and F.get("ipv4"):
        vals = {}
        for ip, _ in PUBLIC_V4[:2]:
            try:
                vals[ip] = ecn_probe(ip)
            except OSError:
                vals[ip] = None
        F["ecn"] = vals
        R.add("INFO", "ECN negotiation", ", ".join(f"{k}: {'accepted' if v else 'not accepted' if v is False else 'no answer'}" for k, v in vals.items()))
    else:
        R.add("SKIP", "ECN negotiation", "needs root")
    if ARGS.nat_timeout:
        s = bsock(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("", 0))
            srv = servers[0] if servers else None
            first = stun_mapped(s, srv) if srv else None
            expired = None
            if first:
                for idle in (30, 60, 120, 240):
                    R.progress(f"NAT idle test: waiting {idle} s …")
                    time.sleep(idle)
                    now = stun_mapped(s, srv)
                    if now != first:
                        expired = idle
                        break
                R.add("WARN" if expired and expired <= 60 else "INFO", "NAT UDP idle timeout",
                      f"mapping expired after at most {expired} s" if expired else "mapping survived 240 s idle")
        finally:
            s.close()
    if ARGS.conntrack:
        R.progress(f"connection-table test, up to {ARGS.conntrack} connections (other traffic may suffer) …")
        peak, failed = conntrack_stress(ARGS.conntrack)
        F["conntrack_peak"] = peak
        R.add("WARN" if failed else "PASS", "Connection capacity", f"new connections failed beyond about {peak} open" if failed
              else f"{peak} simultaneous connections held, new ones still worked")
    if ARGS.inbound:
        try:
            answer, peer, port = inbound_check(ARGS.inbound, ARGS.token)
            R.add("PASS" if peer else "WARN", "Inbound reachability", f"helper reached this computer on port {port} from {peer}" if peer
                  else f"helper could not connect back ({answer or 'no answer'}) - NAT, CGNAT or a firewall blocks inbound connections")
        except (OSError, ValueError) as e:
            R.add("WARN", "Inbound reachability", f"helper not usable: {describe_exc(e)}")


# --------------------------------------------------------------------------- extended checks: application

KNOWN_PUBLIC_CAS = ("Google Trust Services", "Let's Encrypt", "ISRG", "DigiCert", "Sectigo", "COMODO", "Amazon", "Microsoft",
                    "GlobalSign", "Entrust", "GoDaddy", "Starfield", "Cloudflare", "SSL.com", "IdenTrust", "Apple", "ZeroSSL",
                    "Actalis", "QuoVadis", "Baltimore", "Certum", "HARICA", "SwissSign", "Buypass", "TrustAsia")


def alpn_of(host):
    ip = (resolve(host) or [None])[0]
    if not ip:
        return None
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    fam, sa = sockaddr(ip, 443)
    raw = bsock(fam, socket.SOCK_STREAM)
    raw.settimeout(5)
    try:
        raw.connect(sa)
        s = ctx.wrap_socket(raw, server_hostname=host)
        try:
            return s.selected_alpn_protocol()
        finally:
            s.close()
    finally:
        raw.close()


def test_app_extras():
    if not F.get("https_ok"):
        return
    R.section("L7-EXT", "L7  APPLICATION DETAILS  (TLS interception, HTTP versions)")
    issuers, h3 = {}, []
    for url in HTTPS_SITES:
        host = urlparse(url).hostname
        try:
            r = http_request(url, timeout=6, max_body=4096)
        except HTTP_FAILURES:
            continue
        issuers[host] = (r.get("tls") or {}).get("issuer") or "?"
        if "h3" in r["headers"].get("alt-svc", ""):
            h3.append(host)
    unknown = {h: i for h, i in issuers.items() if not any(c.lower() in i.lower() for c in KNOWN_PUBLIC_CAS)}
    F["tls_issuers"] = issuers
    if unknown:
        F["tls_interception_suspect"] = unknown
    R.add("WARN" if unknown else "PASS", "TLS interception", "unexpected certificate issuers: " + ", ".join(f"{h} ({i})" for h, i in unknown.items())
          + " - a proxy, antivirus or network device may be inspecting HTTPS" if unknown
          else f"all {len(issuers)} sites use well-known public certificate authorities")
    vers = {}
    for host in [urlparse(u).hostname for u in HTTPS_SITES[:3]]:
        try:
            vers[host] = alpn_of(host) or "none"
        except HTTP_FAILURES:
            vers[host] = "failed"
    h2 = sum(v == "h2" for v in vers.values())
    R.add("PASS" if h2 else "WARN", "HTTP versions", ", ".join(f"{h}: {v}" for h, v in vers.items())
          + (f"; HTTP/3 offered by {', '.join(h3)}" if h3 else "; HTTP/3 not offered"))


# --------------------------------------------------------------------------- extended checks: performance

ALT_SPEED_SERVERS = [("OVH, FR", "https://proof.ovh.net/files/100Mb.dat"), ("Tele2, SE", "http://speedtest.tele2.net/100MB.zip")]


def voip_mos(avg, jit, loss):
    """E-model estimate of call quality, 1 (bad) to 4.4 (best for narrowband)."""
    eff = avg + 2 * jit + 10
    r = 93.2 - eff / 40 if eff < 160 else 93.2 - (eff - 120) / 10
    r = max(0.0, min(100.0, r - 2.5 * loss))
    return 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)


def responsiveness(probes=6):
    """Round trips per minute from fresh TCP+TLS+HTTP exchanges (3 round trips each)."""
    rtts = []
    for _ in range(probes):
        try:
            r = http_request(SPEED_DOWN_URL + "1", timeout=6, max_body=1024)
            rtts.append(r["timing"]["ttfb_ms"] / 3)
        except HTTP_FAILURES:
            pass
        time.sleep(0.2)
    return 60000 / mean(rtts) if rtts else None


def iperf_run(host, reverse):
    cmd = ["iperf3", "-c", host, "-t", "5", "-J"] + (["-B", F["ipv4"]] if F.get("ipv4") else []) + (["-R"] if reverse else [])
    rc, out, err = run(cmd, timeout=25)
    d = json.loads(out)
    if d.get("error"):
        raise ValueError(d["error"])
    end = d["end"]
    return end["sum_received"]["bits_per_second"] / 1e6, end["sum_sent"].get("retransmits")


def test_performance_extras():
    if not F.get("down_mbps") or ARGS.quick:
        return
    R.section("PERF-EXT", "PERFORMANCE DETAILS  (other servers, stream counts, responsiveness, call quality)")
    base = F["down_mbps"]
    speeds = {}
    for name, url in ALT_SPEED_SERVERS:
        R.progress(f"download from {name}, 6 s …")
        mbps, _, _, errs = transfer("down", 6, 4, url=url)
        if mbps >= 0.1:
            speeds[name] = mbps
            R.add("INFO", f"Download from {name}", f"{mbps:.1f} Mb/s")
        else:
            R.add("SKIP", f"Download from {name}", errs[0] if errs else "no data")
    F["alt_server_mbps"] = speeds
    if speeds:
        best = max(speeds.values())
        verdict = (f"other servers are much faster ({best:.0f} vs {base:.0f} Mb/s) - the main test server was the limit" if best > base * 1.5
                   else f"every server tops out near {max(best, base):.0f} Mb/s - the limit is on your side of them (ISP plan, router or link)"
                   if all(v <= base * 1.3 and v >= base * 0.5 for v in speeds.values())
                   else "servers differ, so routing to each one matters as well")
        R.add("INFO", "Server comparison", verdict)
    R.progress("download with a single stream, 6 s …")
    single = transfer("down", 6, 1)[0]
    if single >= 0.1:
        R.add("WARN" if base > single * 2 else "INFO", "Single vs multi-stream", f"1 stream {single:.1f} Mb/s, 4 streams {base:.1f} Mb/s"
              + (" - single connections are limited (per-flow shaping or loss)" if base > single * 2 else ""))
    R.progress("download and upload at the same time, 8 s …")
    both = {}
    ts = [threading.Thread(target=lambda k=k: both.__setitem__(k, transfer(k, 8, 3)[0]), daemon=True) for k in ("down", "up")]
    for t in ts:
        t.start()
    for t in ts:
        t.join(25)
    if both.get("down") and both.get("up"):
        R.add("INFO", "Simultaneous up and down", f"{both['down']:.1f} Mb/s down + {both['up']:.1f} Mb/s up")
    idle = ping(REFERENCE_V4, count=20, interval=0.2)
    rpm_idle = responsiveness()
    load = {}
    th = threading.Thread(target=lambda: load.update(t=transfer("down", 8, 4)), daemon=True)
    th.start()
    time.sleep(2)
    rpm_load = responsiveness()
    th.join(20)
    if rpm_idle and rpm_load:
        F["rpm"] = {"idle": round(rpm_idle), "loaded": round(rpm_load)}
        R.add("WARN" if rpm_load < 200 else "PASS", "Responsiveness (approx. RPM)", f"{rpm_idle:.0f} idle, {rpm_load:.0f} under load"
              + (" - the connection feels sluggish when busy" if rpm_load < 200 else ""))
    lp = (load.get("t") or (0, 0, None, 0))[2]
    if idle["avg"] is not None:
        m = voip_mos(idle["avg"], idle["jitter"] or 0, idle["loss"])
        F["mos_idle"] = round(m, 2)
        text = f"MOS {m:.1f} idle"
        worst = m
        if lp and lp["avg"] is not None:
            worst = voip_mos(lp["avg"], lp["jitter"] or 0, lp["loss"])
            F["mos_loaded"] = round(worst, 2)
            text += f", {worst:.1f} during a download"
        R.add("WARN" if worst < 3.6 else "PASS", "Call quality estimate", text + " (4.0 and up is good)")
    if ARGS.iperf:
        if not shutil.which("iperf3"):
            R.add("SKIP", "iperf3", "iperf3 is not installed")
            return
        try:
            up, retr = iperf_run(ARGS.iperf, False)
            down, _ = iperf_run(ARGS.iperf, True)
            F["iperf"] = {"up": round(up, 1), "down": round(down, 1)}
            R.add("INFO", f"iperf3 to {ARGS.iperf}", f"{down:.0f} Mb/s down, {up:.0f} Mb/s up, {retr} retransmits")
            if down > base * 2:
                R.add("INFO", "Local vs internet", f"this host is reached at {down:.0f} Mb/s but the internet at {base:.0f} Mb/s - "
                      "the local link is not the bottleneck")
            elif down < base * 1.2:
                R.add("INFO", "Local vs internet", "the path to this host is about as slow as the internet - the local link may be the bottleneck")
        except (ValueError, KeyError, TypeError) as e:
            R.add("WARN", "iperf3", f"failed: {e}")


# --------------------------------------------------------------------------- history and baselines

def saved_reports():
    """(file name, report) of every readable saved report, newest first."""
    try:
        names = sorted((n for n in os.listdir(ARGS.outdir) if n.startswith("nettest-") and n.endswith(".json")), reverse=True)
    except OSError:
        return
    for n in names:
        try:
            with open(os.path.join(ARGS.outdir, n)) as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(d, dict):
            yield n, d


def read_saved_reports(limit=40):
    return [d for n, d in itertools.islice(saved_reports(), limit) if d.get("interface") == IFACE]


def identity_of(facts):
    v6 = facts.get("v6_global_addrs") or []
    prefix = str(ipaddress.ip_network(f"{v6[0]}/64", strict=False)) if v6 else None
    gw = facts.get("gw_mac")
    return {"IPv6 prefix": prefix, "public IPv4": facts.get("public_ip"), "public IPv6": facts.get("v6_public_ip"), "router": facts.get("gateway"),
            "router MAC": ", ".join(gw) if isinstance(gw, list) and gw else None, "Wi-Fi access point": (facts.get("wifi") or {}).get("bssid")}


def report_history():
    now = datetime.datetime.now().astimezone()
    runs = []
    for d in read_saved_reports():
        try:
            when = datetime.datetime.fromisoformat(d["started"])
        except (KeyError, ValueError):
            continue
        if now - when <= datetime.timedelta(days=7):
            runs.append((when, identity_of(d.get("facts") or {})))
    runs.append((now, identity_of(F)))
    runs.sort(key=lambda x: x[0])
    if len(runs) < 2:
        return
    R.section("HISTORY", f"HISTORY  (stability over {len(runs)} runs in the last 7 days)")
    for field in runs[-1][1]:
        seq = [(w, v[field]) for w, v in runs if v[field]]
        changes = sum(a[1] != b[1] for a, b in zip(seq, seq[1:]))
        distinct = list(dict.fromkeys(v for _, v in seq))
        if len(seq) < 2 or not changes:
            continue
        unstable = (field == "IPv6 prefix" and len(distinct) >= 3) or field in ("router MAC", "router")
        F.setdefault("history_changes", {})[field] = {"changes": changes, "distinct": distinct[-5:]}
        R.add("WARN" if unstable else "INFO", f"{field} changed", f"{changes} changes, {len(distinct)} different values between {seq[0][0]:%d.%m %H:%M} and "
              f"{seq[-1][0]:%d.%m %H:%M}" + (" - unexpected for a stable network" if unstable else ""))
    if not F.get("history_changes"):
        R.add("PASS", "Identity stability", "addresses and router identity did not change")


def compare_reports(path):
    R.section("BASELINE", f"COMPARED WITH  {os.path.basename(path)}")
    try:
        with open(path) as f:
            old = json.load(f)
    except (OSError, ValueError) as e:
        R.add("SKIP", "Baseline", f"cannot read it: {e}")
        return
    rank = {"PASS": 0, "INFO": 0, "SKIP": 0, "WARN": 1, "FAIL": 2}
    before = {r["name"]: r["status"] for r in old.get("results", [])}
    worse, better = [], []
    for r in list(R.results):
        was = before.get(r["name"]) if r["name"] != "Privileges" else None
        if was and rank.get(r["status"], 0) != rank.get(was, 0):
            (worse if rank[r["status"]] > rank[was] else better).append(f"{r['name']} ({was} -> {r['status']})")
    R.add("WARN" if worse else "PASS", "Got worse", ", ".join(worse[:30]) or "nothing")
    R.add("INFO", "Got better", ", ".join(better[:30]) or "nothing")
    of = old.get("facts") or {}
    for key, label, higher_better in (("down_mbps", "Download Mb/s", True), ("up_mbps", "Upload Mb/s", True), ("idle_rtt", "Idle latency ms", False)):
        a, b = of.get(key), F.get(key)
        if isinstance(a, (int, float)) and isinstance(b, (int, float)) and a:
            pct = 100.0 * (b - a) / a
            bad = (pct < -25) if higher_better else (pct > 50)
            R.add("WARN" if bad else "INFO", label, f"{a:.1f} -> {b:.1f} ({pct:+.0f}%)")


# --------------------------------------------------------------------------- packet capture and HTML report

class FlightRecorder(threading.Thread):
    """Keeps the most recent frame headers in memory; written to a pcap only if a check fails."""

    SNAP = 256

    def __init__(self, keep=50000):
        super().__init__(daemon=True)
        self.frames = collections.deque(maxlen=keep)
        self.halt = threading.Event()
        self.sock = packet_socket(ETH_P_ALL)

    def run(self):
        while not self.halt.is_set():
            r, _, _ = select.select([self.sock], [], [], 0.5)
            if r:
                try:
                    d = self.sock.recv(65535)
                except OSError:
                    return
                self.frames.append((time.time(), len(d), d[:self.SNAP]))

    def save(self, path):
        self.halt.set()
        frames = list(self.frames)
        with private_open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, self.SNAP, 1))
            for ts, orig, d in frames:
                f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(d), orig) + d)
        return len(frames)


def html_report():
    colors = {"PASS": "#2e7d32", "WARN": "#b26a00", "FAIL": "#c62828", "INFO": "#1565c0", "SKIP": "#757575"}
    counts = {s: sum(r["status"] == s for r in R.results) for s in colors}
    rows, layer = [], None
    for r in R.results:
        if r["layer"] != layer:
            layer = r["layer"]
            rows.append(f'<tr class="layer"><th colspan="3">{html.escape(str(layer))}</th></tr>')
        rows.append(f'<tr><td><b style="color:{colors[r["status"]]}">{r["status"]}</b></td><td>{html.escape(r["name"])}</td>'
                    f'<td>{html.escape(r["detail"])}</td></tr>')
    summary = " · ".join(f'<b style="color:{colors[s]}">{n} {s}</b>' for s, n in counts.items() if n)
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>nettest report</title>"
            "<style>body{font:15px system-ui,sans-serif;margin:16px auto;max-width:1100px;padding:0 16px;color:#222;background:#fff}"
            "table{border-collapse:collapse;width:100%}td,th{padding:5px 8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top;overflow-wrap:anywhere}"
            ".layer th{background:#eee;padding-top:10px}@media(prefers-color-scheme:dark){body{background:#181a1b;color:#ddd}.layer th{background:#2a2d2f}td,th{border-color:#3a3d40}}"
            "</style>"
            f"<h1>nettest report</h1><p>{html.escape(str(IFACE))} · {html.escape(R.started.isoformat(timespec='seconds'))} · {summary}</p>"
            f"<table>{''.join(rows)}</table>")


def on_terminate(_signum, _frame):
    """SIGTERM / SIGHUP take the same cleanup path as Ctrl-C, so system settings are always restored."""
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    raise KeyboardInterrupt


def main():
    global IFACE, IFINDEX, ARGS, RECORDER
    ap = argparse.ArgumentParser(description="Layered network diagnostics (IPv4 + IPv6) for any network interface.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Usage:")[1])
    ap.add_argument("-i", "--iface", help="interface to test (default: ask which one)")
    ap.add_argument("--gateway", help="override the IPv4 router address")
    ap.add_argument("--quick", action="store_true", help="shorter run: skip burst/port scan, shorter trace & speed test")
    ap.add_argument("--no-speed", action="store_true", help="skip throughput / bufferbloat test")
    ap.add_argument("--no-dhcp-probe", action="store_true", help="do not send DHCPv4/DHCPv6 probes")
    ap.add_argument("--no-scan", action="store_true", help="skip LAN discovery (passive listen, ARP scan, IPv6 scan)")
    ap.add_argument("--arp-scan", action="store_true", help="run the ARP scan even on --quick or a network that looks managed")
    ap.add_argument("--active-dhcp", action="store_true",
                    help="also send DISCOVER/REQUEST/SOLICIT probes when the interface already has an address")
    ap.add_argument("--wifi-scan", action="store_true", help="active Wi-Fi scan as root (the radio briefly leaves its channel)")
    ap.add_argument("--peer", metavar="IP", help="second device on the LAN, for the client isolation check")
    ap.add_argument("--iperf", metavar="HOST", help="also measure against an iperf3 server, e.g. on your LAN")
    ap.add_argument("--nat-timeout", action="store_true", help="measure the NAT UDP idle timeout (takes up to 7.5 min)")
    ap.add_argument("--conntrack", type=int, metavar="N", help="open up to N connections to find the router's limit (stresses the router)")
    ap.add_argument("--inbound", metavar="HOST:PORT", help="check inbound reachability via a helper running --serve (needs --token)")
    ap.add_argument("--serve", type=int, metavar="PORT", help="run as the connect-back helper for --inbound (needs --token)")
    ap.add_argument("--token", help="shared secret for --inbound / --serve")
    ap.add_argument("--compare-report", metavar="FILE", help="show what changed since a saved JSON report")
    ap.add_argument("--pcap", action="store_true", help="as root, keep recent frame headers and save a pcap if a check fails")
    ap.add_argument("--force", action="store_true", help="let --fix-driver / --cable-test run on a working connection (drops it)")
    ap.add_argument("--passive", type=int, default=8, help="seconds of passive listening in LAN discovery (default 8)")
    ap.add_argument("--update-oui", action="store_true", help="re-download the MAC vendor list into ./data/")
    ap.add_argument("--no-oui-download", action="store_true",
                    help="never download the MAC vendor list (use only locally installed databases)")
    ap.add_argument("--compare", nargs="?", const="auto", metavar="IFACE",
                    help="also measure over another interface (default: the other link with a default route, e.g. Wi-Fi)")
    ap.add_argument("--fix-driver", action="store_true",
                    help="if an ASIX/Realtek adapter sits on the generic cdc_ncm/cdc_ether driver, switch it to the "
                         "vendor driver before testing (root; lasts until re-plug)")
    ap.add_argument("--cable-test", action="store_true", help="run the PHY cable test (drops the link briefly; rarely supported)")
    ap.add_argument("--link-watch", type=int, default=10, help="seconds to watch the carrier for flaps (default 10)")
    ap.add_argument("--monitor", type=float, metavar="MIN", help="after the tests, monitor for MIN minutes (0 = until Ctrl-C)")
    ap.add_argument("--monitor-only", type=float, metavar="MIN", help="skip the full test, only monitor (0 = until Ctrl-C)")
    ap.add_argument("--outdir", default=os.path.join(os.getcwd() if INSTALLED else _HERE, "reports"),
                    help="where to save reports (default: ./reports next to the script)")
    ap.add_argument("--no-color", action="store_true")
    ARGS = ap.parse_args()
    if (ARGS.serve or ARGS.inbound) and not ARGS.token:
        ap.error("--serve and --inbound need --token")
    if ARGS.serve:
        serve_helper(ARGS.serve, ARGS.token)
        return 0
    if ARGS.no_color:
        Color.on = False
    if ARGS.quick:
        ARGS.link_watch = min(ARGS.link_watch, 3)
        ARGS.passive = min(ARGS.passive, 4)
    ARGS.passive = max(1, ARGS.passive)
    if not ROOT:
        print(Color.c("33;1", "Not running as root: DHCP, ARP/NDP, LAN discovery and raw traceroute probes are skipped.\n"
                              "For a complete result run:  sudo python3 " + sys.argv[0]))

    signal.signal(signal.SIGTERM, on_terminate)
    signal.signal(signal.SIGHUP, on_terminate)
    interrupted = False
    try:
        test_environment()
        IFACE = select_iface()
        if not IFACE:
            R.section("L1", "L1  ADAPTER")
            R.add("FAIL", "Network interface", "none found. Is the adapter plugged in? Interfaces: "
                  + ", ".join(sorted(os.listdir("/sys/class/net"))))
            _, out, _ = run(["lsusb"])
            for l in out.splitlines():
                R.note(l)
            R.note("If the adapter is in the list above but has no interface, the driver is missing; "
                   "check `sudo dmesg | tail -30`. To test another NIC use --iface.")
            F["iface_found"] = False
            verdict()
            save_reports()
            return 2
        IFINDEX = socket.if_nametoindex(IFACE)
        R.add("PASS", "Interface under test", f"{IFACE} ({iface_kind(IFACE)})")
        if ARGS.fix_driver:
            guarded(fix_driver)

        if ARGS.monitor_only is not None:
            monitor_setup()
            watched_monitor(ARGS.monitor_only)
            save_reports()
            return 0

        if ARGS.pcap and ROOT:
            try:
                RECORDER = FlightRecorder()
                RECORDER.start()
            except OSError as e:
                R.add("SKIP", "Packet capture", describe_exc(e))
        elif ARGS.pcap:
            R.add("SKIP", "Packet capture", "needs root")
        guarded(test_physical)
        if F.get("iface_kind") == "wifi" and F.get("carrier"):
            guarded(test_wifi_quality)
        guarded(test_physical_extras)
        gather_addressing()
        if not (F.get("carrier") and F.get("admin_up")):
            R.section("L2", "L2+  SKIPPED")
            R.add("SKIP", "Higher layers", "no link - nothing above layer 1 can work")
        else:
            guarded(test_datalink)
            guarded(test_datalink6)
            guarded(test_discovery)
            guarded(test_link_extras)
            guarded(test_lan)
            if F.get("gw_ok") or F.get("default_route"):
                guarded(test_wan, False)
            guarded(test_wan, True)
            guarded(test_dns)
            guarded(test_dns_extras)
            guarded(test_transport)
            guarded(test_transport_extras)
            guarded(test_application)
            guarded(test_path_extras)
            guarded(test_app_extras)
            guarded(test_router)
            if not ARGS.no_speed and F.get("inet_ok"):
                guarded(test_performance)
                guarded(test_performance_extras)
        if ARGS.compare:
            guarded(compare_interfaces, ARGS.compare)
        guarded(counters_delta)
        guarded(report_history)
        if ARGS.compare_report:
            guarded(compare_reports, ARGS.compare_report)
        verdict()
        if ARGS.monitor is not None and F.get("carrier"):
            watched_monitor(ARGS.monitor)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        interrupted = True
    finally:
        restore_sysctls()
    save_reports()
    return 130 if interrupted else 1 if run_failed() else 0


if __name__ == "__main__":
    sys.exit(main())
