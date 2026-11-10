# nettest — layered network diagnostics (IPv4 + IPv6)

`nettest.py` tests a network connection (Ethernet, USB adapter, Wi-Fi, ...) layer by layer, from the link up to HTTPS, for
**both IPv4 and IPv6**. It then reports **the first layer that fails**, which is where the problem
most likely is. It also shows what else is visible on the LAN.

It makes no assumptions about the network it is plugged into. It works the same behind DSL, cable,
fibre, mobile (LTE/5G), satellite or fixed-wireless routers, with or without IPv6, NAT, CGNAT or
DS-Lite. Every probe is bound to the tested interface, so another link on the same computer (e.g.
Wi-Fi) cannot hide or fake a result.

It is a single Python 3 file and uses only the standard library. It needs `ip` and `ping`; it also
uses `ethtool`, `iw`, `nmcli`, `resolvectl`, `journalctl` and `mtr` when they are installed.

## Run it

Connect the interface you want to test (for a wired test, usually to a LAN port of the router), then:

```bash
sudo python3 nettest.py
```

Without `--iface` the tool lists the interfaces and asks which one to test (Enter picks the one
with the default route). With no terminal to ask on, `--iface NAME` is required. Root is needed for the low-level probes (DHCP/DHCPv6, ARP/NDP, LAN scan, passive
listening, raw traceroute, kernel counters). Without root those probes are skipped and the rest
still runs.

| Option | What it does |
|---|---|
| `--iface NAME` | test this interface (default: ask which one) |
| `--quick` | shorter run (no burst/port scan, shorter trace, passive listen and speed test) |
| `--no-speed` | skip the throughput / bufferbloat test (use on metered connections) |
| `--no-dhcp-probe` | don't send DHCPv4 / DHCPv6 probes |
| `--no-scan` | skip LAN discovery (passive listen, ARP scan, IPv6 neighbor scan) |
| `--passive 20` | listen passively for 20 s instead of 8 |
| `--compare [NAME]` | also measure over another link (default: any other interface with a default route) and say which side the problem is on |
| `--monitor 30` | after the tests, watch IPv4 and IPv6 for 30 minutes (`0` = until Ctrl-C) |
| `--monitor-only 0` | only watch, starting right away; best for **intermittent** drops |
| `--update-oui` / `--no-oui-download` | refresh / never download the MAC vendor list (see below) |
| `--fix-driver` | if an ASIX or Realtek adapter is on the generic `cdc_ncm`/`cdc_ether` driver, switch it to the vendor driver (`ax88179_178a` / `r8152`) before testing; root, lasts until re-plug |
| `--cable-test` | PHY cable test (drops the link briefly; few adapters support it) |
| `--wifi-scan` | active Wi-Fi scan as root, for an up-to-date list of neighbouring networks; the radio briefly leaves its channel |
| `--peer IP` | second device on the LAN, for the client isolation check |
| `--iperf HOST` | also measure against an iperf3 server, for example on your LAN, to separate local from internet speed |
| `--nat-timeout` | measure how long the NAT keeps an idle UDP mapping (up to 7.5 minutes) |
| `--conntrack N` | open up to N connections to find the router's limit; **stresses the router and can disturb other traffic** |
| `--serve PORT --token T` | run on an outside machine as the connect-back helper for `--inbound` |
| `--inbound HOST:PORT --token T` | check whether connections from outside can reach this computer; the token is sent unencrypted, so use a throwaway one |
| `--compare-report FILE` | show what got better or worse since a saved JSON report |
| `--pcap` | as root, keep recent frame headers in memory and save a pcap if a check fails; it can include LAN traffic metadata, so review it before sharing |
| `--force` | let `--fix-driver` / `--cable-test` run on a connected, addressed interface; without it they refuse, because they drop the connection |
| `--active-dhcp` | also send the DHCP DISCOVER/REQUEST and DHCPv6 SOLICIT probes when the interface already has an address |
| `--arp-scan` | run the ARP scan even with `--quick` or on a network that looks managed |

Each run saves a text and a JSON report in `reports/`, readable only by you. Monitor mode also
writes a per-second CSV log. The exit status is 0 when nothing failed, 1 when a check reported FAIL,
2 when no interface exists and 130 when interrupted.

## Is there a real connection?

The physical layer section ends with one plain answer:

| Result | Meaning |
|---|---|
| **NO LINK** | no electrical signal: cable unplugged or broken, the device at the other end is off, or its port is dead or disabled |
| **CARRIER ONLY** | the electrical link is up but no frames arrive from the other side, even after the tool asks the router to answer (router solicitation, ARP, DHCP). The far port blocks traffic (802.1X, port security, wrong VLAN), the device there is hung, or it is a passive box |
| **REAL CONNECTION** | the link is up and frames arrive; it shows how many, and from which devices |

Around that it reports:
- the negotiated speed and duplex compared with what both ends support (a damaged pair typically
  drops a gigabit link to 100 Mb/s);
- whether the link partner auto-negotiates;
- link flaps, both in history and during a live watch;
- error counters before and after the test;
- USB bus speed and autosuspend for USB adapters;
- SSID, band, signal strength and negotiated bitrate for Wi-Fi (needs `iw`);
- when the link last came up, from the kernel log.

## Generic vs. vendor USB driver

Many ASIX (AX88179A/B) and Realtek (RTL815x) adapters have two USB interfaces: a vendor-specific one and a
standard CDC (NCM/ECM) one. If the active interface is the CDC one, Linux binds the generic `cdc_ncm` or
`cdc_ether` driver. With some chips the result is a link that comes up but never receives a frame. The tool reads
the adapter's USB descriptors and reports this case under **Driver choice**. When the adapter also has a
vendor-specific interface, `--fix-driver` moves the adapter to the vendor driver for the run and prints a
udev rule that makes the change permanent. When the firmware has only the CDC interface, the tool says so, because
the vendor driver cannot take that adapter.

## What is tested

| Layer | IPv4 | IPv6 |
|---|---|---|
| L1 Physical | see above | (shared) plus duplicate-address messages from the kernel |
| L2 Link | **DHCP probes**: <br>• standard DISCOVER: checks option consistency, lease, MTU, DNS and which server answers <br>• DISCOVER from a random new client: is the address pool exhausted? <br>• DISCOVER without the broadcast flag <br>• REQUEST for an address the server must reject: is the server authoritative? <br>• INFORM <br>Every answering server is listed (rogue DHCP). ARP to the router; IP conflicts for the gateway and own address | **Router Solicitation**: each Router Advertisement is decoded (flags, router lifetime, prefixes and their lifetimes, MTU, DNS servers, routes). Flags multiple/rogue routers, a lifetime of 0 (no IPv6 uplink), local-only (ULA) prefixes, failed address autoconfiguration and withdrawn prefixes. NDP to the router, **DHCPv6 SOLICIT / INFORMATION-REQUEST**, duplicate address detection |
| LAN discovery | **passive listen**: broadcast storm / loop, unicast flooding, LLDP (switch name and port), STP, CDP, VLAN tags, PPPoE leaking into the LAN, DHCP and RA speakers, gratuitous ARP, mDNS/SSDP/LLMNR/NetBIOS, malformed frames. **ARP scan**: conflicts, proxy ARP, multi-homed devices | all-nodes / all-routers multicast ping plus NDP for MACs |
| | **device table**: MAC, manufacturer, IPv4, IPv6, name (local DNS or DHCP hostname), role (gateway, DHCP server, IPv6 router, this computer) | |
| L3 LAN | address (APIPA), default route, route priority, rp_filter and ARP-flux safety, router ping, burst, 1500-byte frames, router TCP stack | global/ULA addresses, default route, router ping, 1500-byte packets |
| L3 WAN | public anycast pings; mtr-style traceroute with per-hop loss and reverse DNS. It separates real loss from ICMP rate limiting, decodes the router's "unreachable" answers ("no route" vs "filtered"), and tries a TCP-SYN traceroute where ICMP stops. Recognises double NAT, ISP-internal private networks, CGNAT and DS-Lite; measures the ISP edge hop, path MTU / black holes, and reachability of distant non-anycast destinations | the same over IPv6 |
| DNS | router/ISP and public resolvers over UDP and TCP, NXDOMAIN hijacking, "alive but no upstream" answers, DNS-over-TLS | resolvers from RA, DHCPv6 and the system (including link-local) over IPv6 transport |
| L4 | TCP reachability, outbound port filtering, TCP MSS vs. path MTU, NTP and clock offset | the same over IPv6 |
| L7 | captive portal / transparent proxy, HTTPS with certificate validation and timings, DNS-over-HTTPS, public address | the same over IPv6 (sites without IPv6 are skipped) |
| Router / WAN | router web UI fingerprint; WAN status from routers that publish it: UPnP-IGD, TR-064 (e.g. FRITZ!Box: physical link, DSL sync), Huawei HiLink mobile routers (connection, network type, SIM, data switch, session age, data volume); management pages of an upstream modem/ONT at common addresses | |
| Performance | multi-stream download/upload, latency and loss under load (bufferbloat grade) | IPv6 download compared with IPv4 |
| Comparison | the same targets over a second link side by side, with a verdict | |

Router integrations are optional: they run only when the router answers them. Without one, the
tool still diagnoses the WAN from the outside (traceroute, unreachable codes, DNS behaviour,
comparison).

## MAC address manufacturers

MAC addresses are shown with their manufacturer, using the longest matching IEEE assignment: 24-bit
(MA-L), 28-bit (MA-M) or 36-bit (MA-S). Randomized (locally administered) and multicast addresses
are labelled as such. The tool reads every database it finds: Wireshark's `manuf`, IEEE `oui.csv`/
`mam.csv`/`oui36.csv`/`oui.txt` (package `ieee-data`), `hwdata`, `arp-scan` and `nmap`.

If none is installed, it downloads Wireshark's vendor list once (about 3 MB) into `data/manuf`
next to the script, over the computer's normal internet route. Use `--update-oui` to refresh it,
or `--no-oui-download` to never download.

## Reading the result

The **DIAGNOSIS** section shows two ladders, one for IPv4/link and one for IPv6, e.g.:

```
IPv4 / link:
[PASS] Adapter & driver
[PASS] Physical link (cable/port)
[FAIL] LAN data link (DHCP/ARP)       IP address conflict on the LAN
IPv6:
[WARN] IPv6 router (RA/NDP)           2 routers send RAs (rogue/second router)
>>> MOST LIKELY PROBLEM: LAN DATA LINK ...
```

The first `FAIL` in a ladder is where to look; everything above it in that ladder was tested and
works. If IPv4 is fine but IPv6 fails, the tool says so separately. Broken IPv6 often feels like
"slow or randomly hanging internet", because apps try IPv6 first.

If everything passes but the problem comes and goes, run `sudo python3 nettest.py --monitor-only 0`
and leave it running until the problem happens. The monitor:

* logs every outage with its family and type: `LINK DOWN` (adapter, cable or Wi-Fi association), `LAN DOWN` (router
  stopped answering), `WAN DOWN` (router fine, uplink gone), `INTERNET DOWN` (ISP edge fine,
  nothing beyond) or `DNS FAIL`;
* judges each second 3 s after sending, so slow links (satellite, a loaded mobile link) show high
  latency instead of false loss;
* re-binds automatically when the adapter is reset or re-plugged;
* takes a **snapshot when an outage starts**: where the path ends now, the router's DNS answer, the
  router's own status when it publishes one, and the IPv6 router advertisement;
* polls the WAN identity every 60 s and logs **WAN events**: public IPv4 or IPv6 prefix changes
  (reconnects), router session restarts, mobile network or signal changes where the router reports
  them, likely router reboots;
* ends with a **pattern**: FLAPPING, DEGRADED, LATENCY SPIKES or STABLE.

### Extended checks

| Layer | What is measured |
|---|---|
| Wi-Fi | transmit retries, beacon loss, power save, channel utilisation (if the driver reports it), neighbouring networks, security type, regulatory domain, roaming this boot |
| Physical | optical module levels and alarms, per-queue NIC errors |
| Data link | 802.1X, jumbo frames (only if the interface MTU is already above 1500), client isolation, router MAC changes while monitoring |
| Network | path MTU with real TCP, load balancing on the path (root), IPv6 extension headers and fragments (root), RPKI status of your prefix via RIPEstat |
| DNS | DNSSEC validation, large answers over UDP, rebinding protection, per-link DNS and VPN split DNS |
| Transport | QUIC on UDP 443, NAT type via STUN, ECN (root), TCP retransmits and out-of-order arrivals during the speed test |
| Application | certificate issuers against well-known public CAs, HTTP/2 and HTTP/3 |
| Performance | a second and third download server, single vs multi-stream, simultaneous up and down, approximate responsiveness (RPM), call quality estimate (MOS) |
| History | changes in IPv6 prefix, public address, router and access point across the last 7 days of saved reports |

Each run also writes an HTML report next to the text and JSON reports. The JSON format is described in
[report.schema.json](report.schema.json).

Install as a command with `pipx install .`. Use `sudo pipx install --global .` if you run it as root, so
root never executes code from a folder your user can write to.

### About the probes

* **An interface that already has an address is left alone:** only DHCP INFORM and DHCPv6
  INFORMATION-REQUEST are sent, which ask for settings and involve no lease. The probes below run
  only when it has no address, or with `--active-dhcp`.
* **DHCP:** the probes never take a lease. They send DISCOVER (no REQUEST follows), INFORM, and one
  REQUEST for an address from the reserved documentation range 192.0.2.0/24 (RFC 5737). No real
  network uses that range, so a correct server must reject it. The "new device" and reject probes
  use random, locally administered client MACs; some servers hold an offered address for a few
  seconds.
* **ARP scan:** one request per address in the local subnet (at most a /22; larger subnets are
  limited to the local /24), 12.5 packets/s, so about 20 s for a /24. It is skipped with `--quick` and
  on networks that look managed (STP, CDP, LLDP or VLAN tags seen, or larger than a /24), where
  switches can shut a port for ARP bursts; `--arp-scan` runs it anyway.
* **Speed test:** downloads and uploads for about 70 s in total, which uses data volume on metered
  connections; skip it with `--no-speed`.
* **Other interfaces on the same subnet:** Linux answers ARP for any of its addresses on every
  interface ("ARP flux"), so the router may send this interface's replies to the other one. As
  root the tool pins ARP to the owning interface for the duration of the run and restores the
  setting at exit, including on Ctrl-C, SIGTERM and a closed terminal (not SIGKILL); without root
  it warns.

Turn these off with `--no-dhcp-probe`, `--no-scan` and `--no-speed` where needed.

Not included on purpose: logging in to the router with its password, and PPPoE/VLAN probes towards
the ISP with the computer plugged straight into a modem.
