# nettest

Layered network diagnostics for Linux. `nettest.py` tests one interface (Ethernet, USB adapter or
Wi-Fi) from the link up to HTTPS, over both IPv4 and IPv6, and tells you the first layer that fails.

It is a single Python 3 file with no dependencies beyond the standard library.

## Usage

```bash
sudo python3 nettest.py                # asks which interface to test
sudo python3 nettest.py -i wlan0       # test a specific interface
sudo python3 nettest.py --monitor-only 0   # watch for intermittent drops until Ctrl-C
```

It needs `ip` and `ping`, and uses `ethtool`, `iw`, `nmcli`, `resolvectl`, `journalctl` and `mtr`
when available. Without root, the low-level probes (DHCP, ARP/NDP, LAN discovery, raw traceroute)
are skipped and the rest still runs.

## What it checks

Adapter and link, Wi-Fi signal, DHCP, ARP/NDP, router reachability, path and MTU to the internet,
DNS, DNSSEC, TCP, QUIC, NAT behaviour, HTTPS and TLS interception, throughput, responsiveness and
call quality under load, and how addresses changed between runs. It ends with a diagnosis of the
most likely problem, and writes text, JSON and HTML reports.

## Safe on a working connection

- An interface that already has an address keeps it: no DHCP request or renewal is sent.
  `--active-dhcp` adds the DISCOVER, REQUEST and SOLICIT probes.
- `--fix-driver` and `--cable-test` drop the link, so they refuse on a working connection unless
  you add `--force`.
- The ARP scan is slow (12.5 packets/s) and skipped on networks that look managed.
- The speed test takes about 70 s, uses data and loads your connection; skip it with `--no-speed`.
- Anything that stresses the router or needs a helper is off by default, such as `--conntrack` and
  `--inbound`.

Only run it on networks you are allowed to test.

The tool contacts public services (Cloudflare, Google, Quad9, OpenDNS, OVH, Tele2, RIPEstat, portquiz.net and others) to
measure connectivity. Reports are saved to `reports/`, readable only by you. They contain addresses
and device names from your network, so review them before sharing.

The exit status is 0 if nothing failed, 1 if any check reported FAIL, 2 if the interface does not
exist and 130 if interrupted.

See [docs/DETAILS.md](docs/DETAILS.md) for all options and how to read the results.
