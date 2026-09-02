#!/usr/bin/env python3
"""NetNeighbors LAN scanner.

Answers one question: "who is on this network right now?"

The scan is deliberately rootless and dependency-free:

1. Find the primary IPv4 subnet (scope-global addresses via `ip -j`).
2. Gently probe every address on it with a UDP datagram to port 9
   (discard). No reply is needed for discovery: simply addressing a host
   makes the kernel resolve it with ARP, so every host that is awake ends
   up in the neighbor table with a MAC address - firewalls included.
3. Read the kernel neighbor table (`ip -j neigh show` / /proc/net/arp)
   and report every host that answered.
4. Best-effort names: reverse DNS in parallel threads, then an mDNS
   reverse sweep through avahi-resolve when it is installed.
5. MAC vendor lookup: /usr/share/hwdata/oui.txt (Arch ships it with
   hwdata), /usr/share/ieee-data/oui.txt, then the bundled oui.json.
6. Remember what was seen before (plain JSON under ~/.local/share) so
   freshly appearing MACs can be flagged as NEW.

Output: a single JSON object on stdout.

Only ever touches hosts on the local subnet you are already connected to,
sends a handful of small UDP datagrams per scan, and needs no privileges.
"""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

PLUGIN_ID = "io.github.i12bp8.netneighbors"
STATE_DIR = Path(
    os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
) / PLUGIN_ID
HISTORY_FILE = STATE_DIR / "history.json"

OUI_PATHS = [
    "/usr/share/hwdata/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/lib/hwdata/oui.txt",
]

VENDOR_TYPES = [
    # (needles, type) - checked against the vendor string.
    (["nintendo", "xbox", "playstation", "steam", "valve"], "console"),
    (["canon", "epson", "brother", "kyocera", "ricoh", "xerox", "zebra tech"], "printer"),
    (["hikvision", "dahua", "reolink", "wyze", "ring", "eufy", "arlo"], "camera"),
    (["roku"], "tv"),
    (["sonos", "bose", "harman", "jbl", "yamaha", "denon", "polk"], "speaker"),
    (["synology", "qnap", "western digital", "seagate", "buffalo"], "nas"),
    (["espressif", "arduino", "tuya", "philips"], "iot"),
    (["apple", "samsung", "huawei", "xiaomi", "oneplus", "oppo", "vivo",
      "realme", "motorola", "nokia", "google", "lg electron", "sony", "zte"], "phone"),
    (["microsoft", "intel", "dell", "hewlett", "acer", "asus", "lenovo", "msi",
      "razer", "raspberry", "framework", "system76"], "laptop"),
    (["nvidia", "qualcomm", "broadcom", "mediatek", "marvell", "realtek",
      "cypress", "silicon labs", "nordic"], "iot"),
    (["tp-link", "tplink", "netgear", "linksys", "belkin", "cisco", "ubiquiti",
      "mikrotik", "aruba", "ruckus", "zyxel", "juniper", "fortinet",
      "huawei tech", "sagemcom", "arcadyan", "sercomm", "foxconn", "avm",
      "eero", "meraki", "d-link"], "router"),
]

HOSTNAME_HINTS = [
    (["iphone", "smartphone", "pixel", "galaxy s", "galaxy a", "galaxy z", "oneplus",
      "redmi", "moto g", "moto e", "xperia", "poco", "honor", "realme"], "phone"),
    (["ipad", "galaxy tab", "tablet", "kindle", "fire tab", "tab s"], "tablet"),
    (["macbook", "thinkpad", "laptop", "notebook", "desktop", "workstation",
      "galaxy book", "surface"], "laptop"),
    (["imac", "mac mini", "mac pro"], "desktop"),
    (["printer", "laserjet", "deskjet", "officejet", "bizhub", "mx92"], "printer"),
    (["chromecast", "roku", "fire tv", "firetv", "apple tv", "android tv", "bravia",
      "smart tv", "hisense", "vizio", "tcl "], "tv"),
    (["playstation", "ps4", "ps5", "xbox", "nintendo switch", "steam deck",
      "steamdeck"], "console"),
    (["echo", "homepod", "google home", "nest mini", "alexa", "sonos", "boombox"], "speaker"),
    (["airtag", "air tag", "tracker"], "iot"),
    (["cam", "camera", "doorbell"], "camera"),
    (["nas", "diskstation", "synology", "qnap", "cloudbox"], "nas"),
    (["airport", "router", "access point", "wrt", "mesh", "gateway", "ap-"], "router"),
]

# Hostnames matching this are almost certainly router-assigned generic
# labels ("dhcp-10-5-7-3", "192-168-1-23"), not real device names; they
# stay displayable but never overwrite a remembered name.
GENERIC_NAME_RE = re.compile(
    r"^(dhcp|dns|host|node|client|user|pc|desktop|android-|ipad-|iphone-)?[\s_-]*"
    r"(?:ip)?[\d-]+|^unknown|^localhost|^[\d-]+$",
    re.IGNORECASE,
)


def sh(args, timeout=6):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", "not found"
    except Exception as exc:  # noqa: BLE001 - boundary script, report anything
        return -1, "", str(exc)


def fail(error):
    print(json.dumps({"ok": False, "error": str(error)}))
    sys.exit(0)


def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Network facts
# --------------------------------------------------------------------------- #


def discover_network():
    """Return {iface, ip, prefixlen, network, mac, gateway} or raise."""
    rc, out, err = sh(["ip", "-j", "-4", "addr", "show", "scope", "global"])
    if rc != 0:
        raise RuntimeError("ip addr failed: %s" % (err or out or "no ip tool"))

    ifaces = json.loads(out or "[]") or []

    # Prefer the interface that owns the default route.
    rc2, route_out, _ = sh(["ip", "-j", "route", "show", "default"])
    default_iface = ""
    gateway = ""
    if rc2 == 0:
        for route in json.loads(route_out or "[]") or []:
            if route.get("dst", "default") != "default":
                continue
            default_iface = route.get("dev", "") or default_iface
            gateway = route.get("gateway", "") or gateway
            break

    pick = None
    for iface in ifaces:
        dev = iface.get("ifname", "")
        for info in iface.get("addr_info", []) or []:
            if info.get("family") != "inet":
                continue
            entry = {
                "iface": dev,
                "ip": info.get("local", ""),
                "prefixlen": int(info.get("prefixlen", 24) or 24),
            }
            if pick is None:
                pick = entry
            if dev == default_iface:
                pick = entry
                break
        if pick and pick["iface"] == default_iface:
            break

    if pick is None:
        raise RuntimeError("no ipv4 network (offline?)")

    net = ipaddress.ip_network("%s/%d" % (pick["ip"], pick["prefixlen"]), strict=False)
    if net.num_addresses > 4096:
        raise RuntimeError("subnet too large to scan (/%d)" % net.prefixlen)
    pick["network"] = str(net)

    # Interface MAC.
    rc3, link_out, _ = sh(["ip", "-j", "link", "show", "dev", pick["iface"]])
    if rc3 == 0:
        links = json.loads(link_out or "[]") or []
        if links:
            pick["mac"] = (links[0].get("address", "") or "").upper()

    if not gateway:
        # Common home setup: router is network +1. Confirmed later through
        # the neighbor table's router flag when possible.
        gw = net.network_address + 1
        if gw in net and gw != ipaddress.ip_address(pick["ip"]):
            gateway = str(gw)
    pick["gateway"] = gateway
    return pick


def discover_ssid(iface):
    """Best-effort current SSID via NetworkManager, then iw."""
    rc, out, _ = sh(["nmcli", "-t", "-f", "active,ssid,dev", "dev", "wifi"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[0] == "yes":
                return parts[1] or None
    if "wlan" in iface or "wlp" in iface:
        rc2, out2, _ = sh(["iw", "dev", iface, "link"])
        if rc2 == 0:
            match = re.search(r"SSID:\s*(.+)", out2)
            if match:
                return match.group(1).strip() or None
    return None


# --------------------------------------------------------------------------- #
# Probe sweep
# --------------------------------------------------------------------------- #


def probe_host(ip):
    """UDP 'poke' - no reply needed, ARP resolution is the point."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.sendto(b"\x00", (ip, 9))
        sock.close()
    except Exception:  # noqa: BLE001
        pass


def read_neighbors(iface, candidates):
    """Return {ip: {mac, state, router}} from the kernel neighbor table."""
    found = {}
    rc, out, _ = sh(["ip", "-j", "neigh", "show"])
    if rc == 0:
        try:
            for entry in json.loads(out or "[]") or []:
                if entry.get("dev") != iface:
                    continue
                ip = entry.get("dst", "")
                mac = (entry.get("lladdr", "") or "").upper().replace(":", "")
                if ip not in candidates or len(mac) != 12:
                    continue
                state = entry.get("state", "UNKNOWN")
                if isinstance(state, list):
                    state = state[0] if state else "UNKNOWN"
                if state in ("FAILED", "INCOMPLETE"):
                    continue
                found[ip] = {
                    "mac": mac,
                    "state": state,
                    "router": bool(entry.get("router", False)),
                }
        except Exception:  # noqa: BLE001
            found = {}
    if not found:
        # Fallback: /proc/net/arp (plain text, no state flags).
        try:
            with open("/proc/net/arp", "r", encoding="ascii") as handle:
                for line in handle.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].replace(":", "").upper()
                        if ip in candidates and mac and mac != "000000000000":
                            found.setdefault(ip, {"mac": mac, "state": "REACHABLE", "router": False})
        except Exception:  # noqa: BLE001
            pass
    return found


# --------------------------------------------------------------------------- #
# Names
# --------------------------------------------------------------------------- #


def reverse_names(ips):
    """Best-effort rDNS in parallel threads, bounded wait."""
    names = {}

    def lookup(ip):
        try:
            names[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:  # noqa: BLE001
            pass

    threads = [threading.Thread(target=lookup, args=(ip,), daemon=True) for ip in ips]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 1.2
    while time.monotonic() < deadline:
        if all(ip in names for ip in ips):
            break
        time.sleep(0.05)
    return names


def mdns_names(ips):
    """mDNS reverse sweep through avahi-resolve when available."""
    if not shutil.which("avahi-resolve") or not ips:
        return {}
    rc, out, _ = sh(["avahi-resolve", "-a", "-4", "-t", "2"] + list(ips), timeout=5)
    names = {}
    if rc == 0:
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                names[parts[0]] = parts[1].rstrip(".").split(".")[0]
    return names


def label_from(raw):
    """First label of an FQDN-ish name."""
    if not raw:
        return ""
    return str(raw).strip().rstrip(".").split(".")[0]


def best_name(rdns, mdns, ip):
    """Non-generic names win over generic ones, mDNS over rDNS."""
    candidates = []
    for source in (mdns, rdns):
        raw = source.get(ip, "")
        if not raw:
            continue
        label = label_from(raw)
        # "_gateway" and friends are service instance names, not hostnames.
        if not label or label.startswith("_"):
            continue
        if label:
            candidates.append((not GENERIC_NAME_RE.match(label), label))
    if not candidates:
        return ""
    candidates.sort(key=lambda pair: (-pair[0], pair[1].lower()))
    return candidates[0][1]


# --------------------------------------------------------------------------- #
# Vendors
# --------------------------------------------------------------------------- #


def load_vendor_tables():
    """System OUI DB first, bundled oui.json as the portable fallback."""
    tables = []
    for path in OUI_PATHS:
        if not os.path.exists(path):
            continue
        try:
            db = {}
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    match = re.match(r"\s*([0-9a-fA-F]{6})\s+\(base 16\)\s+(.+)$", line)
                    if match:
                        db[match.group(1).upper()] = match.group(2).strip()
            if db:
                tables.append(db)
        except Exception:  # noqa: BLE001
            pass
    # Bundled full IEEE OUI database (gzipped, ~40k entries) - works even
    # without hwdata installed; system tables still win on overlap.
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.json.gz")
    try:
        import gzip
        with gzip.open(bundled, "rt", encoding="utf-8") as handle:
            db = json.load(handle)
        if isinstance(db, dict) and db:
            tables.append({str(k).upper(): v for k, v in db.items()})
    except Exception:  # noqa: BLE001
        pass
    return tables


def vendor_short(org):
    """Collapse an OUI org string to something a row can display."""
    short = re.split(r",", org, maxsplit=1)[0].strip()
    words = short.split()
    if len(words) > 3:
        short = " ".join(words[:3]).rstrip(" ,-")
    return short[:28] or "Unknown"


def classify_device(vendor, hostname):
    """Pick a device type from vendor + hostname hints."""
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    for needles, kind in HOSTNAME_HINTS:
        for needle in needles:
            if h and needle in h:
                return kind
    for needles, kind in VENDOR_TYPES:
        for needle in needles:
            if needle in v:
                return kind
    return "unknown"


# --------------------------------------------------------------------------- #
# History (new-device detection)
# --------------------------------------------------------------------------- #


def load_history():
    existed = HISTORY_FILE.exists()
    history = {}
    if existed:
        try:
            raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("devices"), dict):
                history = raw["devices"]
        except Exception:  # noqa: BLE001
            existed = False
    return existed, history


def save_history(history):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps({"devices": history}, indent=1), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# Main scan
# --------------------------------------------------------------------------- #


def main():
    started = time.monotonic()
    oui_tables = load_vendor_tables()

    # Optional --out <path>: additionally write the result JSON atomically.
    # The Omarchy shell runs this scan detached and watches that file.
    out_path = None
    rest_args = sys.argv[1:]
    if "--out" in rest_args:
        idx = rest_args.index("--out")
        if idx + 1 < len(rest_args):
            out_path = rest_args[idx + 1]


    def emit(payload):
        raw = json.dumps(payload, ensure_ascii=False)
        print(raw)
        if out_path:
            try:
                target = Path(out_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_name(target.name + ".tmp")
                tmp.write_text(raw + "\n", encoding="utf-8")
                os.replace(str(tmp), str(target))
            except Exception as exc:  # noqa: BLE001 - report, never crash
                print("warning: scan output not written: %s" % exc, file=sys.stderr)

    try:
        net = discover_network()
    except Exception as exc:  # noqa: BLE001
        emit({"ok": False, "error": str(exc)})
        return
    iface = net["iface"]
    subnet = ipaddress.ip_network(net["network"])
    self_ip = net["ip"]
    self_mac = net.get("mac", "")
    self_host = socket.gethostname() or "this device"
    ssid = discover_ssid(iface)

    candidates = {str(ip) for ip in subnet.hosts() if str(ip) != self_ip}
    if not candidates:
        raise RuntimeError("no addressable hosts in %s" % net["network"])

    # 1. Probe sweep - ARP resolution is the point.
    with ThreadPoolExecutor(max_workers=96) as pool:
        list(pool.map(probe_host, candidates))
    time.sleep(0.5)

    # 2. Neighbor table.
    neighbors = read_neighbors(iface, candidates)

    # 3. Router: the route gateway, or anything the kernel flags as a router.
    router_macs = set()
    for ip, entry in neighbors.items():
        if entry["router"] or ip == net["gateway"]:
            router_macs.add(entry["mac"])
    if not net["gateway"] and router_macs:
        for ip in neighbors:
            if neighbors[ip]["mac"] in router_macs:
                net["gateway"] = ip
                break

    # 4. Names for online hosts.
    online_ips = list(neighbors.keys())
    rdns = reverse_names(online_ips[:64])
    want_mdns = [
        ip for ip in online_ips[:48]
        if ip not in rdns or GENERIC_NAME_RE.match(label_from(rdns[ip]))
    ]
    mdns = mdns_names(want_mdns)

    # 5. History + NEW flags (first-ever scan is a baseline, not a flood).
    history_existed, history = load_history()
    now = iso_now()
    new_count = 0

    devices = []
    online_macs = set()
    for ip, entry in neighbors.items():
        mac = entry["mac"]
        online_macs.add(mac)
        vendor = ""
        for table in oui_tables:
            org = table.get(mac[:6], "")
            if org:
                vendor = vendor_short(org)
                break

        hostname = best_name(rdns, mdns, ip)
        is_router = entry["mac"] in router_macs
        key = mac  # devices are tracked by MAC

        known = history.get(key)
        is_new = False
        if history_existed and not known and not is_router:
            is_new = True

        # Remembered names beat router-generated labels.
        remembered = str((known or {}).get("name") or "")
        if remembered and (not hostname or GENERIC_NAME_RE.match(hostname)):
            hostname = remembered

        # A generic label ("dhcp-10-5-7-3") is worse than the vendor name;
        # drop it so the UI falls back to the vendor line.
        if hostname and GENERIC_NAME_RE.match(hostname) and vendor:
            hostname = ""

        if is_router:
            # Routers rarely carry a useful name; give them a stable one.
            if not hostname:
                hostname = "Gateway"

        if is_new:
            new_count += 1

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "type": classify_device(vendor, hostname),
            "isNew": is_new,
            "router": is_router,
            "self": False,
            "online": True,
            "state": entry["state"],
            "first": (known or {}).get("first", now),
            "lastSeen": now,
        })

        if not is_router:
            if known:
                known["last"] = now
                if hostname and not known.get("name") and not GENERIC_NAME_RE.match(hostname):
                    known["name"] = hostname
            else:
                history[key] = {
                    "first": now,
                    "last": now,
                    "name": hostname if hostname and not GENERIC_NAME_RE.match(hostname) else "",
                }

    # The machine running the scan, for the "you" row.
    devices.append({
        "ip": self_ip,
        "mac": self_mac,
        "vendor": "",
        "hostname": self_host,
        "type": "laptop",
        "isNew": False,
        "router": False,
        "self": True,
        "online": True,
        "state": "REACHABLE",
        "first": now,
        "lastSeen": now,
    })

    def sort_key(dev):
        name = (dev["hostname"] or dev["vendor"] or dev["ip"] or "").lower()
        if dev["router"]:
            return (0, 0, "")
        if dev["self"]:
            return (1, 0, "")
        if dev["isNew"]:
            return (2, 0, name)
        if not dev["online"]:
            return (4, 0, name)
        return (3, 0, name)

    # 6. Away devices: things history knows, seen within a day, gone right
    # now. Shown dimmed so the panel reads as "who's here" vs "who was here".
    from datetime import datetime as _dt  # noqa: PLC0415
    now_epoch = _dt.now(timezone.utc)

    def _iso_epoch(text):
        try:
            parsed = _dt.fromisoformat(str(text or ""))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except Exception:  # noqa: BLE001
            return None

    away_candidates = []
    if history_existed:
        for mac, meta in history.items():
            if mac in online_macs or mac in router_macs or mac == self_mac:
                continue
            last_epoch = _iso_epoch(meta.get("last"))
            if last_epoch is None or now_epoch.timestamp() - last_epoch > 24 * 3600:
                continue
            vendor = ""
            for table in oui_tables:
                org = table.get(mac[:6], "")
                if org:
                    vendor = vendor_short(org)
                    break
            remembered = str(meta.get("name") or "")
            away_candidates.append({
                "ip": "",
                "mac": mac,
                "vendor": vendor,
                "hostname": remembered,
                "type": classify_device(vendor, remembered),
                "isNew": False,
                "router": False,
                "self": False,
                "online": False,
                "state": "",
                "first": str(meta.get("first") or ""),
                "lastSeen": str(meta.get("last") or ""),
                "lastEpoch": last_epoch,
            })
    away_candidates.sort(key=lambda d: d["lastEpoch"], reverse=True)
    devices.extend(away_candidates[:8])
    away_count = len(devices) - len([d for d in devices if d["online"]])
    if away_candidates:
        del away_candidates  # keep only capped entries in devices

    online_others = sum(1 for d in devices if d["online"] and not d["self"])

    # History housekeeping: keep the most recently seen 400 MACs.
    if len(history) > 400:
        ordered = sorted(
            history.items(),
            key=lambda kv: _iso_epoch(kv[1].get("last")) or 0,
            reverse=True,
        )
        history = dict(ordered[:400])

    devices.sort(key=sort_key)
    save_history(history)

    emit({
        "ok": True,
        "net": {
            "iface": iface,
            "ip": self_ip,
            "cidr": net["network"],
            "gateway": net["gateway"] or "",
            "ssid": ssid or "",
        },
        "self": {"ip": self_ip, "mac": self_mac, "hostname": self_host},
        "devices": devices,
        "newCount": new_count,
        "awayCount": away_count,
        "onlineOtherCount": online_others,
        "scanMs": int((time.monotonic() - started) * 1000),
        "baselined": not history_existed,
        "scannedAt": now,
    })


if __name__ == "__main__":
    main()
