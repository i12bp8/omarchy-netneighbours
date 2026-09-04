#!/usr/bin/python3 -I
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

Output: a single bounded JSON object on stdout and, when --out is given,
atomically at that path.

Security contract (mirrored by Panel.qml):

* Single instance: an flock()ed lock file serialises scans. A newer scan
  sends a verified SIGTERM to a stale holder instead of overlapping it,
  and the lock dies with its process (even on SIGKILL/crash).
* Hard time budget: a watchdog thread caps total runtime and writes the
  final "timed out" verdict itself, so a wedged or orphaned instance can
  never linger indefinitely.
* Bounded reads: every child command's stdout/stderr is captured with a
  byte ceiling; the process group is killed if it exceeds the ceiling or
  its timeout. History reads are size-bounded.
* Bounded writes: all state files are written via unpredictable
  tempfile.mkstemp names + atomic os.replace; file opens use O_NOFOLLOW
  and the state directory is private (0700), so no predictable .tmp or
  symlink-following write target exists. No path is ever followed that
  an untrusted file could have planted.
* Bounded output: the result payload is capped in bytes, rows and string
  lengths (see MAX_* below); Panel.qml enforces the same caps on load.

Only ever touches hosts on the local subnet you are already connected to,
sends a handful of small UDP datagrams per scan, and needs no privileges.
"""

import errno
import fcntl
import gzip
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
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
LOCK_FILE = STATE_DIR / "scan.lock"

# --------------------------------------------------------------------------- #
# Resource / output bounds (the producer half of the size contract).
# --------------------------------------------------------------------------- #

MAX_RESULT_BYTES = 1_500_000      # ceiling for the serialised result payload
MAX_ONLINE_ROWS = 512             # device rows emitted per scan (online)
MAX_AWAY_ROWS = 8                 # remembered-but-away rows emitted per scan
MAX_TOTAL_ROWS = MAX_ONLINE_ROWS + MAX_AWAY_ROWS + 1  # + the "self" row
MAX_CAPTURE_BYTES = 262144        # stdout ceiling for captured child commands
MAX_STDERR_BYTES = 65536          # stderr ceiling for captured child commands
MAX_HISTORY_BYTES = 1_000_000     # history file read ceiling
MAX_HISTORY_ENTRIES = 400         # history entries retained
MAX_FIELD_LEN = 200               # per-string cap when (re)storing history

# Hard overall budget for one scan; the watchdog below enforces it even if
# a phase hangs. NETNEIGHBORS_SCAN_BUDGET exists for tests only - the shell
# runs this script with a whitelisted environment that never carries it.
OVERALL_BUDGET_SECONDS = 16.0
LOCK_WAIT_SECONDS = 4.0

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


def _kill_group(proc):
    """Kill a child and its whole process group (it may have spawned tools)."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def sh(args, timeout=6, max_stdout=MAX_CAPTURE_BYTES, max_stderr=MAX_STDERR_BYTES):
    """Run a command, return (returncode, stdout, stderr).

    Producer-side byte bound: stdout/stderr are captured only up to
    max_stdout/max_stderr bytes each. If a child exceeds its ceiling or
    its timeout, the whole process group is killed and the call fails, so
    callers never parse truncated output and memory stays bounded no
    matter what the child emits.
    """
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # own process group -> killpg below
        )
    except FileNotFoundError:
        return -1, "", "not found"
    except Exception as exc:  # noqa: BLE001 - boundary script, report anything
        return -1, "", str(exc)

    out = bytearray()
    err = bytearray()
    verdict = {"killed": False, "reason": ""}

    def pump(stream, sink, cap, key):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                room = cap - len(sink)
                if room > 0:
                    sink += chunk[:room]
                if len(sink) >= cap:
                    verdict["killed"] = True
                    verdict["reason"] = "%s exceeded its %d-byte capture cap" % (key, cap)
                    _kill_group(proc)
                    return
        except Exception:  # noqa: BLE001 - read side died with the child
            pass
        finally:
            try:
                stream.close()
            except Exception:  # noqa: BLE001
                pass

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, out, max_stdout, "stdout"), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, err, max_stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        verdict["killed"] = True
        verdict["reason"] = "timed out after %ss" % timeout
        _kill_group(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # noqa: PLC0415 - unreachable in practice
            pass

    for thread in threads:
        thread.join(timeout=5)

    rc = proc.returncode if proc.returncode is not None else -1
    text_out = bytes(out).decode("utf-8", "replace")
    text_err = bytes(err).decode("utf-8", "replace")
    if verdict["killed"]:
        return -1, text_out, text_err or verdict["reason"]
    return rc, text_out, text_err


def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso_epoch(text):
    try:
        parsed = datetime.fromisoformat(str(text or ""))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:  # noqa: BLE001
        return None


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

DNS_MAX_LOOKUPS = 96    # defensive cap on addresses resolved per call
DNS_MAX_WORKERS = 24    # concurrent resolver threads (never one per host)
DNS_BUDGET_SECONDS = 1.5


def reverse_names(ips):
    """Best-effort rDNS with bounded concurrency and a bounded wait.

    Never spawns one thread per address: lookups run on at most
    DNS_MAX_WORKERS daemon threads, only DNS_MAX_LOOKUPS addresses are
    considered, and the call returns after DNS_BUDGET_SECONDS. Daemon
    threads can never hold up process exit.
    """
    names = {}
    todo = [ip for ip in ips if ip][:DNS_MAX_LOOKUPS]
    if not todo:
        return names

    slots = threading.BoundedSemaphore(DNS_MAX_WORKERS)
    deadline = time.monotonic() + DNS_BUDGET_SECONDS

    def lookup(ip):
        with slots:
            try:
                names[ip] = socket.gethostbyaddr(ip)[0]
            except Exception:  # noqa: BLE001
                pass

    threads = []
    for ip in todo:
        if time.monotonic() >= deadline:
            break
        thread = threading.Thread(target=lookup, args=(ip,), daemon=True)
        thread.start()
        threads.append(thread)

    while time.monotonic() < deadline:
        if all(ip in names for ip in todo):
            break
        time.sleep(0.05)
    return names


def mdns_names(ips):
    """mDNS reverse sweep through avahi-resolve when available."""
    ips = [ip for ip in ips if ip][:64]
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
# State directory + history (symlink-safe, size-bounded)
# --------------------------------------------------------------------------- #


def _state_dir_ok():
    """Create/validate the private state dir; refuse symlinked directories."""
    try:
        STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = STATE_DIR.lstat()
        return (
            stat.S_ISDIR(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == os.geteuid()
        )
    except OSError:
        return False


def _trim_history(history, limit=MAX_HISTORY_ENTRIES):
    """Keep the `limit` most recently seen entries."""
    if len(history) <= limit:
        return history
    ordered = sorted(
        history.items(),
        key=lambda kv: _iso_epoch((kv[1] or {}).get("last")) or 0.0,
        reverse=True,
    )
    return dict(ordered[:limit])


def load_history():
    """Bounded, symlink-safe read of the remembered-device history.

    The open refuses symlinks (O_NOFOLLOW) and the read is capped at
    MAX_HISTORY_BYTES, so a planted or corrupted history can neither
    redirect the scan into other files nor exhaust memory. Any anomaly is
    treated as "no history yet" (baseline scan).
    """
    try:
        fd = os.open(HISTORY_FILE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        return False, {}
    try:
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(MAX_HISTORY_BYTES + 1)
    except OSError:
        return False, {}
    if len(raw) > MAX_HISTORY_BYTES:
        return False, {}
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return False, {}
    if not isinstance(data, dict) or not isinstance(data.get("devices"), dict):
        return False, {}

    history = {}
    for mac, meta in data["devices"].items():
        if not isinstance(mac, str) or not isinstance(meta, dict):
            continue
        cleaned = {}
        for key in ("first", "last", "name"):
            value = meta.get(key)
            if isinstance(value, str):
                cleaned[key] = value[:MAX_FIELD_LEN]
        if cleaned:
            history[str(mac)[:64]] = cleaned
    return True, _trim_history(history)


def save_history(history):
    """Write history atomically via an unpredictable temp name.

    mkstemp names are unpredictable (no attacker-predictable .tmp),
    os.replace swaps the final file in place without ever following a
    symlink at the destination, and the private 0700 state directory
    keeps the whole area out of other local users' reach.
    """
    if not _state_dir_ok():
        return
    history = _trim_history(history)
    try:
        payload = json.dumps({"devices": history}, indent=1)
    except Exception:  # noqa: BLE001
        return
    if len(payload.encode("utf-8")) > MAX_HISTORY_BYTES:
        return

    fd = None
    tmp = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".history-", suffix=".tmp", dir=str(STATE_DIR))
        tmp = Path(tmp_name)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        fd = None
        os.replace(tmp, HISTORY_FILE)
        tmp = None
    except OSError:
        pass
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Single-instance lock
# --------------------------------------------------------------------------- #


def _signal_stale_holder(pid):
    """SIGTERM a lock holder - only after verifying it is really ours."""
    if not isinstance(pid, int) or pid <= 0 or pid == os.getpid():
        return
    try:
        with open("/proc/%d/status" % pid, "r", encoding="ascii", errors="replace") as handle:
            content = handle.read(4096)
        uid_line = next((line for line in content.splitlines() if line.startswith("Uid:")), "")
        tokens = uid_line.split()
        if len(tokens) < 2 or int(tokens[1]) != os.geteuid():
            return  # not our process - never signal a stranger
    except (OSError, ValueError):
        return  # holder already gone; the flock will be free momentarily
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def acquire_scan_lock(timeout=LOCK_WAIT_SECONDS):
    """Serialise scans with an flock()ed lock file.

    Only one scan instance may run at a time. A live holder (verified to
    belong to this user) receives SIGTERM so a newer scan supersedes a
    stale one instead of overlapping it. The flock is released by the
    kernel when the holder exits or dies, so even SIGKILL or a crash can
    never leak the lock.

    Returns the open lock fd (keep it for the lifetime of the scan);
    raises RuntimeError when the lock cannot be had in time.
    """
    if not _state_dir_ok():
        raise RuntimeError("cannot create the private state directory")

    fd = None
    for _ in range(2):  # a planted symlink at the lock path is unlinked, not followed
        try:
            fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            break
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                try:
                    os.unlink(LOCK_FILE)  # removes the symlink entry, never its target
                except OSError:
                    pass
                continue
            raise RuntimeError("cannot open the scan lock: %s" % exc) from exc
    if fd is None:
        raise RuntimeError("cannot open the scan lock")

    deadline = time.monotonic() + timeout
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(fd, 0)
            os.write(fd, b"%d\n" % os.getpid())
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES):
                os.close(fd)
                raise RuntimeError("scan lock error: %s" % exc) from exc

        holder = None
        try:
            raw = os.pread(fd, 64, 0).decode("ascii", "replace").strip()
            holder = int(raw.splitlines()[0])
        except Exception:  # noqa: BLE001
            pass
        _signal_stale_holder(holder)

        if time.monotonic() >= deadline:
            os.close(fd)
            raise RuntimeError("another scan is still running; try again shortly")
        time.sleep(0.1)


# --------------------------------------------------------------------------- #
# Result emission (bounded + atomic)
# --------------------------------------------------------------------------- #


def write_result_file(target, raw):
    """Atomically write the result file via an unpredictable temp name."""
    try:
        path = Path(target)
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return False

        fd = None
        tmp = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=".scan-", suffix=".tmp", dir=str(parent))
            tmp = Path(tmp_name)
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            fd = None
            os.replace(tmp, path)  # replaces any entry at target, symlink included
            tmp = None
            return True
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp is not None:
                try:
                    tmp.unlink()
                except OSError:
                    pass
    except Exception:  # noqa: BLE001 - report, never crash
        return False


def watchdog_main(done, emit, deadline, scan_id):
    """Hard ceiling for one scan run.

    If the main scan thread has not finished by `deadline`, this thread
    writes the final "timed out" verdict itself and terminates the
    process - deterministically, even if a phase or a resolver thread is
    wedged. os._exit is deliberate: daemon threads that are stuck in C
    calls must not keep the process alive.
    """
    remaining = deadline - time.monotonic()
    if remaining > 0:
        done.wait(remaining)
    if done.is_set():
        return
    payload = {"ok": False, "error": "scan exceeded its time budget"}
    if scan_id is not None:
        payload["scanId"] = scan_id
    emit(payload)
    os._exit(0)  # noqa: PLR1722 - see docstring


# --------------------------------------------------------------------------- #
# Main scan
# --------------------------------------------------------------------------- #


def parse_args(argv):
    """Parse --out <path> and --scan-id <n>; everything else is ignored."""
    out_path = None
    scan_id = None
    index = 0
    while index < len(argv):
        if argv[index] == "--out" and index + 1 < len(argv):
            out_path = argv[index + 1]
            index += 2
            continue
        if argv[index] == "--scan-id" and index + 1 < len(argv):
            try:
                scan_id = int(argv[index + 1])
            except (TypeError, ValueError):
                scan_id = None
            index += 2
            continue
        index += 1
    return out_path, scan_id


def main():
    started = time.monotonic()
    budget_env = os.environ.get("NETNEIGHBORS_SCAN_BUDGET")
    try:
        budget = float(budget_env) if budget_env else OVERALL_BUDGET_SECONDS
    except ValueError:
        budget = OVERALL_BUDGET_SECONDS
    deadline = started + budget

    out_path, scan_id = parse_args(sys.argv[1:])
    oui_tables = load_vendor_tables()

    def fail_payload(error):
        payload = {"ok": False, "error": str(error)}
        if scan_id is not None:
            payload["scanId"] = scan_id
        return payload

    def emit(payload):
        """Print the payload and atomically write it to --out, if given."""
        raw = json.dumps(payload, ensure_ascii=False)
        if len(raw.encode("utf-8")) > MAX_RESULT_BYTES:
            # Keep every output channel inside the size contract.
            raw = json.dumps(
                {"ok": False, "error": "scan result exceeded its size contract"},
                ensure_ascii=False,
            )
        if out_path:
            write_result_file(out_path, raw)
        try:
            sys.stdout.write(raw + "\n")
            sys.stdout.flush()
        except Exception:  # noqa: BLE001 - stdout may be closed/detached
            pass

    # The watchdog is armed before anything else can run away.
    done = threading.Event()
    threading.Thread(
        target=watchdog_main,
        args=(done, emit, deadline, scan_id),
        daemon=True,
        name="netneighbors-budget",
    ).start()

    lock_fd = None
    try:
        try:
            lock_fd = acquire_scan_lock()
        except RuntimeError as exc:
            done.set()
            emit(fail_payload(exc))
            return

        net = discover_network()
        iface = net["iface"]
        subnet = ipaddress.ip_network(net["network"])
        self_ip = net["ip"]
        self_mac = net.get("mac", "")
        self_host = socket.gethostname() or "this device"
        ssid = discover_ssid(iface)

        candidates = {str(ip) for ip in subnet.hosts() if str(ip) != self_ip}
        if not candidates:
            raise RuntimeError("no addressable hosts in %s" % net["network"])

        # 1. Probe sweep - ARP resolution is the point. Worker count and the
        #    /4096 subnet guard keep the sweep bounded.
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

        # 4. Names for online hosts (both helpers bound their own work).
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
        #    now. Shown dimmed so the panel reads as "who's here" vs "who was
        #    here". Capped at MAX_AWAY_ROWS.
        away_candidates = []
        if history_existed:
            for mac, meta in history.items():
                if mac in online_macs or mac in router_macs or mac == self_mac:
                    continue
                last_epoch = _iso_epoch(meta.get("last"))
                if last_epoch is None or datetime.now(timezone.utc).timestamp() - last_epoch > 24 * 3600:
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
        devices.extend(away_candidates[:MAX_AWAY_ROWS])

        # 7. Row cap: even a saturated /22 can never produce an unbounded
        #    payload. Counts below are recomputed from the emitted rows so the
        #    UI never advertises devices it cannot show.
        devices.sort(key=sort_key)
        if len(devices) > MAX_TOTAL_ROWS:
            devices = devices[:MAX_TOTAL_ROWS]
        new_count = sum(1 for d in devices if d["isNew"] and d["online"])
        online_others = sum(1 for d in devices if d["online"] and not d["self"])
        away_count = sum(1 for d in devices if not d["online"])

        save_history(history)

        payload = {
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
        }
        if scan_id is not None:
            payload["scanId"] = scan_id
        done.set()
        emit(payload)
    except Exception as exc:  # noqa: BLE001 - boundary script: report, never crash
        done.set()
        emit(fail_payload(exc))
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


if __name__ == "__main__":
    main()
