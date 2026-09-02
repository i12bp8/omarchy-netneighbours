# NetNeighbors

**Who's on this Wi-Fi?** A Fing-style neighbor radar for the Omarchy bar.
Click the icon, get the whole network in a couple of seconds: every device
with vendor, hostname, MAC — plus NEW badges when a device shows up that
nobody has seen before.

![NetNeighbors panel](netneighbors-preview.png)

## Install

From a public git URL (once published):

```sh
omarchy plugin add https://github.com/i12bp8/omarchy-netneighbours.git --enable
```

Or during development, drop (or symlink) this folder at:

```
~/.config/omarchy/plugins/io.github.i12bp8.netneighbors/
omarchy plugin enable io.github.i12bp8.netneighbors right
```

Saved changes under the plugin folder hot-reload automatically.

## Use

1. Click the Wi-Fi icon in the bar. The first scan happens on its own a
   moment after the shell starts; opening the panel refreshes if the last
   scan is older than 10 seconds.
2. Read the room: SSID + network range on top, then one row per device —
   icon, name, IP, vendor, MAC. The gateway is tagged **GATEWAY**, your own
   machine is tagged **YOU**, and anything new carries a **NEW** badge.
3. Click a row to copy its IP; right-click to copy its MAC. A toast
   confirms what was copied.
4. New devices that appear while you're away turn the bar counter accent
   colored and raise a **NEW devices** banner next time you look.

Keyboard inside the panel: `R` rescans, `A` toggles auto-refresh, `Esc`
closes, `Tab` moves to the next panel.

The small number beside the icon is the live count of other devices.
Rescans happen automatically (every 30 s while open, at least every minute
while closed) — toggle "Auto" in the footer to stop them.

## How it works

`scanner.py` runs with **no privileges and no dependencies**:

1. Finds the primary IPv4 subnet from `ip -j -4 addr` (the interface that
   owns the default route).
2. Gently probes every address on it with one UDP datagram to port 9
   (discard). It never needs a reply: simply addressing a host makes the
   kernel resolve it with ARP, so every awake device lands in the neighbor
   table with a MAC address — firewalls included.
3. Reads back the kernel neighbor table (`ip -j neigh show`, with
   `/proc/net/arp` as fallback) and reports every host found.
4. Names come from reverse DNS (parallel, time-boxed), an mDNS sweep via
   `avahi-resolve` when installed, and names remembered from earlier scans.
5. Vendors are resolved from `/usr/share/hwdata/oui.txt` (Arch ships it),
   with the bundled `oui.json` as a portable fallback.
6. A small history file (`~/.local/share/io.github.i12bp8.netneighbors/`)
   remembers every MAC it has seen, so genuinely new devices stand out.
   The first-ever scan is treated as a baseline, not a flood of "new"
   devices.

The shell runs the scan fully detached and picks the result up from an
atomically-written JSON file, so a shell reload never kills a scan mid-way.

Only ever touches the local subnet you are already connected to; each scan
is a few hundred tiny UDP datagrams plus one file read. No daemon, no root,
no config.

## Privacy & ethics

Everything stays on your machine — history is a local JSON file you can
delete. MAC addresses identify *devices*, not people; use this on networks
you own or where you're allowed to be curious. On café/guest networks with
client isolation you will mostly see the gateway: that's the network
protecting itself, not a bug.

## Configure

```sh
omarchy bar move io.github.i12bp8.netneighbors --section right   # move it
omarchy bar set io.github.i12bp8.netneighbors refreshSeconds 15   # rescan cadence (15-600)
```

## Troubleshooting

- **Panel says "Scan failed / no IPv4"**: you're likely offline or on a
  VPN-only connection. Connect to a LAN/Wi-Fi first.
- **Only the gateway shows**: client isolation (see above), or the other
  devices are asleep — Wi-Fi radios that are powered down don't answer ARP.
- **Vendors show "Unknown"**: many phones randomize their MAC these days
  (locally administered addresses have no IEEE vendor), so that's expected.

## Remove

```sh
omarchy plugin remove io.github.i12bp8.netneighbors
```

## License

MIT — see [LICENSE](LICENSE).
