import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "ui/icons.js" as Icons

// Panel.qml - the NetNeighbors "who's on this network" popover.
//
// A bar-widget panel (host contract lives in BarWidget.qml). Clicking the
// bar button opens this surface, kicks off a scan, and renders the result:
// the network you're on, every device the kernel neighbor table can see,
// with vendor, hostname, MAC, NEW badges, and dimmed AWAY rows for known
// devices that aren't answering right now.
//
// Structure: header (SSID + network facts), a filter row, then a single
// scrolled list with ONLINE and AWAY section headers. Rows expand in place
// (chevron) to reveal full detail, and hover tooltips carry the complete
// info for anything elided. The heavy lifting happens in scanner.py, which
// runs as a managed, time-boxed, single-instance process; its result
// arrives via an atomically-written JSON file watched by FileView (see the
// scan-pipeline contract below).
Panel {
    id: root
    moduleName: "io.github.i12bp8.netneighbors"
    ipcTarget: "io.github.i12bp8.netneighbors"
    manageIpc: false

    property var anchorItem: null
    property var hostWidget: null
    readonly property var barIdentity: hostWidget || root

    // ---- palette ------------------------------------------------------------

    readonly property color contentForeground: bar ? bar.barForeground : Color.foreground
    readonly property color contentAccent: bar ? (bar.accent || Color.accent) : Color.accent
    readonly property color contentUrgent: bar ? (bar.urgent || Color.urgent) : Color.urgent
    readonly property color surface: Color.popups.background
    readonly property string contentFontFamily: bar ? bar.fontFamily : Style.font.family

    // ---- scan state ---------------------------------------------------------

    property bool scanning: false
    property string lastError: ""
    property string ssid: ""
    property string cidr: ""
    property string gateway: ""
    property string ifaceName: ""
    property int otherCount: 0          // online devices minus this machine
    property int awayCount: 0           // known devices not online right now
    property int newCount: 0
    property bool baselined: false
    property int scanMs: 0
    property date lastScanAt: new Date(0)
    property bool lastScanAtValid: false
    property bool autoRefresh: true     // session-only preference
    property bool dismissedNew: false   // "NEW devices" banner dismissed
    property bool hasData: false
    property string filterText: ""
    property var allOnline: []          // master (unfiltered) device rows
    property var allAway: []
    property var expandedRows: ({})     // mac/ip -> expanded, driven by expandRevision
    property int expandRevision: 0

    readonly property int refreshSeconds: (function () {
        var value = parseInt(root.setting("refreshSeconds", 30), 10);
        return isFinite(value) ? Math.max(15, Math.min(600, value)) : 30;
    })()

    // Rows for the view: header entries + device rows, all with the same
    // shape so the delegate is one component.
    ListModel { id: deviceModel }

    // ---- actions ------------------------------------------------------------

    function refresh() {
        root.startScan();
    }

    function startScan() {
        // Managed scan lifecycle (see the scan-pipeline block below):
        // supersede - never overlap - any scan that is still running, then
        // launch a fresh one through the Quickshell Process handle.
        root.cancelCurrentScan();
        root.currentScanId++;
        root.scanning = true;
        root.lastError = "";
        stallTimer.restart();
        autoTimer.stop();
        scanProcess.command = [
            root.pythonPath, "-I", "-X", "utf8=1", // isolated, deterministic interpreter
            root.scannerPath, "--out", root.scanFilePath,
            "--scan-id", String(root.currentScanId)
        ];
        scanProcess.running = true; // quickshell starts it once the old one has exited
    }

    function open() {
        // Always show fresh data when the panel opens.
        var stale = (new Date().getTime() - root.lastScanAt.getTime()) > 10000;
        if (stale || !root.hasData)
            root.startScan();
        root.controller.show();
        Qt.callLater(function () {
            if (keyCatcher) keyCatcher.forceActiveFocus();
        });
    }

    function close() {
        root.controller.hide();
    }

    function toggle() {
        if (root.opened)
            root.close();
        else
            root.open();
    }

    function switchPanel(direction) {
        if (root.bar && typeof root.bar.switchPanelFrom === "function")
            return root.bar.switchPanelFrom(root.barIdentity, direction);
        return false;
    }

    function copyText(text, message) {
        var value = String(text || "");
        if (value === "")
            return;
        Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(value) + " | wl-copy"]);
        root.showToast(message || "Copied to clipboard");
    }

    function showToast(message) {
        toastLabel.text = message;
        toastRect.opacity = 1;
        toastTimer.restart();
    }

    function macPretty(mac) {
        var m = String(mac || "").replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
        if (m.length !== 12)
            return mac || "";
        var parts = [];
        for (var i = 0; i < 12; i += 2)
            parts.push(m.substr(i, 2));
        return parts.join(":");
    }

    function lastSeenLabel(iso) {
        if (!iso)
            return "";
        var then = new Date(iso);
        if (isNaN(then.getTime()))
            return "";
        var seconds = Math.floor((new Date().getTime() - then.getTime()) / 1000);
        if (seconds < 90) return "just now";
        if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
        if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
        var days = Math.floor(seconds / 86400);
        return days === 1 ? "yesterday" : days + "d ago";
    }

    function fmtDate(iso) {
        var then = new Date(iso);
        if (isNaN(then.getTime()))
            return "—";
        return Qt.formatDateTime(then, "yyyy-MM-dd HH:mm");
    }

    function chipTextColor() {
        var c = root.contentAccent;
        var lum = 0.299 * c.r + 0.587 * c.g + 0.114 * c.b;
        return lum > 0.6 ? Qt.rgba(0.05, 0.05, 0.08, 1) : Qt.rgba(0.98, 0.98, 1.0, 1);
    }

    function ageLabel() {
        if (!root.hasData)
            return "never scanned";
        var seconds = Math.floor((new Date().getTime() - root.lastScanAt.getTime()) / 1000);
        if (seconds < 5) return "just now";
        if (seconds < 60) return seconds + "s ago";
        var minutes = Math.floor(seconds / 60);
        if (minutes < 60) return minutes + "m ago";
        var hours = Math.floor(minutes / 60);
        return hours + "h ago";
    }

    // ---- popup geometry -----------------------------------------------------

    readonly property real headerH: Style.space(44)
    readonly property real filterH: Style.space(30)
    readonly property real footerH: Style.space(26)
    readonly property real gapH: Style.space(8)
    readonly property real bannerH: Style.space(28)
    readonly property real labelH: Style.space(20)
    readonly property real rowH: Style.space(46)
    readonly property real rowExpandH: Style.space(74)

    property real listBlockH: Style.space(240)
    property real panelH: Style.space(380)

    function rowHeight(i) {
        var it = deviceModel.get(i);
        if (!it)
            return 0;
        if (it.kind === "header" || it.kind === "empty")
            return root.labelH;
        var key = it.mac !== "" ? it.mac : (it.ip !== "" ? it.ip : "self");
        return root.rowH + (root.expandState(key) ? root.rowExpandH : 0);
    }

    function reflow() {
        var total = 0;
        var rows = deviceModel.count;
        for (var i = 0; i < rows; i++)
            total += root.rowHeight(i);
        if (rows > 1)
            total += (rows - 1) * Style.spacing.sm;
        root.listBlockH = Math.min(Math.max(total, Style.space(60)), Style.space(540));

        var h = Style.space(2);
        h += root.headerH + root.gapH;
        h += root.filterH;
        if (root.newCount > 0 && !root.dismissedNew && rows > 0)
            h += root.gapH + root.bannerH;
        h += root.gapH + root.listBlockH;
        h += root.gapH + root.footerH + Style.space(2);
        root.panelH = h;

        Qt.callLater(function () {
            deviceList.height = root.listBlockH;
            panel.contentHeight = panel.fittedContentHeight(root.panelH);
        });
    }

    // ---- model building -----------------------------------------------------

    function matchesFilter(d) {
        var q = root.filterText.trim().toLowerCase();
        if (q === "")
            return true;
        var hay = ((d.hostname || "") + " " + (d.vendor || "") + " " + (d.ip || "")
            + " " + (d.mac || "") + " " + (d.type || "")).toLowerCase();
        return hay.indexOf(q) >= 0;
    }

    function headerEntry(label) {
        return {
            kind: "header", label: label,
            ip: "", mac: "", vendor: "", hostname: "", type: "",
            isNew: false, router: false, self: false, online: false,
            lastSeen: "", expanded: false
        };
    }

    function rebuildModels() {
        deviceModel.clear();
        var online = [], away = [];
        for (var i = 0; i < root.allOnline.length; i++)
            if (root.matchesFilter(root.allOnline[i]))
                online.push(root.allOnline[i]);
        for (var j = 0; j < root.allAway.length; j++)
            if (root.matchesFilter(root.allAway[j]))
                away.push(root.allAway[j]);

        deviceModel.append(root.headerEntry("ONLINE · " + online.length));
        for (var k = 0; k < online.length; k++) {
            var d = online[k];
            d.kind = "row";
            d.expanded = false;
            deviceModel.append(d);
        }
        if (away.length > 0) {
            deviceModel.append(root.headerEntry("AWAY · " + away.length));
            for (var m = 0; m < away.length; m++) {
                var a = away[m];
                a.kind = "row";
                a.expanded = false;
                deviceModel.append(a);
            }
        }
        if (deviceModel.count <= 1) {
            deviceModel.append({
                kind: "empty", label: "",
                ip: "", mac: "", vendor: "", hostname: "", type: "",
                isNew: false, router: false, self: false, online: false,
                lastSeen: "", expanded: false
            });
        }
        root.reflow();
    }

    // Expansion state lives outside the model and is refreshed through a
    // revision counter - ListModel role changes do not reliably re-bind
    // required properties in the running Quickshell, so we never rely on
    // role propagation for this.
    function expandState(key) {
        root.expandRevision; // tracked dependency: forces re-evaluation
        return root.expandedRows[key] === true;
    }

    function toggleDevice(key) {
        root.expandedRows[key] = !root.expandState(key);
        root.expandRevision++;
        root.reflow();
    }



    // ---- scan pipeline ------------------------------------------------------
    //
    // Scan lifecycle + result contract (mirrored by scanner.py):
    //  * scanner.py runs as a *managed* Quickshell Process, never detached:
    //    Quickshell exposes its identity (processId), SIGTERMs it when a scan
    //    is superseded or cancelled (`running = false`), and kills it when
    //    this panel or the shell goes away. scanner.py additionally flock()s
    //    a lock file, so two scan processes can never overlap no matter what.
    //  * the interpreter is an absolute path (never PATH-resolved), runs
    //    isolated (`-I`: no PYTHON*/user-site loading) with a whitelisted
    //    environment (clearEnvironment) and forced UTF-8, so no inherited
    //    loader environment can reach the scanner.
    //  * result size/depth/cardinality contract: scanner.py caps the JSON
    //    payload (bytes, rows, string lengths); this panel enforces the same
    //    caps when a result arrives (onScanFile/onScanData), so an oversized
    //    or malformed result can never stall or exhaust the shell.
    //  * every result is tagged with the scan id it belongs to; while a scan
    //    is in flight only its own result is accepted, and results older than
    //    the newest accepted one are ignored.
    readonly property string scannerPath: Qt.resolvedUrl("scanner.py").toString().replace("file://", "")
    readonly property string pythonPath: "/usr/bin/python3"
    readonly property string stateDir: (Quickshell.env("XDG_DATA_HOME") && Quickshell.env("XDG_DATA_HOME").length > 0
        ? Quickshell.env("XDG_DATA_HOME")
        : Quickshell.env("HOME") + "/.local/share") + "/io.github.i12bp8.netneighbors"
    readonly property string scanFilePath: root.stateDir + "/scan.json"

    // Result input caps (consumer half of the size contract).
    readonly property int maxResultChars: 2000000
    readonly property int maxResultDevices: 768
    readonly property int maxFieldLen: 160

    // One scan generation at a time; results carry the id they belong to.
    property int currentScanId: 0

    // Whitelisted environment for the scanner child: with clearEnvironment
    // below, only the variables returned here exist in the child. Values are
    // read explicitly from the shell's own environment (never inherited
    // implicitly), so HOME/XDG_DATA_HOME keep both sides of the file
    // contract on identical paths.
    readonly property var scanEnv: root.buildScanEnv()

    function buildScanEnv() {
        var env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LC_ALL": "C"
        };
        var passThrough = ["HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR",
                           "DBUS_SESSION_BUS_ADDRESS"];
        for (var i = 0; i < passThrough.length; i++) {
            var value = Quickshell.env(passThrough[i]);
            if (value && value.length > 0)
                env[passThrough[i]] = value;
        }
        return env;
    }

    Process {
        id: scanProcess
        running: false
        clearEnvironment: true
        environment: root.scanEnv

        // Parsers keep both pipes drained (a closed channel would SIGPIPE the
        // scanner); their text is never parsed here - the atomically-written
        // result file below is the delivery channel.
        stdout: StdioCollector { waitForEnd: true }
        stderr: StdioCollector { waitForEnd: true }

        // Parameterless handler (like the built-in plugins): QProcess types
        // are not registered QML types, so typed arguments would not compile.
        onExited: {
            killTimer.stop();
        }
    }

    // SIGTERM escalation: a cancelled scan that is still alive after this
    // delay gets SIGKILL, so a superseding scan can never wait on it.
    Timer {
        id: killTimer
        interval: 1500
        repeat: false
        onTriggered: {
            if (scanProcess.running)
                scanProcess.signal(9); // SIGKILL
        }
    }

    // Cancellation contract: SIGTERM via running = false, escalate if needed.
    function cancelCurrentScan() {
        killTimer.stop();
        if (!scanProcess.running)
            return;
        scanProcess.running = false; // Quickshell sends SIGTERM to the child
        killTimer.start();
    }

    FileView {
        id: scanFile
        path: root.scanFilePath
        watchChanges: true
        atomicWrites: true
        printErrors: false
        onLoaded: root.onScanFile(text())
        onFileChanged: reload()
    }

    // The result file may not exist when the panel starts (nothing watches
    // a nonexistent file), so poll it gently as well. reload() on an
    // unchanged file is cheap - onScanFile de-duplicates by timestamp.
    Timer {
        id: pollTimer
        interval: 1500
        repeat: true
        running: true
        onTriggered: scanFile.reload()
    }

    // Watchdog: a scan should take a few seconds. If nothing lands in time,
    // cancel the scanner process (cancellation contract) and let the next
    // auto-scan try again.
    Timer {
        id: stallTimer
        interval: 20000
        repeat: false
        onTriggered: {
            if (root.scanning) {
                root.cancelCurrentScan();
                root.endScan(root.lastError === "" ? "scan timed out" : root.lastError);
            }
        }
    }

    // Common end-of-attempt path: mirror scan state to the UI and re-arm the
    // next automatic scan. Data/hasData semantics belong to the callers.
    function endScan(error) {
        if (error !== undefined && error !== null && String(error).length > 0)
            root.lastError = String(error);
        root.scanning = false;
        stallTimer.stop();
        root.reflow();
        root.syncHost();
        root.armAuto();
    }

    function dataFail(error) {
        root.lastError = error || "Scan failed";
        root.hasData = false;
        root.endScan(root.lastError);
    }

    function clampStr(value, max) {
        if (value === null || value === undefined)
            return "";
        var s = String(value);
        return s.length > max ? s.slice(0, max) : s;
    }

    function clampInt(value, max, fallback) {
        var n = parseInt(value, 10);
        if (!isFinite(n))
            n = fallback;
        if (n < 0) n = 0;
        if (n > max) n = max;
        return n;
    }

    // Cardinality/depth bound: whatever produced the file, the UI only ever
    // accepts this many rows and this much text per field.
    function sanitizeDevices(list) {
        var out = [];
        if (!Array.isArray(list))
            return out;
        var max = Math.min(list.length, root.maxResultDevices);
        for (var i = 0; i < max; i++) {
            var d = list[i];
            if (!d || typeof d !== "object")
                continue;
            out.push({
                ip: root.clampStr(d.ip, 64),
                mac: root.clampStr(d.mac, 32),
                vendor: root.clampStr(d.vendor, 80),
                hostname: root.clampStr(d.hostname, root.maxFieldLen),
                type: root.clampStr(d.type, 32),
                state: root.clampStr(d.state, 16),
                isNew: !!d.isNew,
                router: !!d.router,
                self: !!d.self,
                online: !!d.online,
                first: root.clampStr(d.first, 40),
                lastSeen: root.clampStr(d.lastSeen, 40)
            });
        }
        return out;
    }

    function onScanFile(raw) {
        // Size bound (consumer half of the contract): refuse anything beyond
        // the cap before it reaches JSON.parse.
        if (typeof raw !== "string" || raw.length > root.maxResultChars) {
            root.dataFail("scan result too large");
            return;
        }
        var data;
        try {
            data = JSON.parse(raw);
        } catch (e) {
            return; // partial write - the atomic replace makes this rare
        }
        if (!data || typeof data !== "object" || typeof data.ok !== "boolean")
            return;
        if (!data.ok) {
            root.dataFail(data.error || "Scan failed");
            return;
        }
        // Process identity: while a scan is in flight, only accept the result
        // tagged with the current scan id - a superseded scan may still have
        // written its file just before it was cancelled.
        if (root.scanning && typeof data.scanId === "number"
            && data.scanId !== root.currentScanId)
            return;
        // Ignore results older than the ones we already hold, keyed on the
        // scanner's own timestamp so duplicate deliveries can never regress
        // the view.
        if (root.hasData && root.lastScanAtValid && typeof data.scannedAt === "string") {
            var ts = new Date(data.scannedAt).getTime();
            if (isFinite(ts) && ts <= root.lastScanAt.getTime())
                return;
        }
        root.onScanData(data);
    }

    function onScanData(data) {
        var devices = root.sanitizeDevices(data.devices);
        var online = [], away = [];
        var i;
        for (i = 0; i < devices.length; i++) {
            if (devices[i].online)
                online.push(devices[i]);
            else
                away.push(devices[i]);
        }

        var prevSsid = root.ssid;
        var wasOnline = root.hasData;
        root.ssid = root.clampStr(data.net && data.net.ssid, 64);
        root.cidr = root.clampStr(data.net && data.net.cidr, 64);
        root.gateway = root.clampStr(data.net && data.net.gateway, 64);
        root.ifaceName = root.clampStr(data.net && data.net.iface, 32);
        root.scanMs = root.clampInt(data.scanMs, 3600000, 0);
        root.baselined = !!data.baselined;
        root.newCount = root.clampInt(data.newCount, devices.length, 0);
        root.awayCount = away.length;
        var other = 0;
        for (i = 0; i < online.length; i++) {
            if (!online[i].self)
                other++;
        }
        root.otherCount = other;
        root.dismissedNew = false;
        root.hasData = true;
        root.lastError = "";

        var scannedAt = root.clampStr(data.scannedAt, 40);
        var scannedDate = new Date(scannedAt);
        root.lastScanAt = (scannedAt !== "" && isFinite(scannedDate.getTime()))
            ? scannedDate : new Date();
        root.lastScanAtValid = true;

        root.allOnline = online;
        root.allAway = away;
        root.rebuildModels();
        root.endScan("");

        // Moving between networks is worth announcing.
        if (wasOnline && prevSsid !== "" && root.ssid !== "" && prevSsid !== root.ssid)
            root.showToast("Now on " + root.ssid);
        else if (root.newCount > 0)
            root.showToast(root.newCount + (root.newCount === 1
                ? " new device on your network"
                : " new devices on your network"));
    }

    function syncHost() {
        if (!root.hostWidget)
            return;
        root.hostWidget.deviceCount = root.otherCount;
        root.hostWidget.newCount = root.newCount;
        root.hostWidget.scanning = root.scanning;
        var netName = root.ssid !== "" ? root.ssid : (root.cidr !== "" ? root.cidr : "");
        var suffix = netName !== "" ? " — " + netName : "";
        var text = "NetNeighbors" + suffix + " · " + root.otherCount + " device"
            + (root.otherCount === 1 ? "" : "s");
        if (root.awayCount > 0)
            text += " · " + root.awayCount + " away";
        if (root.newCount > 0)
            text += " · " + root.newCount + " new";
        root.hostWidget.summaryText = text;
    }

    // Auto-rescan: every refreshSeconds while open, slower while closed so
    // the bar badge still notices new neighbors without hammering the LAN.
    Timer {
        id: autoTimer
        interval: 30000
        repeat: false
        running: false
        onTriggered: root.startScan()
    }

    function armAuto() {
        autoTimer.stop();
        if (!root.autoRefresh)
            return;
        var seconds = root.refreshSeconds;
        if (!root.opened)
            seconds = Math.max(60, seconds * 2);
        autoTimer.interval = seconds * 1000;
        autoTimer.start();
    }

    Timer {
        id: clockTimer
        interval: 1000
        repeat: true
        running: true
        onTriggered: {
            lastScanLabel.text = root.ageLabel();
        }
    }

    Timer {
        id: toastTimer
        interval: 1800
        onTriggered: toastRect.opacity = 0
    }



    onOpenedChanged: {
        if (root.opened)
            root.armAuto();
    }

    // Teardown contract: never leave a scan process running behind this
    // panel (hot reload / shell shutdown). Quickshell additionally kills
    // managed Process children whenever the shell itself goes away.
    Component.onDestruction: {
        root.cancelCurrentScan();
    }

    Component.onCompleted: {
        // First paint is instant; scan just after the shell settles.
        Qt.callLater(function () {
            root.startScan();
        });
    }

    // ---- surface ------------------------------------------------------------

    KeyboardPanel {
        id: panel
        anchorItem: root.anchorItem
        owner: root.barIdentity
        bar: root.bar
        open: root.opened
        focusTarget: keyCatcher
        contentWidth: panel.fittedContentWidth(Style.space(392))
        contentHeight: panel.fittedContentHeight(root.panelH)

        PanelKeyCatcher {
            id: keyCatcher
            anchors.fill: parent
            blocked: filterField.activeFocus
            onCloseRequested: root.close()
            onTabRequested: function (direction) {
                root.switchPanel(direction);
            }
            onTextKey: function (t) {
                if (t === "r" || t === "R")
                    root.startScan();
                else if (t === "a" || t === "A")
                    root.autoRefresh = !root.autoRefresh;
                else if (t === "f" || t === "F") {
                    filterField.forceActiveFocus();
                    filterField.selectAll();
                }
            }

            Column {
                id: contentColumn
                width: parent.width
                spacing: 0

                // ---- header -------------------------------------------------

                Item {
                    width: parent.width
                    height: root.headerH

                    Row {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.spacing.md

                        Column {
                            width: parent.width - refreshButton.width - reportButton.width - Style.spacing.md * 2
                            spacing: Style.spacing.xxs

                            // SSID, with a WI-FI/WIRED chip and a tooltip for
                            // long network names.
                            Rectangle {
                                width: parent.width
                                height: 18
                                radius: Style.cornerRadius
                                color: "transparent"

                                Row {
                                    anchors.fill: parent
                                    spacing: Style.spacing.sm

                                    Text {
                                        id: ssidText
                                        width: parent.width - (netChip.visible ? netChip.width + Style.spacing.sm : 0)
                                        text: root.ssid !== "" ? root.ssid : (root.cidr !== "" ? "Local network" : "Not connected")
                                        color: root.contentForeground
                                        font.family: root.contentFontFamily
                                        font.pixelSize: Style.font.subtitle
                                        font.bold: true
                                        elide: Text.ElideRight
                                    }

                                    Rectangle {
                                        id: netChip
                                        visible: root.ssid !== "" || root.ifaceName !== ""
                                        width: netChipText.implicitWidth + Style.space(12)
                                        height: Style.space(14)
                                        radius: Style.cornerRadius
                                        anchors.verticalCenter: parent.verticalCenter
                                        color: Util.alpha(root.contentAccent, 0.14)

                                        Text {
                                            id: netChipText
                                            anchors.centerIn: parent
                                            text: root.ssid !== "" ? "WI-FI" : "WIRED"
                                            color: root.contentAccent
                                            font.family: root.contentFontFamily
                                            font.pixelSize: Style.font.caption - 1
                                            font.bold: true
                                        }
                                    }
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    acceptedButtons: Qt.NoButton
                                    PanelToolTip {
                                        visible: parent.containsMouse
                                        text: (root.ssid !== "" ? root.ssid : "Local network") + "\n"
                                            + (root.cidr !== "" ? root.cidr : "") + (root.gateway !== "" ? " · gw " + root.gateway : "")
                                            + (root.ifaceName !== "" ? " · " + root.ifaceName : "")
                                        fontFamily: root.contentFontFamily
                                    }
                                }
                            }

                            Text {
                                id: netSubText
                                width: parent.width
                                text: root.netSubtitle()
                                color: Qt.darker(root.contentForeground, 1.6)
                                font.family: root.contentFontFamily
                                font.pixelSize: Style.font.caption
                                elide: Text.ElideRight
                            }
                        }

                        PanelActionButton {
                            id: reportButton
                            anchors.verticalCenter: parent.verticalCenter
                            iconText: Icons.GLYPH_COPY
                            tooltipText: "Copy device list"
                            foreground: root.contentForeground
                            fontFamily: root.contentFontFamily
                            onClicked: root.copyReport()
                        }

                        PanelActionButton {
                            id: refreshButton
                            anchors.verticalCenter: parent.verticalCenter
                            iconText: root.scanning ? Icons.GLYPH_SPINNER : Icons.GLYPH_REFRESH
                            tooltipText: root.scanning ? "Scanning…" : "Scan now (R)"
                            foreground: root.scanning ? root.contentAccent : root.contentForeground
                            fontFamily: root.contentFontFamily
                            onClicked: root.startScan()
                        }
                    }
                }

                Item { width: parent.width; height: root.gapH }

                // ---- filter --------------------------------------------------

                TextField {
                    id: filterField
                    width: parent.width
                    height: root.filterH
                    placeholderText: "Filter devices…"
                    foreground: root.contentForeground
                    accent: root.contentAccent
                    font.family: root.contentFontFamily
                    font.pixelSize: Style.font.bodySmall
                    onTextChanged: {
                        root.filterText = text;
                        root.rebuildModels();
                    }
                    Keys.onPressed: function (event) {
                        if (event.key === Qt.Key_Escape) {
                            if (text !== "") {
                                text = "";
                            } else {
                                keyCatcher.forceActiveFocus();
                            }
                            event.accepted = true;
                        } else if (event.key === Qt.Key_Return) {
                            keyCatcher.forceActiveFocus();
                            event.accepted = true;
                        }
                    }

                    // clear button, appears when a filter is active
                    Text {
                        anchors.right: parent.right
                        anchors.rightMargin: Style.spacing.sm
                        anchors.verticalCenter: parent.verticalCenter
                        visible: filterField.text !== ""
                        text: Icons.GLYPH_XMARK
                        color: Qt.darker(root.contentForeground, 1.5)
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.iconSmall

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                filterField.text = "";
                                filterField.forceActiveFocus();
                            }
                        }
                    }
                }

                Item { width: parent.width; height: root.gapH }

                // ---- NEW banner ---------------------------------------------

                Rectangle {
                    id: newBanner
                    visible: root.newCount > 0 && !root.dismissedNew && deviceModel.count > 1
                    width: parent.width
                    height: root.bannerH
                    radius: Style.cornerRadius
                    color: Util.alpha(root.contentAccent, 0.12)
                    border.width: Style.spacing.hairline
                    border.color: Util.alpha(root.contentAccent, 0.5)

                    Row {
                        anchors.fill: parent
                        anchors.leftMargin: Style.space(12)
                        anchors.rightMargin: Style.space(8)
                        spacing: Style.spacing.sm

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: Icons.GLYPH_ALERT
                            color: root.contentAccent
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.iconSmall
                        }

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.newCount + (root.newCount === 1 ? " new device" : " new devices") + " just showed up"
                            color: root.contentAccent
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.bodySmall
                            font.bold: true
                            elide: Text.ElideRight
                            width: parent.width - 28
                        }

                        Item { width: Style.space(4) }

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "dismiss"
                            color: Qt.darker(root.contentForeground, 1.4)
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption

                            MouseArea {
                                anchors.fill: parent
                                onClicked: {
                                    root.dismissedNew = true;
                                    root.reflow();
                                }
                                cursorShape: Qt.PointingHandCursor
                            }
                        }
                    }
                }

                Item {
                    id: bannerGap
                    visible: newBanner.visible
                    width: parent.width
                    height: visible ? root.gapH : 0
                }

                // ---- device list / states -----------------------------------

                ListView {
                    id: deviceList
                    width: parent.width
                    height: root.listBlockH
                    clip: true
                    model: deviceModel
                    spacing: Style.spacing.sm
                    boundsBehavior: Flickable.StopAtBounds
                    visible: root.hasData && root.otherCount > 0

                    delegate: Rectangle {
                        required property string kind
                        required property string label
                        required property string ip
                        required property string mac
                        required property string vendor
                        required property string hostname
                        required property string type
                        required property bool isNew
                        required property bool router
                        required property bool self
                        required property bool online
                        required property string lastSeen

                        id: row
                        readonly property string rowKey: mac !== "" ? mac : (ip !== "" ? ip : "self")
                        width: deviceList.width
                        height: kind === "header" || kind === "empty"
                            ? root.labelH
                            : (root.rowH + (root.expandState(rowKey) ? root.rowExpandH : 0))
                        radius: Style.cornerRadius
                        color: kind === "row" && rowMouse.containsMouse
                            ? Style.hoverFillFor(root.contentForeground, root.contentAccent)
                            : (kind === "row" && isNew ? Util.alpha(root.contentAccent, 0.06) : "transparent")

                        // ---- section header ----------------------------------
                        Item {
                            visible: kind === "header"
                            width: parent.width
                            height: parent.height

                            Text {
                                id: headerLabel
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                                text: label
                                color: Qt.darker(root.contentForeground, 1.8)
                                font.family: root.contentFontFamily
                                font.pixelSize: Style.font.caption
                                font.bold: true
                                font.letterSpacing: 1
                            }

                            Rectangle {
                                anchors.left: headerLabel.right
                                anchors.leftMargin: Style.spacing.md
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                height: Style.spacing.hairline
                                color: Util.alpha(root.contentForeground, 0.10)
                            }
                        }

                        // ---- empty-filter note --------------------------------
                        Text {
                            visible: kind === "empty"
                            anchors.centerIn: parent
                            text: "No devices match your filter"
                            color: Qt.darker(root.contentForeground, 1.9)
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption
                        }

                        // ---- device row --------------------------------------
                        Item {
                            id: mainArea
                            visible: kind === "row"
                            width: parent.width
                            height: root.rowH

                            Rectangle {
                                anchors.fill: parent
                                radius: row.radius
                                color: "transparent"
                                visible: isNew
                                border.width: Style.spacing.hairline
                                border.color: Util.alpha(root.contentAccent, 0.55)
                            }

                            MouseArea {
                                id: rowMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: ip !== "" ? Qt.PointingHandCursor : Qt.ArrowCursor
                                acceptedButtons: Qt.LeftButton | Qt.RightButton
                                onClicked: function (mouse) {
                                    if (mouse.button === Qt.RightButton)
                                        root.copyText(root.macPretty(mac), "MAC copied");
                                    else
                                        root.copyText(ip, "IP " + ip + " copied");
                                }

                                PanelToolTip {
                                    visible: rowMouse.containsMouse
                                    text: root.rowDetails(ip, mac, vendor, hostname, type, isNew, router, self, online, lastSeen)
                                    fontFamily: root.contentFontFamily
                                }
                            }

                            // device icon
                            Item {
                                id: iconArea
                                anchors.left: parent.left
                                anchors.leftMargin: Style.space(6)
                                anchors.verticalCenter: parent.verticalCenter
                                width: Style.space(30)
                                height: Style.space(30)

                                Rectangle {
                                    anchors.fill: parent
                                    radius: width / 2
                                    color: !online
                                        ? Util.alpha(root.contentForeground, 0.04)
                                        : (self
                                            ? Util.alpha(root.contentForeground, 0.06)
                                            : (router || isNew
                                                ? Util.alpha(root.contentAccent, 0.16)
                                                : Util.alpha(root.contentForeground, 0.09)))
                                }

                                Text {
                                    anchors.centerIn: parent
                                    text: root.rowGlyph(self, vendor, router, type)
                                    color: !online
                                        ? Qt.darker(root.contentForeground, 2.2)
                                        : (self
                                            ? Qt.darker(root.contentForeground, 1.4)
                                            : (router || isNew ? root.contentAccent : root.contentForeground))
                                    font.family: root.contentFontFamily
                                    font.pixelSize: Style.font.iconSmall
                                }
                            }

                            // name + details
                            Column {
                                anchors.left: iconArea.right
                                anchors.leftMargin: Style.space(10)
                                anchors.right: chipRow.left
                                anchors.rightMargin: Style.space(6)
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.spacing.xxs

                                Text {
                                    width: parent.width
                                    text: root.rowTitle(hostname, router, vendor)
                                    color: !online
                                        ? Qt.darker(root.contentForeground, 2.1)
                                        : (self
                                            ? Qt.darker(root.contentForeground, 1.4)
                                            : (isNew ? root.contentAccent : root.contentForeground))
                                    font.family: root.contentFontFamily
                                    font.pixelSize: Style.font.body
                                    font.bold: true
                                    elide: Text.ElideRight
                                }

                                Text {
                                    width: parent.width
                                    text: root.rowSubtitle(ip, self, vendor, hostname, mac, online, lastSeen)
                                    color: !online
                                        ? Qt.darker(root.contentForeground, 2.3)
                                        : Qt.darker(root.contentForeground, 1.6)
                                    font.family: root.contentFontFamily
                                    font.pixelSize: Style.font.caption
                                    elide: Text.ElideRight
                                }
                            }

                            // right chips + expand chevron
                            Row {
                                id: chipRow
                                anchors.right: parent.right
                                anchors.rightMargin: Style.space(6)
                                anchors.verticalCenter: parent.verticalCenter
                                spacing: Style.spacing.xxs

                                Rectangle {
                                    visible: self
                                    width: chipSelf.implicitWidth + Style.space(12)
                                    height: Style.space(15)
                                    radius: height / 2
                                    color: Util.alpha(root.contentForeground, 0.10)

                                    Text {
                                        id: chipSelf
                                        anchors.centerIn: parent
                                        text: "YOU"
                                        color: Qt.darker(root.contentForeground, 1.3)
                                        font.family: root.contentFontFamily
                                        font.pixelSize: Style.font.caption - 1
                                        font.bold: true
                                    }
                                }

                                Rectangle {
                                    visible: router && !self && !isNew
                                    width: chipGw.implicitWidth + Style.space(12)
                                    height: Style.space(15)
                                    radius: height / 2
                                    color: Util.alpha(root.contentAccent, 0.16)

                                    Text {
                                        id: chipGw
                                        anchors.centerIn: parent
                                        text: "GATEWAY"
                                        color: root.contentAccent
                                        font.family: root.contentFontFamily
                                        font.pixelSize: Style.font.caption - 1
                                        font.bold: true
                                    }
                                }

                                Rectangle {
                                    visible: isNew && !self && !router
                                    width: chipNew.implicitWidth + Style.space(12)
                                    height: Style.space(15)
                                    radius: height / 2
                                    color: root.contentAccent

                                    Text {
                                        id: chipNew
                                        anchors.centerIn: parent
                                        text: "NEW"
                                        color: root.chipTextColor()
                                        font.family: root.contentFontFamily
                                        font.pixelSize: Style.font.caption - 1
                                        font.bold: true
                                    }
                                }

                                // expand / collapse
                                Text {
                                    id: chevron
                                    anchors.verticalCenter: parent.verticalCenter
                                    text: root.expandState(rowKey) ? Icons.GLYPH_CHEVRON_UP : Icons.GLYPH_CHEVRON_DOWN
                                    color: Qt.darker(root.contentForeground, 1.8)
                                    font.family: root.contentFontFamily
                                    font.pixelSize: Style.font.caption

                                    MouseArea {
                                        anchors.fill: parent
                                        anchors.leftMargin: -Style.spacing.md
                                        anchors.rightMargin: -Style.spacing.md
                                        anchors.topMargin: -Style.spacing.sm
                                        anchors.bottomMargin: -Style.spacing.sm
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: {
                                            root.toggleDevice(rowKey);
                                        }
                                    }
                                }
                            }

                            // expanded details
                            Item {
                                id: detailArea
                                visible: root.expandState(rowKey)
                                y: root.rowH
                                width: parent.width
                                height: root.rowExpandH

                                Column {
                                    anchors.fill: parent
                                    anchors.leftMargin: Style.space(48)
                                    anchors.rightMargin: Style.space(10)
                                    anchors.topMargin: Style.space(2)
                                    spacing: Style.spacing.sm

                                    Text {
                                        width: parent.width
                                        text: root.rowDetailText(vendor, hostname, mac, type, isNew, router, self, online, lastSeen)
                                        color: Qt.darker(root.contentForeground, 1.6)
                                        font.family: root.contentFontFamily
                                        font.pixelSize: Style.font.caption
                                        wrapMode: Text.WordWrap
                                        maximumLineCount: 2
                                        elide: Text.ElideRight
                                    }

                                    Row {
                                        spacing: Style.spacing.xs

                                        Text {
                                            text: "copy IP"
                                            color: Qt.darker(root.contentForeground, 1.4)
                                            font.family: root.contentFontFamily
                                            font.pixelSize: Style.font.caption

                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: root.copyText(ip, "IP " + ip + " copied")
                                            }
                                        }

                                        Text {
                                            text: "· copy MAC"
                                            color: Qt.darker(root.contentForeground, 1.4)
                                            font.family: root.contentFontFamily
                                            font.pixelSize: Style.font.caption

                                            MouseArea {
                                                anchors.fill: parent
                                                cursorShape: Qt.PointingHandCursor
                                                onClicked: root.copyText(root.macPretty(mac), "MAC copied")
                                            }
                                        }

                                    }
                                }
                            }
                        }
                    }
                }

                // empty / error / offline states
                Rectangle {
                    id: stateBox
                    width: parent.width
                    height: root.listBlockH
                    visible: !deviceList.visible
                    radius: Style.cornerRadius
                    color: Util.alpha(root.contentForeground, 0.04)

                    Column {
                        anchors.centerIn: parent
                        spacing: Style.spacing.md

                        Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            text: root.lastError !== ""
                                ? Icons.GLYPH_ALERT
                                : (root.scanning ? Icons.GLYPH_SPINNER : Icons.GLYPH_RADAR)
                            color: root.lastError !== ""
                                ? root.contentUrgent
                                : (root.scanning ? root.contentAccent : Qt.darker(root.contentForeground, 1.3))
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.iconLarge
                        }

                        Text {
                            anchors.horizontalCenter: parent.horizontalCenter
                            text: root.lastError !== ""
                                ? "Scan failed"
                                : (root.scanning
                                    ? "Scanning " + (root.ssid !== "" ? root.ssid : "the network") + "…"
                                    : (root.hasData && root.otherCount === 0
                                        ? "No other devices answered"
                                        : "Not connected yet"))
                            color: root.contentForeground
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.bodySmall
                            font.bold: root.lastError === ""
                        }

                        Text {
                            visible: root.lastError !== ""
                            anchors.horizontalCenter: parent.horizontalCenter
                            width: Math.min(implicitWidth, stateBox.width - Style.space(24))
                            horizontalAlignment: Text.AlignHCenter
                            text: root.lastError
                            color: Qt.darker(root.contentForeground, 1.5)
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption
                            wrapMode: Text.WordWrap
                        }

                        Text {
                            visible: root.hasData && root.otherCount === 0 && root.lastError === ""
                            anchors.horizontalCenter: parent.horizontalCenter
                            width: Math.min(implicitWidth, stateBox.width - Style.space(24))
                            horizontalAlignment: Text.AlignHCenter
                            text: "Café and guest networks often isolate clients — you may only ever see the gateway here. On your own LAN, everyone wakes up for a scan."
                            color: Qt.darker(root.contentForeground, 1.6)
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption
                            wrapMode: Text.WordWrap
                        }
                    }
                }

                Item { width: parent.width; height: root.gapH }

                // ---- footer --------------------------------------------------

                Item {
                    width: parent.width
                    height: root.footerH

                    Row {
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.spacing.sm

                        ToggleSwitch {
                            id: autoToggle
                            anchors.verticalCenter: parent.verticalCenter
                            checked: root.autoRefresh
                            foreground: root.contentForeground
                            accent: root.contentAccent
                            onToggled: {
                                root.autoRefresh = checked;
                                if (checked) root.armAuto();
                                else autoTimer.stop();
                            }
                        }

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "Auto · every " + root.refreshSeconds + "s"
                            color: root.autoRefresh ? Qt.darker(root.contentForeground, 1.3) : Qt.darker(root.contentForeground, 2.0)
                            font.family: root.contentFontFamily
                            font.pixelSize: Style.font.caption
                        }
                    }

                    Text {
                        id: lastScanLabel
                        anchors.right: parent.right
                        anchors.rightMargin: Style.space(2)
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.ageLabel()
                        color: Qt.darker(root.contentForeground, 1.6)
                        font.family: root.contentFontFamily
                        font.pixelSize: Style.font.caption
                    }
                }
            }
        }
    }

    // ---- toast --------------------------------------------------------------

    Rectangle {
        id: toastRect
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: Style.space(10)
        width: toastLabel.implicitWidth + Style.space(24)
        height: Style.space(26)
        radius: height / 2
        color: Util.alpha(root.contentForeground, 0.92)
        opacity: 0
        z: 10

        Behavior on opacity { NumberAnimation { duration: 160 } }

        Text {
            id: toastLabel
            anchors.centerIn: parent
            text: ""
            color: root.surface
            font.family: root.contentFontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: true
        }
    }

    // ---- row content helpers ------------------------------------------------

    function rowGlyph(isSelf, vendor, router, type) {
        if (isSelf)
            return Icons.GLYPH_LAPTOP;
        var brand = Icons.brandGlyph(vendor);
        if (brand !== "")
            return brand;
        if (router)
            return Icons.GLYPH_ROUTER;
        return Icons.glyphForType(type);
    }

    function rowTitle(hostname, router, vendor) {
        if (hostname && hostname.length > 0)
            return hostname;
        if (router)
            return "Gateway";
        if (vendor && vendor.length > 0)
            return vendor;
        return "Unknown device";
    }

    function rowSubtitle(ip, isSelf, vendor, hostname, mac, online, lastSeen) {
        if (!online) {
            var awayParts = [];
            var seen = root.lastSeenLabel(lastSeen);
            if (seen !== "")
                awayParts.push("seen " + seen);
            if (mac)
                awayParts.push(root.macPretty(mac));
            if (awayParts.length === 0)
                awayParts.push("known device");
            return awayParts.join("  ·  ");
        }
        var parts = [];
        if (ip)
            parts.push(ip);
        if (isSelf) {
            parts.push("this machine");
        } else if (vendor && vendor !== root.rowTitle(hostname, false, vendor)) {
            // vendor already shown as the title - don't repeat it
            parts.push(vendor);
        }
        if (mac && !isSelf)
            parts.push(root.macPretty(mac));
        return parts.join("  ·  ");
    }

    function typeLabel(type) {
        var names = {
            router: "router / access point",
            phone: "phone",
            tablet: "tablet",
            laptop: "laptop",
            desktop: "desktop",
            computer: "computer",
            server: "server",
            tv: "tv / streaming",
            console: "game console",
            speaker: "smart speaker",
            camera: "camera",
            printer: "printer",
            nas: "network storage",
            iot: "smart device",
            unknown: "unidentified"
        };
        return names[type] || type || "unidentified";
    }

    // Full detail, for hover tooltips and expanded rows.
    function rowDetails(ip, mac, vendor, hostname, type, isNew, router, self, online, lastSeen) {
        var lines = [];
        lines.push(root.rowTitle(hostname, router, vendor) + (self ? " (this machine)" : ""));
        if (vendor && vendor !== root.rowTitle(hostname, router, vendor))
            lines.push("Vendor: " + vendor);
        lines.push("Type: " + root.typeLabel(type));
        if (ip)
            lines.push("IP: " + ip);
        if (mac)
            lines.push("MAC: " + root.macPretty(mac));
        if (online) {
            if (router)
                lines.push("Acts as this network's gateway");
            if (isNew)
                lines.push("Never seen on this network before");
            lines.push("Status: online");
        } else {
            lines.push("Status: away · last seen " + root.lastSeenLabel(lastSeen));
        }
        return lines.join("\n");
    }

    function rowDetailText(vendor, hostname, mac, type, isNew, router, self, online, lastSeen) {
        var parts = [];
        parts.push("Type: " + root.typeLabel(type));
        if (mac)
            parts.push("MAC " + root.macPretty(mac));
        if (online)
            parts.push("Status online");
        else
            parts.push("Seen " + root.lastSeenLabel(lastSeen));
        if (isNew)
            parts.push("NEW");
        return parts.join("   ·   ");
    }

    // Plain-text snapshot of the current scan, for sharing/notes.
    function copyReport() {
        if (!root.hasData)
            return;
        var lines = [];
        var netName = root.ssid !== "" ? root.ssid : (root.cidr !== "" ? root.cidr : "local network");
        lines.push("NetNeighbors — " + netName);
        lines.push(Qt.formatDateTime(new Date(), "yyyy-MM-dd HH:mm") + " · "
            + root.otherCount + " device" + (root.otherCount === 1 ? "" : "s")
            + (root.awayCount > 0 ? " · " + root.awayCount + " away" : ""));
        if (root.cidr) lines.push("Network " + root.cidr);
        if (root.gateway) lines.push("Gateway " + root.gateway);
        var sawDevice = false;
        for (var i = 0; i < deviceModel.count; i++) {
            var d = deviceModel.get(i);
            if (d.kind !== "row")
                continue;
            if (d.self)
                continue;
            var name = d.hostname && d.hostname.length > 0 ? d.hostname : (d.vendor || "Device");
            var tags = [];
            if (d.router) tags.push("gateway");
            if (d.isNew) tags.push("new");
            if (d.online) {
                var line = name + (d.vendor && d.vendor !== name ? " (" + d.vendor + ")" : "")
                    + (d.ip ? " " + d.ip : "") + (d.mac ? " " + root.macPretty(d.mac) : "");
                if (tags.length > 0) line += "  [" + tags.join(", ") + "]";
                lines.push(line);
                sawDevice = true;
            } else {
                lines.push("* " + name + " — away, last seen " + root.lastSeenLabel(d.lastSeen));
            }
        }
        if (!sawDevice)
            lines.push("(no other devices online right now)");
        root.copyText(lines.join("\n"), "Device list copied");
    }

    function netSubtitle() {
        var parts = [];
        if (root.cidr)
            parts.push(root.cidr);
        if (root.ifaceName)
            parts.push(root.ifaceName);
        if (root.hasData) {
            var label = root.otherCount + (root.otherCount === 1 ? " other device" : " other devices");
            if (root.awayCount > 0)
                label += " · " + root.awayCount + " away";
            parts.push(label);
        }
        return parts.join("  ·  ");
    }
}
