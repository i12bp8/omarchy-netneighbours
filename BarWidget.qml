import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui
import "ui/icons.js" as Icons

// BarWidget.qml - the NetNeighbors bar button and popup host.
//
// Contract with the shell (mirrors the built-in plugins): the widget root
// exposes open/close/opened so bar popout routing and
// `omarchy-shell shell summon <id>` can drive the panel. The panel is
// loaded lazily through a Loader and injected with the bar context (bar,
// settings, anchor button) once ready.
//
// The button is a globe with a live device count tucked right next to the
// glyph. The count text is positioned from the glyph's own painted metrics
// (not from the icon slot), so it hugs the globe and shares its baseline
// exactly - no matter the theme font. The panel keeps the counters fresh
// and sets summaryText for the tooltip.
BarWidget {
    id: root
    moduleName: "io.github.i12bp8.netneighbors"

    readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
    readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

    // Live state mirrored from the panel so the bar button can summarize
    // the last scan without owning any scan logic.
    property int deviceCount: 0
    property int newCount: 0
    property bool scanning: false
    property string summaryText: "NetNeighbors — who's on this network"

    // Micro-adjustments for the superscript count (px). Zero should be
    // right for the stock Nerd Font; tweak if a custom theme font sits
    // differently.
    property int countGap: 1
    property int countTopAdjust: 0

    function open() {
        if (panelLoader.item)
            panelLoader.item.open();
    }

    function close() {
        if (panelLoader.item)
            panelLoader.item.close();
    }

    function toggle() {
        if (panelLoader.item)
            panelLoader.item.toggle();
    }

    function closeForPopoutSwitch() {
        if (panelLoader.item)
            panelLoader.item.closeForPopoutSwitch();
    }

    function refresh() {
        if (panelLoader.item && panelLoader.item.refresh)
            panelLoader.item.refresh();
    }

    function injectPanel() {
        var target = panelLoader.item;
        if (!target)
            return;
        if ("bar" in target)
            target.bar = root.bar;
        if ("settings" in target)
            target.settings = root.settings;
        if ("anchorItem" in target)
            target.anchorItem = button;
        if ("hostWidget" in target)
            target.hostWidget = root;
    }

    // Count-text placement, derived from the glyph's own painted metrics:
    // the number sits like a superscript badge at the globe's top-right
    // corner, whatever the theme font.
    function countTextX() {
        var painted = button.glyphPaintedWidth > 0 ? button.glyphPaintedWidth : button.width;
        var glyphLeft = (button.width - painted) / 2;
        return button.x + glyphLeft + painted + root.countGap;
    }

    function countTextY() {
        var canvasTop = button.y + (button.height - Style.bar.iconCanvas) / 2;
        return canvasTop + root.countTopAdjust;
    }

    // Open-panel indicator dot, sized like the icon widgets' mark.
    readonly property real openPanelIndicatorWidth: Style.space(6)
    readonly property real openPanelIndicatorHeight: Math.max(Style.space(2), Math.round(Style.bar.iconSlot * 0.2))

    implicitWidth: countText.visible
        ? Style.bar.iconSlot + countText.width + root.countGap
        : Style.bar.iconSlot
    implicitHeight: button.implicitHeight

    onBarChanged: injectPanel()
    onSettingsChanged: injectPanel()

    Loader {
        id: panelLoader
        active: true
        source: Qt.resolvedUrl("Panel.qml")
        visible: false
        onLoaded: {
            root.injectPanel();
            Qt.callLater(root.injectPanel);
        }
    }

    IpcHandler {
        target: "io.github.i12bp8.netneighbors"

        function refresh(): void {
            root.broadcast("refresh");
        }
        function open(): void {
            root.open();
        }
        function close(): void {
            root.close();
        }
        function show(): void {
            root.open();
        }
        function hide(): void {
            root.close();
        }
        function toggle(): void {
            root.toggle();
        }
    }

    BarIconButton {
        id: button
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: Style.bar.iconSlot
        bar: root.bar
        text: Icons.GLYPH_GLOBE
        tooltipText: root.summaryText
        onPressed: function (buttonCode) {
            if (buttonCode === Qt.LeftButton)
                root.toggle();
            else if (buttonCode === Qt.RightButton)
                root.open();
        }

        // Radar-sweep rotation while a scan is in flight: the globe spins
        // for the couple of seconds a sweep takes, then settles on its
        // meridian. The superscript count stays put.
        RotationAnimator on rotation {
            running: root.scanning
            from: 0
            to: 360
            duration: 1200
            loops: Animation.Infinite
        }
    }

    // Font metrics for aligning the count's baseline with the glyph's.
    FontMetrics {
        id: countMetrics
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: root.newCount > 0
    }

    // Device count, positioned against the globe glyph itself: x starts at
    // the glyph's painted right edge (+gap), y puts the count baseline on
    // the glyph baseline. Empty until the first scan finishes.
    Text {
        id: countText
        visible: !root.vertical && root.deviceCount > 0
        text: root.deviceCount > 0 ? String(root.deviceCount) : ""
        color: root.newCount > 0
            ? (root.bar ? (root.bar.accent || Color.accent) : Color.accent)
            : (root.bar ? root.bar.foreground : Color.foreground)
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: root.newCount > 0

        // The glyph metrics live on the BarIconButton; they become valid
        // once the icon font resolves, and settle when text changes.
        x: root.countTextX()
        y: root.countTextY()
    }
}
