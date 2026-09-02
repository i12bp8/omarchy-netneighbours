// icons.js - glyphs used by the NetNeighbors UI.
//
// Bar, panel, and row icons. FA icons (U+F000 block) and the md-* set are
// drawn from JetBrainsMono Nerd Font, the family the Omarchy bar resolves
// through its fontconfig alias. The md-* entries below the BMP are written
// as UTF-16 surrogate pairs, mirroring the shell's glyph tables.

// ---- bar + actions ---------------------------------------------------------

var GLYPH_NET = "\uF1EB";             // fa-wifi (unused, kept for reference)
var GLYPH_GLOBE = "\uF0AC";            // fa-globe - the bar icon (internet globe)
var GLYPH_REFRESH = "\uDB81\uDC50";    // md-refresh
var GLYPH_COPY = "\uDB80\uDD8F";       // md-content_copy
var GLYPH_CHECK = "\uDB80\uDD2C";      // md-check
var GLYPH_ALERT = "\uDB80\uDC26";      // md-alert
var GLYPH_CLOSE = "\uDB80\uDD56";      // md-close
var GLYPH_SPINNER = "\uF110";             // fa-spinner (the md-progress_clock codepoint renders as a cart in the bundled Nerd Font)
var GLYPH_RADAR = "\uDB81\uDC37";      // md-radar
var GLYPH_CHEVRON_DOWN = "\uF078";   // fa-chevron-down
var GLYPH_CHEVRON_UP = "\uF077";      // fa-chevron-up
var GLYPH_HISTORY = "\uDB80\uDEDA";    // md-history (away/recently seen)

// ---- device types ----------------------------------------------------------
//
// Best-effort per-type glyphs. Rows fall back to GLYPH_UNKNOWN for anything
// the classifier could not name.

var GLYPH_ROUTER = "\uF0E8";           // fa-sitemap - network gear
var GLYPH_PHONE = "\uF10B";            // fa-mobile
var GLYPH_TABLET = "\uF10A";           // fa-tablet
var GLYPH_LAPTOP = "\uF109";           // fa-laptop
var GLYPH_DESKTOP = "\uF108";          // fa-desktop
var GLYPH_SERVER = "\uF233";           // fa-server
var GLYPH_TV = "\uF26C";               // fa-television
var GLYPH_CONSOLE = "\uF11B";          // fa-gamepad
var GLYPH_SPEAKER = "\uF028";          // fa-volume-up
var GLYPH_CAMERA = "\uF030";           // fa-camera
var GLYPH_PRINTER = "\uF02F";          // fa-print
var GLYPH_NAS = "\uF0A0";              // fa-hdd
var GLYPH_IOT = "\uF0EB";              // fa-lightbulb (smart home)
var GLYPH_UNKNOWN = "\uF2DB";          // fa-microchip (generic hardware)

var GLYPH_BY_TYPE = {
  router: GLYPH_ROUTER,
  phone: GLYPH_PHONE,
  tablet: GLYPH_TABLET,
  laptop: GLYPH_LAPTOP,
  desktop: GLYPH_DESKTOP,
  computer: GLYPH_LAPTOP,
  server: GLYPH_SERVER,
  tv: GLYPH_TV,
  console: GLYPH_CONSOLE,
  speaker: GLYPH_SPEAKER,
  camera: GLYPH_CAMERA,
  printer: GLYPH_PRINTER,
  nas: GLYPH_NAS,
  iot: GLYPH_IOT,
  unknown: GLYPH_UNKNOWN
};

function glyphForType(type) {
  var g = GLYPH_BY_TYPE[String(type || "unknown").toLowerCase()];
  return g !== undefined ? g : GLYPH_UNKNOWN;
}

// ---- brand marks -----------------------------------------------------------
//
// When the vendor is recognizable, the row icon is the brand mark instead
// of the device-type glyph (Apple phone vs. generic phone).

var GLYPH_BRAND_APPLE = "\uF179";      // fa-apple
var GLYPH_BRAND_ANDROID = "\uF17B";    // fa-android
var GLYPH_BRAND_WINDOWS = "\uF17A";    // fa-windows
var GLYPH_BRAND_LINUX = "\uF17C";      // fa-linux
var GLYPH_BRAND_GOOGLE = "\uF1A0";     // fa-google

function brandGlyph(vendor) {
  var v = String(vendor || "").toLowerCase();
  if (v.indexOf("apple") >= 0) return GLYPH_BRAND_APPLE;
  if (v.indexOf("google") >= 0) return GLYPH_BRAND_GOOGLE;
  if (v.indexOf("microsoft") >= 0) return GLYPH_BRAND_WINDOWS;
  if (v.indexOf("linux") >= 0) return GLYPH_BRAND_LINUX;
  return "";
}

var GLYPH_XMARK = "\uF00D";              // fa-xmark (clear filter)
