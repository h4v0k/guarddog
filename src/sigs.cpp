// Signature tables. Prefix/UUID/company-ID facts compiled from the IEEE registry,
// Bluetooth SIG assigned numbers, colonelpanichacks/flock-you (MIT), the DeFlock
// community and the SquachWatch-CYD research notes (prefixes re-checked there
// against the IEEE registry; Espressif and Samsung blocks deliberately excluded).
#include "sigs.h"
#include "common.h"

struct OuiRow {
  uint8_t b[3];
  DetType t;
  Conf c;
  const char* label;
};

static const OuiRow OUIS[] = {
    // body cameras / TASER
    {{0x00, 0x25, 0xDF}, DT_BODYCAM, CF_HIGH, "Axon"},
    {{0xE4, 0x05, 0x40}, DT_BODYCAM, CF_LOW, "Axon?"},
    {{0x28, 0x24, 0xFF}, DT_BODYCAM, CF_LOW, "Axon Signal?"},
    {{0x00, 0x1D, 0x96}, DT_BODYCAM, CF_MED, "WatchGuard"},
    {{0x00, 0x23, 0xBD}, DT_BODYCAM, CF_MED, "Digital Ally"},
    // gunshot sensors
    {{0xD4, 0x11, 0xD6}, DT_RAVEN, CF_HIGH, "ShotSpotter"},
    // Flock Safety: own MA-L is HIGH, module-vendor blocks are LOW
    {{0xB4, 0x1E, 0x52}, DT_FLOCK, CF_HIGH, "Flock Safety"},
    {{0x24, 0xB2, 0xB9}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xD0, 0x39, 0x57}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x00, 0xF4, 0x8D}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x14, 0x5A, 0xFC}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x80, 0x30, 0x49}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xE0, 0x0A, 0xF6}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x70, 0xC9, 0x4E}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x3C, 0x91, 0x80}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xD8, 0xF3, 0xBC}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xB8, 0x35, 0x32}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x82, 0x6B, 0xF2}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x74, 0x4C, 0xA1}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x9C, 0x2F, 0x9D}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xC0, 0x35, 0x32}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x94, 0x08, 0x53}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xE4, 0xAA, 0xEA}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xF4, 0x6A, 0xDD}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xE8, 0xD0, 0xFC}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xB8, 0x1E, 0xA4}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x70, 0x08, 0x94}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x58, 0x00, 0xE3}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x5C, 0x93, 0xA2}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x64, 0x6E, 0x69}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x14, 0xB5, 0xCD}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x08, 0x3A, 0x88}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xE0, 0x4F, 0x43}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x58, 0x8E, 0x81}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0xEC, 0x1B, 0xBD}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x90, 0x35, 0xEA}, DT_FLOCK, CF_LOW, "Flock?"},
    {{0x00, 0x03, 0x7F}, DT_FLOCK, CF_LOW, "Flock? (QCA)"},
    // ALPR: Motorola Solutions (Vigilant) + Genetec AutoVu
    {{0x00, 0x04, 0x7D}, DT_ALPR, CF_HIGH, "Motorola"},
    {{0x00, 0x18, 0x85}, DT_ALPR, CF_HIGH, "Motorola"},
    {{0x00, 0x1F, 0x92}, DT_ALPR, CF_HIGH, "Motorola"},
    {{0x4C, 0xCC, 0x34}, DT_ALPR, CF_HIGH, "Motorola"},
    {{0xB8, 0xE2, 0x8C}, DT_ALPR, CF_HIGH, "Motorola"},
    {{0x00, 0xBF, 0x15}, DT_ALPR, CF_HIGH, "Genetec"},
    {{0x0C, 0xBF, 0x15}, DT_ALPR, CF_HIGH, "Genetec"},
    // card skimmer BT modules
    {{0x20, 0x13, 0x00}, DT_SKIMMER, CF_LOW, "Linvor BT"},
    {{0x98, 0xD3, 0x31}, DT_SKIMMER, CF_LOW, "HC-05 BT"},
    {{0x00, 0x1A, 0x7D}, DT_SKIMMER, CF_LOW, "CSR BT"},
    // camera glasses
    {{0x98, 0x59, 0x49}, DT_GLASSES, CF_MED, "Luxottica"},
    // drones
    {{0x60, 0x60, 0x1F}, DT_DRONE, CF_MED, "DJI"},
    {{0x34, 0xD2, 0x62}, DT_DRONE, CF_MED, "DJI"},
    {{0x48, 0x1C, 0xB9}, DT_DRONE, CF_MED, "DJI"},
    {{0xE4, 0x7A, 0x2C}, DT_DRONE, CF_MED, "DJI"},
    {{0x58, 0xB8, 0x58}, DT_DRONE, CF_MED, "DJI"},
    {{0x04, 0xA8, 0x5A}, DT_DRONE, CF_MED, "DJI"},
    {{0x8C, 0x58, 0x23}, DT_DRONE, CF_MED, "DJI"},
    {{0x0C, 0x9A, 0xE6}, DT_DRONE, CF_MED, "DJI"},
    {{0x88, 0x29, 0x85}, DT_DRONE, CF_MED, "DJI"},
    {{0x4C, 0x43, 0xF6}, DT_DRONE, CF_MED, "DJI"},
    {{0x38, 0x1D, 0x14}, DT_DRONE, CF_HIGH, "Skydio"},
    {{0x90, 0x03, 0xB7}, DT_DRONE, CF_MED, "Parrot"},
    {{0x90, 0x3A, 0xE6}, DT_DRONE, CF_MED, "Parrot"},
    {{0xA0, 0x14, 0x3D}, DT_DRONE, CF_MED, "Parrot"},
    // hacker gear (Hak5 locally-administered defaults)
    {{0x02, 0xC0, 0xCA}, DT_HACKER, CF_LOW, "Hak5?"},
    {{0x02, 0x13, 0x37}, DT_HACKER, CF_LOW, "Hak5?"},
    // fixed / pro cameras
    {{0xE0, 0xA7, 0x00}, DT_CAMERA, CF_HIGH, "Verkada"},
    {{0x70, 0x1A, 0xD5}, DT_CAMERA, CF_HIGH, "Avigilon"},
    {{0x00, 0x40, 0x8C}, DT_CAMERA, CF_HIGH, "Axis"},
    {{0xB8, 0xA4, 0x4F}, DT_CAMERA, CF_HIGH, "Axis"},
    {{0xD4, 0x2D, 0xC5}, DT_CAMERA, CF_HIGH, "i-PRO"},
    {{0xC0, 0x56, 0xE3}, DT_CAMERA, CF_HIGH, "Hikvision"},
    {{0x44, 0x19, 0xB6}, DT_CAMERA, CF_HIGH, "Hikvision"},
    {{0x28, 0x57, 0xBE}, DT_CAMERA, CF_HIGH, "Hikvision"},
    {{0x2C, 0xAA, 0x8E}, DT_CAMERA, CF_HIGH, "Wyze"},
    {{0xD0, 0x3F, 0x27}, DT_CAMERA, CF_HIGH, "Wyze"},
    {{0x7C, 0x78, 0xB2}, DT_CAMERA, CF_HIGH, "Wyze"},
    {{0xFC, 0x9C, 0x98}, DT_CAMERA, CF_HIGH, "Arlo"},
    {{0x48, 0x62, 0x64}, DT_CAMERA, CF_HIGH, "Arlo"},
    {{0xA4, 0x11, 0x62}, DT_CAMERA, CF_HIGH, "Arlo"},
    {{0x3C, 0xA0, 0x70}, DT_CAMERA, CF_MED, "Blink"},
    {{0x70, 0xAD, 0x43}, DT_CAMERA, CF_MED, "Blink"},
    {{0x74, 0x13, 0x48}, DT_CAMERA, CF_MED, "Blink"},
    {{0x74, 0xAB, 0x93}, DT_CAMERA, CF_MED, "Blink"},
    {{0xC8, 0x19, 0xD8}, DT_CAMERA, CF_MED, "Blink"},
    {{0xF0, 0x74, 0xC1}, DT_CAMERA, CF_MED, "Blink"},
    // Ring
    {{0xAC, 0x9F, 0xC3}, DT_RING, CF_HIGH, "Ring"},
    {{0x18, 0x7F, 0x88}, DT_RING, CF_HIGH, "Ring"},
    {{0x34, 0x3E, 0xA4}, DT_RING, CF_HIGH, "Ring"},
    {{0x54, 0xE0, 0x19}, DT_RING, CF_HIGH, "Ring"},
    {{0x5C, 0x47, 0x5E}, DT_RING, CF_HIGH, "Ring"},
    {{0x64, 0x9A, 0x63}, DT_RING, CF_HIGH, "Ring"},
    {{0x90, 0x48, 0x6C}, DT_RING, CF_HIGH, "Ring"},
    {{0x9C, 0x76, 0x13}, DT_RING, CF_HIGH, "Ring"},
    {{0xCC, 0x3B, 0xFB}, DT_RING, CF_HIGH, "Ring"},
    {{0xC4, 0xDB, 0xAD}, DT_RING, CF_HIGH, "Ring"},
    {{0x24, 0x2B, 0xD6}, DT_RING, CF_HIGH, "Ring"},
    {{0x00, 0xB4, 0x63}, DT_RING, CF_HIGH, "Ring"},
    {{0x50, 0xE4, 0x67}, DT_RING, CF_HIGH, "Ring"},
    {{0xFC, 0x65, 0xDE}, DT_RING, CF_MED, "Ring"},
    {{0x68, 0x37, 0xE9}, DT_RING, CF_MED, "Ring"},
};

struct SsidRow {
  const char* pfx;
  bool anywhere;
  DetType t;
  Conf c;
  const char* label;
};
static const SsidRow SSIDS[] = {
    {"AB2-", false, DT_BODYCAM, CF_HIGH, "Axon Body 2"},
    {"AB3-", false, DT_BODYCAM, CF_HIGH, "Axon Body 3"},
    {"AB4-", false, DT_BODYCAM, CF_HIGH, "Axon Body 4"},
    {"AXON-", false, DT_BODYCAM, CF_HIGH, "Axon"},
    {"Flock Camera", false, DT_FLOCK, CF_HIGH, "Flock camera"},
    {"flock", true, DT_FLOCK, CF_HIGH, "Flock SSID"},
    {"penguin", true, DT_FLOCK, CF_HIGH, "Penguin"},
    {"fs ext battery", true, DT_FLOCK, CF_HIGH, "FS Ext Battery"},
    {"pigvision", true, DT_FLOCK, CF_HIGH, "Pigvision"},
    {"Pineapple_", false, DT_HACKER, CF_HIGH, "WiFi Pineapple"},
    {"pwned", false, DT_HACKER, CF_MED, "ESP deauther"},
};

struct U16Row {
  uint16_t u;
  DetType t;
  Conf c;
  const char* label;
};
static const U16Row UUIDS[] = {
    {0x1101, DT_SKIMMER, CF_LOW, "SPP serial"},
    {0xFEED, DT_TILE, CF_LOW, "Tile"},
    {0xFEEC, DT_TILE, CF_LOW, "Tile"},
    {0xFD84, DT_TILE, CF_LOW, "Tile"},
    {0xFC81, DT_BODYCAM, CF_HIGH, "Axon"},
    {0xFE6B, DT_BODYCAM, CF_HIGH, "Axon"},
    {0xFE6C, DT_BODYCAM, CF_HIGH, "Axon"},
    {0xFD5F, DT_GLASSES, CF_HIGH, "Ray-Ban Meta"},
    {0xFEB7, DT_GLASSES, CF_MED, "Meta"},
    {0xFEB8, DT_GLASSES, CF_MED, "Meta"},
    {0xFE45, DT_GLASSES, CF_MED, "Snap"},
    {0xFD5A, DT_SMARTTAG, CF_LOW, "SmartTag"},
    {0xFCB2, DT_GTAG, CF_LOW, "Find Hub tag"},
    {0xFEAA, DT_GTAG, CF_LOW, "Find Hub tag"},
    {0xFE33, DT_GTAG, CF_LOW, "Chipolo"},
    {0xFE65, DT_GTAG, CF_LOW, "Chipolo"},
    {0xFFFA, DT_DRONE, CF_HIGH, "Remote ID"},
    {0x3081, DT_HACKER, CF_HIGH, "Flipper Zero"},
    {0x3082, DT_HACKER, CF_HIGH, "Flipper Zero"},
    {0x3083, DT_HACKER, CF_HIGH, "Flipper Zero"},
};

const char* det_name(uint8_t t) {
  static const char* N[] = {"-",      "Flock",    "Raven",    "Bodycam",  "ALPR",   "Glasses", "Skimmer", "Drone",
                            "FindMy", "Tile",     "SmartTag", "GoogleTag", "Hacker", "Camera",  "Ring"};
  return t < DT_COUNT ? N[t] : "?";
}

uint32_t det_color(uint8_t t) {
  switch (t) {
    case DT_FLOCK:
    case DT_RAVEN:
    case DT_BODYCAM:
    case DT_ALPR: return col::bad;
    case DT_GLASSES: return col::purple;
    case DT_SKIMMER:
    case DT_HACKER: return col::accent;
    case DT_DRONE: return col::info;
    case DT_FINDMY:
    case DT_TILE:
    case DT_SMARTTAG:
    case DT_GTAG: return col::warn;
    default: return col::dim;
  }
}

uint16_t det_default_mask() {
  uint16_t m = 0;
  for (int t = 1; t < DT_COUNT; t++) m |= 1 << t;
  return m & ~((1 << DT_CAMERA) | (1 << DT_RING));  // home cams are everywhere: off by default
}

SigHit sig_oui(const uint8_t* mac) {
  SigHit h;
  for (auto& r : OUIS)
    if (mac[0] == r.b[0] && mac[1] == r.b[1] && mac[2] == r.b[2]) {
      h.type = r.t;
      h.conf = r.c;
      h.label = r.label;
      break;
    }
  return h;
}

bool sig_is_flock_oui(const uint8_t* mac) { return sig_oui(mac).type == DT_FLOCK; }

bool sig_is_pwnagotchi(const uint8_t* m) {
  return m[0] == 0xDE && m[1] == 0xAD && m[2] == 0xBE && m[3] == 0xEF && m[4] == 0xDE && m[5] == 0xAD;
}

SigHit sig_ssid(const char* s) {
  SigHit h;
  if (!s || !*s) return h;
  for (auto& r : SSIDS) {
    bool m = r.anywhere ? ci_contains(s, r.pfx) : strncasecmp(s, r.pfx, strlen(r.pfx)) == 0;
    if (m) {
      h.type = r.t;
      h.conf = r.c;
      h.label = r.label;
      return h;
    }
  }
  return h;
}

SigHit sig_uuid16(uint16_t u) {
  SigHit h;
  for (auto& r : UUIDS)
    if (r.u == u) {
      h.type = r.t;
      h.conf = r.c;
      h.label = r.label;
      return h;
    }
  if (u >= 0x3100 && u <= 0x3500) {
    h.type = DT_RAVEN;
    h.conf = CF_MED;
    h.label = "Raven";
  }
  return h;
}

SigHit sig_mfg(uint16_t id, const uint8_t* d, size_t len) {
  SigHit h;
  switch (id) {
    case 0x004C:  // Apple: only the Find My "separated" payload counts
      if (len >= 3 && d[2] == 0x12) h = {DT_FINDMY, len >= 27 ? CF_MED : CF_LOW, "FindMy tag"};
      break;
    case 0x09C8: h = {DT_FLOCK, CF_MED, "XUNTONG radio"}; break;
    case 0x01AB: h = {DT_GLASSES, CF_LOW, "Meta device"}; break;
    case 0x0D53: h = {DT_GLASSES, CF_MED, "Luxottica"}; break;
    case 0x03C2: h = {DT_GLASSES, CF_MED, "Snap"}; break;
    case 0x060C: h = {DT_GLASSES, CF_MED, "Vuzix"}; break;
    case 0x034D: h = {DT_BODYCAM, CF_HIGH, "Axon"}; break;
    case 0x08C3: h = {DT_GTAG, CF_LOW, "Chipolo"}; break;
  }
  return h;
}

static bool allDigits(const char* s, int n) {
  for (int i = 0; i < n; i++)
    if (!isdigit((unsigned char)s[i])) return false;
  return s[n] == 0;
}

SigHit sig_ble_name(const char* n) {
  SigHit h;
  if (!n || !*n) return h;
  if (!strncasecmp(n, "penguin-", 8) && allDigits(n + 8, 10)) return {DT_FLOCK, CF_HIGH, "Penguin battery"};
  if (ci_contains(n, "fs ext battery")) return {DT_FLOCK, CF_HIGH, "FS Ext Battery"};
  if (!strncasecmp(n, "Flock", 5)) return {DT_FLOCK, CF_MED, "Flock BLE"};
  if (allDigits(n, 10)) return {DT_FLOCK, CF_LOW, "10-digit serial"};
  if (!strncasecmp(n, "Flipper", 7)) return {DT_HACKER, CF_HIGH, "Flipper Zero"};
  if (!strcmp(n, "HC-05") || !strcmp(n, "HC-06") || !strcmp(n, "HC-03") || !strcmp(n, "RN42") ||
      !strcmp(n, "BT04-A"))
    return {DT_SKIMMER, CF_MED, "Skimmer module"};
  return h;
}

// ---------------- Remote ID (ASTM F3411 / OpenDroneID) ----------------
static int32_t le32(const uint8_t* p) { return (int32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24)); }
static uint16_t le16(const uint8_t* p) { return p[0] | (p[1] << 8); }

static void copyId(char* out, const uint8_t* p) {
  int n = 0;
  for (int i = 0; i < 20 && p[i]; i++)
    if (p[i] >= 0x20 && p[i] < 0x7F) out[n++] = p[i];
  out[n] = 0;
}

static bool decodeOne(const uint8_t* m, RidInfo& r) {
  uint8_t type = m[0] >> 4;
  switch (type) {
    case 0x0:  // Basic ID
      if (!r.uasId[0]) copyId(r.uasId, m + 2);
      return true;
    case 0x1: {  // Location / vector
      int32_t la = le32(m + 5), lo = le32(m + 9);
      if (la == 0 && lo == 0) return true;
      r.lat = la * 1e-7f;
      r.lon = lo * 1e-7f;
      uint16_t ag = le16(m + 15);
      r.altM = ag ? ag * 0.5f - 1000.0f : 0;
      uint8_t sh = m[3];
      r.speedMs = (m[1] & 0x01) ? sh * 0.75f + 63.75f : sh * 0.25f;
      r.hasLoc = true;
      return true;
    }
    case 0x4: {  // System: operator location
      int32_t la = le32(m + 2), lo = le32(m + 6);
      if (la || lo) {
        r.opLat = la * 1e-7f;
        r.opLon = lo * 1e-7f;
        r.hasOp = true;
      }
      return true;
    }
    case 0x5:  // Operator ID
      copyId(r.opId, m + 2);
      return true;
    case 0x2:  // auth
    case 0x3:  // self-id
      return true;
  }
  return false;
}

bool rid_decode(const uint8_t* p, int len, RidInfo& r) {
  if (len < 25) return false;
  if ((p[0] >> 4) == 0xF) {  // message pack
    if (len < 3) return false;
    int sz = p[1], cnt = p[2];
    if (sz != 25 || cnt < 1 || cnt > 9) return false;
    bool any = false;
    for (int i = 0; i < cnt && 3 + (i + 1) * 25 <= len; i++) any |= decodeOne(p + 3 + i * 25, r);
    return any;
  }
  return decodeOne(p, r);
}
