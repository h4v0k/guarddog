#pragma once
#include <Arduino.h>

// Detection types (order = bit index in Settings::typeMask)
enum DetType : uint8_t {
  DT_NONE = 0,
  DT_FLOCK,
  DT_RAVEN,
  DT_BODYCAM,
  DT_ALPR,
  DT_GLASSES,
  DT_SKIMMER,
  DT_DRONE,
  DT_FINDMY,
  DT_TILE,
  DT_SMARTTAG,
  DT_GTAG,
  DT_HACKER,
  DT_CAMERA,
  DT_RING,
  DT_COUNT
};
enum Conf : uint8_t { CF_NONE = 0, CF_LOW = 1, CF_MED = 2, CF_HIGH = 3 };

struct SigHit {
  DetType type;
  Conf conf;
  const char* label;
  SigHit() : type(DT_NONE), conf(CF_NONE), label("") {}
  SigHit(DetType t, Conf c, const char* l) : type(t), conf(c), label(l) {}
};

const char* det_name(uint8_t t);
uint32_t det_color(uint8_t t);
uint16_t det_default_mask();

// Wi-Fi
SigHit sig_oui(const uint8_t* mac);
SigHit sig_ssid(const char* ssid);
bool sig_is_pwnagotchi(const uint8_t* mac);
bool sig_is_flock_oui(const uint8_t* mac);

// BLE
SigHit sig_uuid16(uint16_t u);
SigHit sig_mfg(uint16_t companyId, const uint8_t* data, size_t len);
SigHit sig_ble_name(const char* name);

// OpenDroneID / ASTM F3411 Remote ID
struct RidInfo {
  char uasId[21];
  char opId[21];
  bool hasLoc, hasOp;
  float lat, lon, altM, speedMs;
  float opLat, opLon;
};
// msgs: one 25-byte message or a message pack (type 0xF). Merges into r.
bool rid_decode(const uint8_t* msgs, int len, RidInfo& r);

inline SigHit better(const SigHit& a, const SigHit& b) { return b.conf > a.conf ? b : a; }
