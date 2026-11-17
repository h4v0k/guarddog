#pragma once
#include <Arduino.h>
#include <M5Unified.h>
#include <WiFi.h>
#include <SD.h>
#include <functional>
#include "esp_wifi.h"

#define SW_VERSION "1.0.0"

// ---------- theme (RGB888) ----------
namespace col {
static constexpr uint32_t bg     = 0x0A0C0Fu;
static constexpr uint32_t panel  = 0x181C23u;
static constexpr uint32_t line   = 0x2A313Bu;
static constexpr uint32_t text   = 0xE8ECF1u;
static constexpr uint32_t dim    = 0x8A94A3u;
static constexpr uint32_t accent = 0xFF7A1Au;  // squatch orange
static constexpr uint32_t good   = 0x34D399u;
static constexpr uint32_t warn   = 0xFBBF24u;
static constexpr uint32_t bad    = 0xF43F5Eu;
static constexpr uint32_t info   = 0x38BDF8u;
static constexpr uint32_t purple = 0xA78BFAu;
}  // namespace col

// ---------- layout ----------
constexpr int SCR_W = 320, SCR_H = 240;
constexpr int HDR_H = 26, FTR_H = 22;
constexpr int BODY_Y = HDR_H, BODY_H = SCR_H - HDR_H - FTR_H;  // 192

extern M5Canvas body;  // off-screen body, pushed to (0, BODY_Y)

struct Settings {
  uint8_t bright = 140;
  bool sound = true;
  bool leds = true;
  bool big = true;  // large text in lists
};
extern Settings gSet;
extern bool gSdOk;
void settings_load();
void settings_save();

// ---------- input / ui ----------
enum Key : uint8_t { K_NONE, K_UP, K_DOWN, K_OK, K_BACK };
Key ui_tick();  // call every loop: buttons, LEDs, battery
void ui_header(const char* title, uint32_t tint = col::accent);
void ui_header_note(const char* note, uint32_t color = col::dim);
void ui_footer(const char* a, const char* b, const char* c);  // "^" / "v" draw arrows
void ui_push();
int ui_rowh();
void ui_rowfont();
void ui_smallfont();
void ui_list(int count, int sel, int& top, const std::function<void(int, int, int, bool)>& row,
             const char* empty = "Scanning...");
void ui_splash();
void ui_toast(const char* msg, uint32_t color);
void draw_fit(const char* s, int x, int y, int maxw);  // body, truncates with ".."
void draw_foot(lgfx::LovyanGFX& d, int cx, int cy, int s, uint32_t c);
void fmt_mac(const uint8_t* m, char* out);  // out >= 18
void fmt_age(uint32_t ms, char* out);       // out >= 12
uint32_t rssi_color(int rssi);
void draw_meter(int x, int y, int w, int h, int rssi);
bool ci_contains(const char* hay, const char* needle);

// ---------- leds / sound / sd ----------
void leds_begin();
void leds_base(uint32_t rgb);
void leds_flash(uint32_t rgb, uint16_t ms);
void leds_off();
void leds_tick();
void beep(uint16_t freq, uint16_t ms);
void sd_begin();
bool sd_append(const char* path, const char* line);

// ---------- wifi sniffer engine ----------
struct FrameInfo {
  uint8_t type, sub;  // 802.11 type/subtype
  uint8_t a1[6], a2[6], a3[6];
  char ssid[33];
  int8_t ssidLen;  // -1 = no SSID IE, 0 = wildcard/hidden
  int8_t rssi;
  uint8_t ch;      // channel we heard it on
  uint8_t apCh;    // DS param channel (beacons/probe resp), 0 if none
  bool priv;       // privacy bit (beacons/probe resp)
};
typedef bool (*FrameFilter)(const FrameInfo& f);

struct SniffStats {
  volatile uint32_t pkts, mgmt, data, beacons, probes, deauth, disassoc, eapol;
};
extern SniffStats gStats;

void sniff_start(uint8_t ch, FrameFilter filter);
void sniff_stop();
void sniff_channel(uint8_t ch);
void sniff_hop(bool on, uint16_t dwellMs = 250);
uint8_t sniff_cur_channel();
bool sniff_pop(FrameInfo& f);
void sniff_tick();  // hopping + pcap drain
void sniff_reset_stats();

bool pcap_start();
void pcap_stop();
bool pcap_active();
const char* pcap_name();
uint32_t pcap_bytes();
uint32_t pcap_drops();

// ---------- ble ----------
enum BleKind : uint8_t { BK_NONE, BK_FINDMY, BK_TILE, BK_SMARTTAG, BK_FLOCK };
struct BleDev {
  char addr[18];
  char name[24];
  int8_t rssi;
  uint32_t first, last;
  uint16_t mfg;
  bool hasMfg;
  uint8_t kind;
  uint8_t flock;  // flock-signature score 0..100
  char why[18];
  uint16_t seen;
};
void ble_start();
void ble_stop();
int ble_snapshot(BleDev* out, int max, uint32_t staleMs = 45000);
const char* ble_vendor(uint16_t id);

// ---------- apps ----------
void app_survey();
void app_channels();
void app_ble();
void app_monitor();
void app_guard();
void app_flock();
void app_settings();
