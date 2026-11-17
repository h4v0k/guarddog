// Flock Detector: Flock Safety ALPR / Penguin / Raven signatures over Wi-Fi + BLE.
// Signature set credit: colonelpanichacks/flock-you (MIT) and the DeFlock community.
#include "common.h"
#include <algorithm>

namespace {

// Transmitter-side OUIs seen on Flock hardware (flock-you, 2026 revision).
// Several are generic Espressif/Qualcomm radio OUIs, so an OUI hit alone is "weak";
// it only becomes strong with a wildcard probe request (camera LOWI scanning) or SSID.
const uint8_t OUIS[][3] = {
    {0x70, 0xC9, 0x4E}, {0x3C, 0x91, 0x80}, {0xD8, 0xF3, 0xBC}, {0x80, 0x30, 0x49}, {0xB8, 0x35, 0x32},
    {0x14, 0x5A, 0xFC}, {0x74, 0x4C, 0xA1}, {0x08, 0x3A, 0x88}, {0x9C, 0x2F, 0x9D}, {0xC0, 0x35, 0x32},
    {0x94, 0x08, 0x53}, {0xE4, 0xAA, 0xEA}, {0xF4, 0x6A, 0xDD}, {0xE0, 0x0A, 0xF6}, {0x24, 0xB2, 0xB9},
    {0x00, 0xF4, 0x8D}, {0xD0, 0x39, 0x57}, {0xE8, 0xD0, 0xFC}, {0xE0, 0x4F, 0x43}, {0xB8, 0x1E, 0xA4},
    {0x70, 0x08, 0x94}, {0x58, 0x8E, 0x81}, {0xEC, 0x1B, 0xBD}, {0x3C, 0x71, 0xBF}, {0x58, 0x00, 0xE3},
    {0x90, 0x35, 0xEA}, {0x5C, 0x93, 0xA2}, {0x64, 0x6E, 0x69}, {0x48, 0x27, 0xEA}, {0xA4, 0xCF, 0x12},
    {0x14, 0xB5, 0xCD}, {0x82, 0x6B, 0xF2}, {0xB4, 0x1E, 0x52}, {0x00, 0x03, 0x7F},
};
const uint8_t FLOCK_OWN[3] = {0xB4, 0x1E, 0x52};  // Flock Safety IEEE MA-L
const char* KEYWORDS[] = {"flock", "penguin", "fs ext battery", "pigvision"};

bool ouiMatch(const uint8_t* m) {
  for (auto& o : OUIS)
    if (m[0] == o[0] && m[1] == o[1] && m[2] == o[2]) return true;
  return false;
}
bool kwMatch(const char* s) {
  for (auto k : KEYWORDS)
    if (ci_contains(s, k)) return true;
  return false;
}

bool want(const FrameInfo& f) {
  if (ouiMatch(f.a2)) return true;
  return f.type == 0 && f.ssidLen > 0 && kwMatch(f.ssid);
}

struct Hit {
  char id[18];
  char why[18];
  char ssid[33];
  uint8_t score;
  int8_t rssi;
  bool ble;
  uint32_t first, last;
  uint16_t count;
};
const int MAX_HIT = 24;
Hit hits[MAX_HIT];
int hitN = 0;

void addHit(const char* id, uint8_t score, const char* why, int8_t rssi, const char* ssid, bool ble) {
  uint32_t now = millis();
  for (int i = 0; i < hitN; i++) {
    Hit& h = hits[i];
    if (strcmp(h.id, id)) continue;
    h.last = now;
    h.rssi = rssi;
    h.count++;
    if (score > h.score) {
      h.score = score;
      strlcpy(h.why, why, sizeof h.why);
    }
    if (ssid && ssid[0]) strlcpy(h.ssid, ssid, sizeof h.ssid);
    return;
  }
  int slot = hitN < MAX_HIT ? hitN++ : 0;
  if (hitN == MAX_HIT)
    for (int i = 1; i < MAX_HIT; i++)
      if (hits[i].score < hits[slot].score || (hits[i].score == hits[slot].score && hits[i].last < hits[slot].last))
        slot = i;
  Hit& h = hits[slot];
  memset(&h, 0, sizeof h);
  strlcpy(h.id, id, sizeof h.id);
  strlcpy(h.why, why, sizeof h.why);
  if (ssid) strlcpy(h.ssid, ssid, sizeof h.ssid);
  h.score = score;
  h.rssi = rssi;
  h.ble = ble;
  h.first = h.last = now;
  h.count = 1;
  char line[120];
  snprintf(line, sizeof line, "%lu,%s,%s,%s,%d,%d,%s", (unsigned long)(now / 1000), ble ? "ble" : "wifi", id, why,
           score, rssi, ssid ? ssid : "");
  sd_append("/guarddog/flock.csv", line);
  if (score >= 60) {
    leds_flash(0xFF0010, 800);
    beep(2400, 90);
  }
}

}  // namespace

void app_flock() {
  static BleDev snap[40];
  hitN = 0;
  ui_header("Flock Detector", col::warn);
  ui_footer("", "Clear", "");
  sniff_start(1, want);
  sniff_hop(true, 220);
  ble_start();
  leds_base(0x101000);
  uint32_t lastDraw = 0, lastBle = 0, nextTick = 0;
  FrameInfo f;
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_OK) hitN = 0, lastDraw = 0;

    int budget = 40;
    while (budget-- > 0 && sniff_pop(f)) {
      char mac[18];
      fmt_mac(f.a2, mac);
      bool oui = ouiMatch(f.a2);
      bool own = !memcmp(f.a2, FLOCK_OWN, 3);
      bool ssidHit = f.type == 0 && f.ssidLen > 0 && kwMatch(f.ssid);
      if (ssidHit) addHit(mac, 85, "SSID match", f.rssi, f.ssid, false);
      else if (own) addHit(mac, 90, "Flock OUI", f.rssi, nullptr, false);
      else if (oui && f.type == 0 && f.sub == 4 && f.ssidLen == 0) addHit(mac, 65, "OUI+wild probe", f.rssi, nullptr, false);
      else if (oui) addHit(mac, 35, "OUI only", f.rssi, nullptr, false);
    }
    if (millis() - lastBle > 700) {
      lastBle = millis();
      int n = ble_snapshot(snap, 40, 20000);
      for (int i = 0; i < n; i++)
        if (snap[i].flock >= 35) addHit(snap[i].addr, snap[i].flock, snap[i].why, snap[i].rssi, snap[i].name, true);
    }

    // strongest live high-confidence hit drives the geiger beeper
    int best = -127;
    bool live = false;
    for (int i = 0; i < hitN; i++)
      if (hits[i].score >= 60 && millis() - hits[i].last < 20000) {
        live = true;
        best = max<int>(best, hits[i].rssi);
      }
    if (live && millis() > nextTick) {
      int iv = map(constrain(best, -95, -40), -95, -40, 1500, 150);
      nextTick = millis() + iv;
      beep(2000, 15);
      leds_flash(0xFF0010, 60);
    }

    if (millis() - lastDraw < 400) {
      delay(5);
      continue;
    }
    lastDraw = millis();
    leds_base(live ? 0x200000 : 0x101000);
    std::sort(hits, hits + hitN, [](const Hit& a, const Hit& b) {
      bool la = millis() - a.last < 20000, lb = millis() - b.last < 20000;
      if (la != lb) return la;
      if (a.score != b.score) return a.score > b.score;
      return a.rssi > b.rssi;
    });

    body.fillScreen(col::bg);
    body.fillRoundRect(6, 4, SCR_W - 12, 46, 8, live ? col::bad : col::panel);
    body.setFont(&fonts::FreeSansBold12pt7b);
    body.setTextDatum(middle_left);
    body.setTextColor(live ? col::text : col::good);
    body.drawString(live ? "FLOCK NEARBY" : "NONE DETECTED", 16, 27);
    if (live) {
      char r[12];
      snprintf(r, sizeof r, "%d", best);
      body.setTextDatum(middle_right);
      body.drawString(r, SCR_W - 16, 27);
    }
    int y = 56;
    if (live) {
      draw_meter(8, y + 2, SCR_W - 16, 12, best);
      y += 20;
    } else {
      ui_smallfont();
      body.setTextDatum(top_left);
      body.setTextColor(col::dim);
      char b[48];
      snprintf(b, sizeof b, "Wi-Fi ch %d + BLE   weak hits: %d", sniff_cur_channel(), hitN);
      body.drawString(b, 8, y);
      y += 22;
    }
    body.drawFastHLine(6, y, SCR_W - 12, col::line);
    y += 4;
    ui_smallfont();
    for (int i = 0; i < hitN && y < BODY_H - 20; i++) {
      Hit& h = hits[i];
      bool fresh = millis() - h.last < 20000;
      uint32_t c = h.score >= 60 ? col::bad : col::warn;
      if (!fresh) c = col::dim;
      body.fillCircle(12, y + 9, 4, c);
      body.setTextDatum(top_left);
      body.setTextColor(fresh ? col::text : col::dim);
      char b[48];
      snprintf(b, sizeof b, "%s %s", h.ble ? "BLE" : "WiFi", h.why);
      draw_fit(b, 22, y, 150);
      body.setTextColor(col::dim);
      draw_fit(h.ssid[0] ? h.ssid : h.id + 9, 176, y, 90);
      char r[8];
      snprintf(r, sizeof r, "%d", h.rssi);
      body.setTextDatum(top_right);
      body.setTextColor(fresh ? rssi_color(h.rssi) : col::dim);
      body.drawString(r, SCR_W - 8, y);
      y += 21;
    }
    ui_push();
  }
  ble_stop();
  sniff_stop();
  leds_off();
}
