// Wi-Fi Survey + Channel Map (active scan via the ESP32 scanner)
#include "common.h"
#include <vector>
#include <algorithm>

struct ApInfo {
  char ssid[33];
  uint8_t bssid[6];
  uint8_t ch, second;
  int8_t rssi;
  uint8_t auth, pc, gc;
  bool wps, b, g, n, lr;
  char cc[3];
};

// Arduino keeps the raw wifi_ap_record_t list; expose it to read WPS/cipher/PHY.
struct ScanPeek : public WiFiScanClass {
  static wifi_ap_record_t* rec(int i) { return (wifi_ap_record_t*)_getScanInfoByIndex(i); }
};

static void scan_begin() {
  esp_wifi_set_promiscuous(false);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  WiFi.scanDelete();
  WiFi.scanNetworks(true, true, false, 160);
}

// returns true when a fresh result set landed in `out`
static bool scan_poll(std::vector<ApInfo>& out) {
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_RUNNING) return false;
  if (n < 0) {
    scan_begin();
    return false;
  }
  out.clear();
  for (int i = 0; i < n; i++) {
    wifi_ap_record_t* r = ScanPeek::rec(i);
    if (!r) continue;
    ApInfo a;
    memset(&a, 0, sizeof(a));
    memcpy(a.ssid, r->ssid, 32);
    a.ssid[32] = 0;
    memcpy(a.bssid, r->bssid, 6);
    a.ch = r->primary;
    a.second = (uint8_t)r->second;
    a.rssi = r->rssi;
    a.auth = (uint8_t)r->authmode;
    a.pc = (uint8_t)r->pairwise_cipher;
    a.gc = (uint8_t)r->group_cipher;
    a.wps = r->wps;
    a.b = r->phy_11b;
    a.g = r->phy_11g;
    a.n = r->phy_11n;
    a.lr = r->phy_lr;
    a.cc[0] = r->country.cc[0];
    a.cc[1] = r->country.cc[1];
    a.cc[2] = 0;
    out.push_back(a);
  }
  WiFi.scanDelete();
  std::sort(out.begin(), out.end(), [](const ApInfo& x, const ApInfo& y) { return x.rssi > y.rssi; });
  return true;
}

static const char* authName(uint8_t a) {
  switch (a) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "OTHER";
  }
}

static const char* cipherName(uint8_t c) {
  switch (c) {
    case WIFI_CIPHER_TYPE_NONE: return "none";
    case WIFI_CIPHER_TYPE_WEP40: return "WEP40";
    case WIFI_CIPHER_TYPE_WEP104: return "WEP104";
    case WIFI_CIPHER_TYPE_TKIP: return "TKIP";
    case WIFI_CIPHER_TYPE_CCMP: return "CCMP";
    case WIFI_CIPHER_TYPE_TKIP_CCMP: return "TKIP+CCMP";
    default: return "other";
  }
}

static uint32_t authColor(const ApInfo& a) {
  if (a.auth == WIFI_AUTH_OPEN || a.auth == WIFI_AUTH_WEP) return col::bad;
  if (a.wps || a.auth == WIFI_AUTH_WPA_PSK || a.pc == WIFI_CIPHER_TYPE_TKIP) return col::warn;
  return col::good;
}

static void drawDetail(const ApInfo& a) {
  body.fillScreen(col::bg);
  char mac[18], v[48];
  fmt_mac(a.bssid, mac);
  ui_smallfont();
  int y = 4;
  const int lh = 21;
  auto kv = [&](const char* k, const char* val, uint32_t c) {
    body.setTextDatum(top_left);
    body.setTextColor(col::dim);
    body.drawString(k, 10, y);
    body.setTextColor(c);
    draw_fit(val, 104, y, SCR_W - 114);
    y += lh;
  };
  kv("SSID", a.ssid[0] ? a.ssid : "<hidden>", a.ssid[0] ? col::text : col::dim);
  snprintf(v, sizeof v, "%s%s", mac, (a.bssid[0] & 0x02) ? "  (random)" : "");
  kv("BSSID", v, col::text);
  snprintf(v, sizeof v, "%d%s", a.ch, a.second == 1 ? " +above" : (a.second == 2 ? " +below" : ""));
  kv("Channel", v, col::text);
  snprintf(v, sizeof v, "%d dBm", a.rssi);
  kv("Signal", v, rssi_color(a.rssi));
  draw_meter(200, y - lh + 5, 100, 10, a.rssi);
  kv("Security", authName(a.auth), authColor(a));
  snprintf(v, sizeof v, "%s / %s", cipherName(a.pc), cipherName(a.gc));
  kv("Cipher", v, a.pc == WIFI_CIPHER_TYPE_TKIP ? col::warn : col::text);
  snprintf(v, sizeof v, "%s%s%s%s", a.b ? "b " : "", a.g ? "g " : "", a.n ? "n " : "", a.lr ? "LR" : "");
  kv("PHY", v, col::text);
  kv("WPS", a.wps ? "ENABLED" : "off", a.wps ? col::warn : col::dim);
  kv("Country", a.cc[0] >= 'A' ? a.cc : "-", col::text);
}

void app_survey() {
  std::vector<ApInfo> aps;
  int sel = 0, top = 0;
  bool detail = false, dirty = true, scanning = true;
  uint8_t selB[6] = {0};
  uint32_t doneAt = 0;
  ui_header("Wi-Fi Survey", col::info);
  ui_footer("^", "Details", "v");
  scan_begin();
  ui_header_note("scanning", col::accent);
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) {
      if (detail) {
        detail = false;
        dirty = true;
        ui_footer("^", "Details", "v");
      } else break;
    }
    if (!detail) {
      if (k == K_UP && sel > 0) sel--, dirty = true;
      if (k == K_DOWN && sel + 1 < (int)aps.size()) sel++, dirty = true;
      if (k == K_OK && !aps.empty()) {
        detail = true;
        dirty = true;
        ui_footer("", "Back", "");
      }
    } else if (k == K_OK) {
      detail = false;
      dirty = true;
      ui_footer("^", "Details", "v");
    }

    if (scanning) {
      if (scan_poll(aps)) {
        scanning = false;
        doneAt = millis();
        sel = 0;
        for (size_t i = 0; i < aps.size(); i++)
          if (!memcmp(aps[i].bssid, selB, 6)) sel = i;
        char n[16];
        snprintf(n, sizeof n, "%u APs", (unsigned)aps.size());
        ui_header_note(n, col::text);
        dirty = true;
      }
    } else if (millis() - doneAt > 5000 && !detail) {
      scanning = true;
      scan_begin();
      ui_header_note("scanning", col::accent);
    }
    if (!aps.empty()) memcpy(selB, aps[sel].bssid, 6);

    if (!dirty) {
      delay(10);
      continue;
    }
    dirty = false;
    if (detail && !aps.empty()) {
      drawDetail(aps[sel]);
    } else {
      ui_list(aps.size(), sel, top, [&](int i, int y, int h, bool s) {
        const ApInfo& a = aps[i];
        int cy = y + h / 2;
        body.fillRoundRect(10, y + 6, 5, h - 12, 2, authColor(a));
        ui_smallfont();
        char r[12];
        snprintf(r, sizeof r, "%d", a.rssi);
        body.setTextDatum(middle_right);
        body.setTextColor(rssi_color(a.rssi));
        body.drawString(r, SCR_W - 12, cy);
        snprintf(r, sizeof r, "ch%d", a.ch);
        body.setTextColor(col::dim);
        body.drawString(r, SCR_W - 52, cy);
        ui_rowfont();
        body.setTextDatum(middle_left);
        body.setTextColor(a.ssid[0] ? col::text : col::dim);
        draw_fit(a.ssid[0] ? a.ssid : "<hidden>", 22, cy, SCR_W - 22 - 100);
      });
    }
    ui_push();
  }
  WiFi.scanDelete();
}

// ---------------- Channel Map ----------------
void app_channels() {
  std::vector<ApInfo> aps;
  ui_header("Channel Map", col::info);
  ui_footer("", "Rescan", "");
  scan_begin();
  ui_header_note("scanning", col::accent);
  bool scanning = true;
  uint32_t doneAt = 0;
  {
    int t = 0;
    ui_list(0, 0, t, [](int, int, int, bool) {});
    ui_push();
  }
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_OK && !scanning) {
      scanning = true;
      scan_begin();
      ui_header_note("scanning", col::accent);
    }
    if (!scanning && millis() - doneAt > 8000) {
      scanning = true;
      scan_begin();
      ui_header_note("scanning", col::accent);
    }
    if (!scanning || !scan_poll(aps)) {
      delay(10);
      continue;
    }
    scanning = false;
    doneAt = millis();
    char note[16];
    snprintf(note, sizeof note, "%u APs", (unsigned)aps.size());
    ui_header_note(note, col::text);

    int cnt[14] = {0}, best[14];
    for (int i = 0; i < 14; i++) best[i] = -100;
    float load[14] = {0};
    for (auto& a : aps) {
      if (a.ch < 1 || a.ch > 13) continue;
      cnt[a.ch]++;
      best[a.ch] = max(best[a.ch], (int)a.rssi);
      for (int c = 1; c <= 13; c++) {
        int d = abs(c - a.ch);
        if (d <= 4) load[c] += (a.rssi + 100) * (5 - d) / 5.0f;
      }
    }
    int rec = 1;
    for (int c : {6, 11})
      if (load[c] < load[rec]) rec = c;
    int mx = 4;
    for (int c = 1; c <= 13; c++) mx = max(mx, cnt[c]);

    body.fillScreen(col::bg);
    ui_smallfont();
    body.setTextDatum(top_left);
    body.setTextColor(col::dim);
    body.drawString("Best of 1/6/11:", 10, 4);
    body.setFont(&fonts::FreeSansBold12pt7b);
    body.setTextColor(col::good);
    char b[12];
    snprintf(b, sizeof b, "ch %d", rec);
    body.drawString(b, 140, 1);

    const int gx = 12, gy = 34, gh = 120, bw = 18, step = 23;
    for (int c = 1; c <= 13; c++) {
      int x = gx + (c - 1) * step;
      int h = cnt[c] * gh / mx;
      body.fillRect(x, gy, bw, gh, col::panel);
      if (h) body.fillRect(x, gy + gh - h, bw, h, rssi_color(best[c]));
      if (c == rec) body.drawRect(x - 2, gy - 2, bw + 4, gh + 4, col::good);
      body.setFont(&fonts::Font2);
      body.setTextDatum(top_center);
      body.setTextColor(cnt[c] ? col::text : col::dim);
      snprintf(b, sizeof b, "%d", cnt[c]);
      if (cnt[c]) body.drawString(b, x + bw / 2, gy + gh - h - 16 < gy ? gy + 2 : gy + gh - h - 16);
      body.setTextColor(c == 1 || c == 6 || c == 11 ? col::text : col::dim);
      snprintf(b, sizeof b, "%d", c);
      body.drawString(b, x + bw / 2, gy + gh + 4);
    }
    ui_smallfont();
    body.setTextDatum(bottom_left);
    body.setTextColor(col::dim);
    body.drawString("bar = AP count, color = strongest", 10, BODY_H - 2);
    ui_push();
  }
  WiFi.scanDelete();
}
