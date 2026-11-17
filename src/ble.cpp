// BLE scanner engine + BLE Scanner app (trackers + Flock/Raven signatures)
#include "common.h"
#include <NimBLEDevice.h>
#include <algorithm>

#define MAX_BLE 80
static BleDev devs[MAX_BLE];
static int devN = 0;
static SemaphoreHandle_t mtx = nullptr;
static bool bleInit = false;

// Flock Safety / Raven BLE signatures (credit: colonelpanichacks/flock-you, MIT)
static NimBLEUUID uFlockGatt("e8ccbb38-9532-46a8-9fe5-1814df172e6f");

static bool allDigits(const char* s, int n) {
  for (int i = 0; i < n; i++)
    if (!isdigit((unsigned char)s[i])) return false;
  return s[n] == 0;
}

static uint8_t flockScore(NimBLEAdvertisedDevice* d, const char* name, bool hasMfg, uint16_t mfg, char* why) {
  uint8_t score = 0;
  auto hit = [&](uint8_t s, const char* w) {
    if (s > score) {
      score = s;
      strlcpy(why, w, 18);
    }
  };
  if (name[0]) {
    if (!strncasecmp(name, "penguin-", 8) && allDigits(name + 8, 10)) hit(85, "Penguin batt");
    else if (ci_contains(name, "fs ext battery")) hit(85, "FS Ext Battery");
    else if (ci_contains(name, "flock")) hit(70, "name: flock");
    else if (ci_contains(name, "pigvision")) hit(70, "name: pigvision");
    else if (allDigits(name, 10)) hit(50, "10-digit serial");
    else if (!strcmp(name, "DfuTarg")) hit(35, "DFU target");
  }
  if (hasMfg && mfg == 0x09C8) hit(70, "mfg 0x09C8");
  int n = d->getServiceUUIDCount();
  for (int i = 0; i < n; i++) {
    NimBLEUUID u = d->getServiceUUID(i);
    if (u == uFlockGatt) hit(90, "Flock GATT");
    else if (u.bitSize() == 16) {
      uint16_t v = u.getNative()->u16.value;
      if (v >= 0x3100 && v <= 0x3500) hit(70, "Raven service");
    }
  }
  return score;
}

class ScanCB : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* d) override {
    BleDev n;
    memset(&n, 0, sizeof(n));
    strlcpy(n.addr, d->getAddress().toString().c_str(), sizeof(n.addr));
    n.rssi = d->getRSSI();
    n.last = millis();
    if (d->haveName()) strlcpy(n.name, d->getName().c_str(), sizeof(n.name));
    if (d->haveManufacturerData()) {
      std::string m = d->getManufacturerData();
      if (m.size() >= 2) {
        n.hasMfg = true;
        n.mfg = (uint8_t)m[0] | ((uint16_t)(uint8_t)m[1] << 8);
        if (n.mfg == 0x004C && m.size() >= 3 && (uint8_t)m[2] == 0x12) n.kind = BK_FINDMY;
      }
    }
    if (d->haveServiceUUID()) {
      if (d->isAdvertisingService(NimBLEUUID((uint16_t)0xFEED)) ||
          d->isAdvertisingService(NimBLEUUID((uint16_t)0xFEEC)))
        n.kind = BK_TILE;
      else if (d->isAdvertisingService(NimBLEUUID((uint16_t)0xFD5A)))
        n.kind = BK_SMARTTAG;
    }
    n.flock = flockScore(d, n.name, n.hasMfg, n.mfg, n.why);
    if (n.flock >= 50 && n.kind == BK_NONE) n.kind = BK_FLOCK;

    if (xSemaphoreTake(mtx, pdMS_TO_TICKS(5)) != pdTRUE) return;
    int idx = -1;
    for (int i = 0; i < devN; i++)
      if (!strcmp(devs[i].addr, n.addr)) {
        idx = i;
        break;
      }
    if (idx < 0) {
      if (devN < MAX_BLE) idx = devN++;
      else {  // evict least recently seen
        idx = 0;
        for (int i = 1; i < devN; i++)
          if (devs[i].last < devs[idx].last) idx = i;
      }
      n.first = n.last;
      n.seen = 1;
      devs[idx] = n;
    } else {
      BleDev& o = devs[idx];
      o.rssi = n.rssi;
      o.last = n.last;
      o.seen++;
      if (n.name[0]) strlcpy(o.name, n.name, sizeof(o.name));
      if (n.hasMfg) o.mfg = n.mfg, o.hasMfg = true;
      if (n.kind != BK_NONE) o.kind = n.kind;
      if (n.flock > o.flock) {
        o.flock = n.flock;
        strlcpy(o.why, n.why, sizeof(o.why));
      }
    }
    xSemaphoreGive(mtx);
  }
};
static ScanCB scanCb;

void ble_start() {
  if (!mtx) mtx = xSemaphoreCreateMutex();
  if (!bleInit) {
    NimBLEDevice::init("");
    bleInit = true;
  }
  xSemaphoreTake(mtx, portMAX_DELAY);
  devN = 0;
  xSemaphoreGive(mtx);
  NimBLEScan* s = NimBLEDevice::getScan();
  s->setAdvertisedDeviceCallbacks(&scanCb, true);
  s->setActiveScan(true);
  s->setInterval(100);
  s->setWindow(60);
  s->setMaxResults(0);
  s->start(0, nullptr, false);
}

void ble_stop() {
  if (!bleInit) return;
  NimBLEDevice::getScan()->stop();
}

int ble_snapshot(BleDev* out, int max, uint32_t staleMs) {
  if (!mtx) return 0;
  int n = 0;
  uint32_t now = millis();
  xSemaphoreTake(mtx, portMAX_DELAY);
  for (int i = 0; i < devN && n < max; i++)
    if (now - devs[i].last < staleMs) out[n++] = devs[i];
  xSemaphoreGive(mtx);
  return n;
}

const char* ble_vendor(uint16_t id) {
  switch (id) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x0075: return "Samsung";
    case 0x00E0: return "Google";
    case 0x0087: return "Garmin";
    case 0x0059: return "Nordic";
    case 0x02E5: return "Espressif";
    case 0x0171: return "Amazon";
    case 0x009E: return "Bose";
    case 0x012D: return "Sony";
    case 0x0310: return "SGL Italia";
    case 0x09C8: return "XUNTONG";
    default: return nullptr;
  }
}

static const char* kindTag(uint8_t k) {
  switch (k) {
    case BK_FINDMY: return "FindMy";
    case BK_TILE: return "Tile";
    case BK_SMARTTAG: return "SmartTag";
    case BK_FLOCK: return "FLOCK?";
    default: return nullptr;
  }
}
static uint32_t kindColor(uint8_t k) { return k == BK_FLOCK ? col::bad : (k ? col::warn : col::dim); }

void app_ble() {
  static BleDev snap[MAX_BLE];
  int n = 0, sel = 0, top = 0;
  bool detail = false;
  char selAddr[18] = "";
  uint32_t lastRefresh = 0;
  ui_header("BLE Scanner", col::purple);
  ui_footer("^", "Details", "v");
  ble_start();
  while (true) {
    Key k = ui_tick();
    bool force = false;
    if (k == K_BACK) {
      if (detail) detail = false, force = true, ui_footer("^", "Details", "v");
      else break;
    } else if (k == K_OK) {
      detail = !detail;
      force = true;
      ui_footer(detail ? "" : "^", detail ? "Back" : "Details", detail ? "" : "v");
    } else if (!detail && k == K_UP && sel > 0) {
      sel--;
      force = true;
    } else if (!detail && k == K_DOWN && sel + 1 < n) {
      sel++;
      force = true;
    }
    if (n && sel < n) strlcpy(selAddr, snap[sel].addr, sizeof selAddr);

    if (!force && millis() - lastRefresh < 1000) {
      delay(10);
      continue;
    }
    lastRefresh = millis();
    n = ble_snapshot(snap, MAX_BLE);
    std::sort(snap, snap + n, [](const BleDev& a, const BleDev& b) {
      if ((a.kind != 0) != (b.kind != 0)) return a.kind != 0;
      return a.rssi > b.rssi;
    });
    sel = 0;
    for (int i = 0; i < n; i++)
      if (!strcmp(snap[i].addr, selAddr)) sel = i;
    int trackers = 0;
    for (int i = 0; i < n; i++)
      if (snap[i].kind) trackers++;
    char note[24];
    snprintf(note, sizeof note, trackers ? "%d / %d tags" : "%d devices", trackers ? trackers : n, n);
    ui_header_note(note, trackers ? col::warn : col::text);

    if (detail && n) {
      const BleDev& d = snap[sel];
      body.fillScreen(col::bg);
      ui_smallfont();
      int y = 6;
      char v[40];
      auto kv = [&](const char* key, const char* val, uint32_t c) {
        body.setTextDatum(top_left);
        body.setTextColor(col::dim);
        body.drawString(key, 10, y);
        body.setTextColor(c);
        draw_fit(val, 100, y, SCR_W - 110);
        y += 23;
      };
      kv("Name", d.name[0] ? d.name : "-", col::text);
      kv("Address", d.addr, col::text);
      snprintf(v, sizeof v, "%d dBm", d.rssi);
      kv("Signal", v, rssi_color(d.rssi));
      draw_meter(200, y - 18, 100, 10, d.rssi);
      const char* ven = d.hasMfg ? ble_vendor(d.mfg) : nullptr;
      if (d.hasMfg) snprintf(v, sizeof v, "%s (0x%04X)", ven ? ven : "?", d.mfg);
      else strcpy(v, "-");
      kv("Vendor", v, col::text);
      kv("Type", kindTag(d.kind) ? kindTag(d.kind) : "-", kindColor(d.kind));
      if (d.flock) {
        snprintf(v, sizeof v, "%s (%d)", d.why, d.flock);
        kv("Flock sig", v, d.flock >= 60 ? col::bad : col::warn);
      }
      char a1[12], a2[12];
      fmt_age(millis() - d.first, a1);
      fmt_age(millis() - d.last, a2);
      snprintf(v, sizeof v, "%s ago (%u adv)", a1, d.seen);
      kv("First seen", v, col::text);
      kv("Last seen", a2, col::text);
    } else {
      ui_list(n, sel, top, [&](int i, int y, int h, bool s) {
        const BleDev& d = snap[i];
        int cy = y + h / 2;
        char r[8];
        snprintf(r, sizeof r, "%d", d.rssi);
        ui_smallfont();
        body.setTextDatum(middle_right);
        body.setTextColor(rssi_color(d.rssi));
        body.drawString(r, SCR_W - 12, cy);
        int x = 14;
        const char* tag = kindTag(d.kind);
        if (!tag && d.hasMfg) tag = ble_vendor(d.mfg);
        if (tag) {
          body.setFont(&fonts::Font2);
          int w = body.textWidth(tag) + 10;
          body.fillRoundRect(x, cy - 9, w, 18, 4, d.kind ? kindColor(d.kind) : col::line);
          body.setTextDatum(middle_center);
          body.setTextColor(d.kind ? col::bg : col::text);
          body.drawString(tag, x + w / 2, cy);
          x += w + 6;
        }
        ui_rowfont();
        body.setTextDatum(middle_left);
        body.setTextColor(d.name[0] ? col::text : col::dim);
        draw_fit(d.name[0] ? d.name : d.addr, x, cy, SCR_W - x - 50);
      });
    }
    ui_push();
  }
  ble_stop();
}
