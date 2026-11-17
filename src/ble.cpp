// BLE scanner engine + BLE Scanner app (trackers + Flock/Raven signatures)
#include "common.h"
#include <NimBLEDevice.h>
#include <algorithm>

#define MAX_BLE 80
static BleDev devs[MAX_BLE];
static int devN = 0;
static SemaphoreHandle_t mtx = nullptr;
static bool bleInit = false;

static NimBLEUUID uFlockGatt("e8ccbb38-9532-46a8-9fe5-1814df172e6f");
static NimBLEUUID uRid((uint16_t)0xFFFA);

class ScanCB : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* d) override {
    BleDev n;
    memset(&n, 0, sizeof(n));
    strlcpy(n.addr, d->getAddress().toString().c_str(), sizeof(n.addr));
    n.rssi = d->getRSSI();
    n.last = millis();
    SigHit h;
    if (d->haveName()) {
      strlcpy(n.name, d->getName().c_str(), sizeof(n.name));
      h = better(h, sig_ble_name(n.name));
    }
    if (d->haveManufacturerData()) {
      std::string m = d->getManufacturerData();
      if (m.size() >= 2) {
        n.hasMfg = true;
        n.mfg = (uint8_t)m[0] | ((uint16_t)(uint8_t)m[1] << 8);
        h = better(h, sig_mfg(n.mfg, (const uint8_t*)m.data(), m.size()));
      }
    }
    int sc = d->getServiceUUIDCount();
    for (int i = 0; i < sc; i++) {
      NimBLEUUID u = d->getServiceUUID(i);
      if (u.bitSize() == 16) h = better(h, sig_uuid16(u.getNative()->u16.value));
      else if (u == uFlockGatt) h = better(h, SigHit(DT_FLOCK, CF_HIGH, "Flock GATT"));
    }
    if (d->getAddressType() == BLE_ADDR_PUBLIC) {
      const uint8_t* a = d->getAddress().getNative();  // little-endian
      uint8_t be[3] = {a[5], a[4], a[3]};
      h = better(h, sig_oui(be));
    }
    if (d->haveServiceData()) {
      std::string sd = d->getServiceData(uRid);
      if (sd.size() >= 2 + 25 && (uint8_t)sd[0] == 0x0D) {
        if (rid_decode((const uint8_t*)sd.data() + 2, sd.size() - 2, n.rid)) {
          n.hasRid = true;
          h = better(h, SigHit(DT_DRONE, CF_HIGH, "Remote ID"));
        }
      }
    }
    n.type = h.type;
    n.conf = h.conf;
    strlcpy(n.label, h.label, sizeof(n.label));

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
      if (n.conf > o.conf) {
        o.type = n.type;
        o.conf = n.conf;
        strlcpy(o.label, n.label, sizeof(o.label));
      }
      if (n.hasRid) {
        RidInfo& r = o.rid;
        if (n.rid.uasId[0]) strlcpy(r.uasId, n.rid.uasId, sizeof r.uasId);
        if (n.rid.opId[0]) strlcpy(r.opId, n.rid.opId, sizeof r.opId);
        if (n.rid.hasLoc) r.hasLoc = true, r.lat = n.rid.lat, r.lon = n.rid.lon, r.altM = n.rid.altM, r.speedMs = n.rid.speedMs;
        if (n.rid.hasOp) r.hasOp = true, r.opLat = n.rid.opLat, r.opLon = n.rid.opLon;
        o.hasRid = true;
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

static const char* kindTag(uint8_t t) { return t ? det_name(t) : nullptr; }
static uint32_t kindColor(uint8_t t) { return det_color(t); }

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
      if ((a.type != 0) != (b.type != 0)) return a.type != 0;
      return a.rssi > b.rssi;
    });
    sel = 0;
    for (int i = 0; i < n; i++)
      if (!strcmp(snap[i].addr, selAddr)) sel = i;
    int trackers = 0;
    for (int i = 0; i < n; i++)
      if (snap[i].type) trackers++;
    char note[24];
    snprintf(note, sizeof note, "%d nearby", n);
    ui_header_note(note, col::dim);

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
      kv("Type", kindTag(d.type) ? kindTag(d.type) : "-", kindColor(d.type));
      if (d.type) {
        snprintf(v, sizeof v, "%s (%s)", d.label, d.conf == CF_HIGH ? "high" : (d.conf == CF_MED ? "med" : "low"));
        kv("Match", v, det_color(d.type));
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
        const char* tag = kindTag(d.type);
        if (!tag && d.hasMfg) tag = ble_vendor(d.mfg);
        if (tag) {
          body.setFont(&fonts::Font2);
          int w = body.textWidth(tag) + 10;
          body.fillRoundRect(x, cy - 9, w, 18, 4, d.type ? kindColor(d.type) : col::line);
          body.setTextDatum(middle_center);
          body.setTextColor(d.type ? col::bg : col::text);
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
