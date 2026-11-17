// Detector: surveillance / tracker / drone / hacker-gear detection over Wi-Fi + BLE.
// Full-screen alerts, ignore, snooze, auto-snooze and hunt mode.
#include "common.h"
#include <algorithm>

namespace {

struct Hit {
  char id[18];
  uint8_t type, conf;
  char label[18];
  char name[33];
  int8_t rssi;
  bool ble;
  uint32_t first, last;
  uint16_t count;
  uint8_t alerts;
  int8_t alertRssi;
  uint32_t snoozeUntil;
  bool ignored;
  bool hasRid;
  RidInfo rid;
};

const int MAX_HIT = 48;
Hit* hits = nullptr;
int hitN = 0;
const uint32_t LIVE_MS = 30000;

// ---- Wi-Fi capture filter (runs in the Wi-Fi task) ----
uint8_t cacheMac[16][6];
uint32_t cacheT[16];
uint8_t cacheI = 0;

bool want(const FrameInfo& f) {
  bool hit = f.ridLen > 0 || sig_is_pwnagotchi(f.a2) || sig_oui(f.a2).type != DT_NONE;
  if (!hit && f.type == 0 && f.ssidLen > 0) hit = sig_ssid(f.ssid).type != DT_NONE;
  if (!hit) return false;
  if (f.ridLen) return true;  // drone telemetry: always pass
  uint32_t now = millis();
  for (int i = 0; i < 16; i++)
    if (!memcmp(cacheMac[i], f.a2, 6) && now - cacheT[i] < 700) return false;
  memcpy(cacheMac[cacheI], f.a2, 6);
  cacheT[cacheI] = now;
  cacheI = (cacheI + 1) % 16;
  return true;
}

Hit* find(const char* id) {
  for (int i = 0; i < hitN; i++)
    if (!strcmp(hits[i].id, id)) return &hits[i];
  return nullptr;
}

const char* confName(uint8_t c) { return c == CF_HIGH ? "High" : (c == CF_MED ? "Med" : "Low"); }

// returns the hit if this observation should raise a full-screen alert
Hit* ingest(const char* id, const SigHit& s, int8_t rssi, const char* name, bool ble, const RidInfo* rid) {
  if (s.type == DT_NONE || !type_enabled(s.type)) return nullptr;
  uint32_t now = millis();
  Hit* h = find(id);
  bool fresh = false;
  if (!h) {
    int slot = hitN < MAX_HIT ? hitN++ : -1;
    if (slot < 0) {  // evict oldest, lowest-confidence
      slot = 0;
      for (int i = 1; i < MAX_HIT; i++)
        if (hits[i].last < hits[slot].last) slot = i;
    }
    h = &hits[slot];
    memset(h, 0, sizeof(Hit));
    strlcpy(h->id, id, sizeof h->id);
    h->first = now;
    h->ble = ble;
    fresh = true;
  } else if (now - h->last > 60000) {
    fresh = true;  // came back after a minute away
  }
  if (s.conf > h->conf) {
    if (h->conf) fresh = true;  // upgraded confidence
    h->type = s.type;
    h->conf = s.conf;
    strlcpy(h->label, s.label, sizeof h->label);
  }
  if (name && name[0]) strlcpy(h->name, name, sizeof h->name);
  h->rssi = rssi;
  h->last = now;
  h->count++;
  if (rid) {
    if (rid->uasId[0]) strlcpy(h->rid.uasId, rid->uasId, sizeof h->rid.uasId);
    if (rid->opId[0]) strlcpy(h->rid.opId, rid->opId, sizeof h->rid.opId);
    if (rid->hasLoc) h->rid.hasLoc = true, h->rid.lat = rid->lat, h->rid.lon = rid->lon, h->rid.altM = rid->altM,
                     h->rid.speedMs = rid->speedMs;
    if (rid->hasOp) h->rid.hasOp = true, h->rid.opLat = rid->opLat, h->rid.opLon = rid->opLon;
    h->hasRid = true;
    if (h->rid.uasId[0] && !h->name[0]) strlcpy(h->name, h->rid.uasId, sizeof h->name);
  }

  if (fresh) {
    char line[160];
    snprintf(line, sizeof line, "%lu,%s,%s,%s,%s,%d,%s,%.6f,%.6f", (unsigned long)(now / 1000), ble ? "ble" : "wifi",
             det_name(h->type), h->label, h->id, rssi, h->name, h->hasRid ? h->rid.lat : 0.0f,
             h->hasRid ? h->rid.lon : 0.0f);
    sd_append("/guarddog/detect.csv", line);
  }

  // auto-snooze: after 3 alerts a device must come 7 dB closer to alert again
  bool closer = h->alerts >= 3 && rssi >= h->alertRssi + 7;
  if (h->ignored || now < h->snoozeUntil || h->conf < gSet.alertLvl) return nullptr;
  if (!(fresh && h->alerts < 3) && !closer) return nullptr;
  h->alerts++;
  h->alertRssi = rssi;
  return h;
}

void kv(int& y, const char* k, const char* v, uint32_t c) {
  body.setTextDatum(top_left);
  body.setTextColor(col::dim);
  body.drawString(k, 10, y);
  body.setTextColor(c);
  draw_fit(v, 100, y, SCR_W - 110);
  y += 21;
}

void drawTag(int x, int cy, uint8_t t, bool live) {
  body.setFont(&fonts::Font2);
  const char* n = det_name(t);
  int w = body.textWidth(n) + 10;
  body.fillRoundRect(x, cy - 9, w, 18, 4, live ? det_color(t) : col::line);
  body.setTextDatum(middle_center);
  body.setTextColor(live ? col::bg : col::dim);
  body.drawString(n, x + w / 2, cy);
}

void drawDetail(const Hit& h) {
  body.fillScreen(col::bg);
  ui_smallfont();
  int y = 4;
  char v[48], a[12];
  snprintf(v, sizeof v, "%s  (%s confidence)", det_name(h.type), confName(h.conf));
  kv(y, "Type", v, det_color(h.type));
  kv(y, "Match", h.label, col::text);
  if (h.name[0]) kv(y, h.ble ? "Name" : "SSID", h.name, col::text);
  kv(y, h.ble ? "BLE addr" : "MAC", h.id, col::text);
  snprintf(v, sizeof v, "%d dBm", h.rssi);
  kv(y, "Signal", v, rssi_color(h.rssi));
  draw_meter(200, y - 16, 100, 10, h.rssi);
  fmt_age(millis() - h.last, a);
  snprintf(v, sizeof v, "%s ago  (%u hits)", a, h.count);
  kv(y, "Last seen", v, col::text);
  if (h.hasRid) {
    if (h.rid.uasId[0]) kv(y, "UAS ID", h.rid.uasId, col::info);
    if (h.rid.hasLoc) {
      snprintf(v, sizeof v, "%.5f, %.5f", h.rid.lat, h.rid.lon);
      kv(y, "Drone at", v, col::info);
      snprintf(v, sizeof v, "%.0f m  %.1f m/s", h.rid.altM, h.rid.speedMs);
      kv(y, "Alt / spd", v, col::info);
    }
    if (h.rid.hasOp) {
      snprintf(v, sizeof v, "%.5f, %.5f", h.rid.opLat, h.rid.opLon);
      kv(y, "Pilot at", v, col::warn);
    }
  }
  if (h.ignored) kv(y, "Status", "Ignored", col::dim);
  else if (millis() < h.snoozeUntil) kv(y, "Status", "Snoozed", col::dim);
}

void drawAlert(const Hit& h) {
  uint32_t c = det_color(h.type);
  body.fillScreen(col::bg);
  body.drawRoundRect(2, 2, SCR_W - 4, BODY_H - 4, 10, c);
  body.drawRoundRect(3, 3, SCR_W - 6, BODY_H - 6, 9, c);
  body.setTextDatum(top_center);
  body.setFont(&fonts::FreeSansBold18pt7b);
  body.setTextColor(c);
  body.drawString(det_name(h.type), SCR_W / 2, 12);
  body.setFont(&fonts::FreeSansBold12pt7b);
  body.setTextColor(col::text);
  body.drawString(h.label, SCR_W / 2, 56);
  ui_smallfont();
  body.setTextColor(col::dim);
  char v[64];
  snprintf(v, sizeof v, "%s%s%s", h.name[0] ? h.name : "", h.name[0] ? "  " : "", h.id);
  body.setTextDatum(top_left);
  int w = body.textWidth(v);
  if (w > SCR_W - 24) w = SCR_W - 24;
  draw_fit(v, (SCR_W - w) / 2, 90, SCR_W - 24);
  snprintf(v, sizeof v, "%d dBm   %s confidence", h.rssi, confName(h.conf));
  body.setTextDatum(top_center);
  body.setTextColor(rssi_color(h.rssi));
  body.drawString(v, SCR_W / 2, 116);
  draw_meter(20, 146, SCR_W - 40, 14, h.rssi);
}

void alertSound(uint8_t type) {
  if (type == DT_DRONE) {
    beep(1800, 80);
    delay(100);
    beep(2400, 80);
  } else if (type == DT_FINDMY || type == DT_TILE || type == DT_SMARTTAG || type == DT_GTAG) {
    beep(1500, 120);
  } else {
    beep(2600, 90);
    delay(110);
    beep(2600, 90);
    delay(110);
    beep(2600, 90);
  }
}

}  // namespace

void app_detector() {
  static BleDev snap[MAX_HIT];
  hits = (Hit*)calloc(MAX_HIT, sizeof(Hit));
  if (!hits) return;
  hitN = 0;
  memset(cacheT, 0, sizeof cacheT);

  enum Mode { LIST, DETAIL, HUNT, ALERT } mode = LIST, back = LIST;
  int sel = 0, top = 0;
  char cur[18] = "";  // id of the hit shown in detail / hunt / alert
  uint32_t alertUntil = 0, lastDraw = 0, lastBle = 0, nextTick = 0;
  float ema = -100;
  float emaPrev = -100;
  uint32_t trendT = 0;

  auto footer = [&]() {
    switch (mode) {
      case LIST: ui_footer("^", "Details", "v"); break;
      case DETAIL: {
        Hit* h = find(cur);
        ui_footer(h && h->ignored ? "Unignore" : "Ignore", "Back", "Hunt");
        break;
      }
      case HUNT: ui_footer("", "Back", ""); break;
      case ALERT: ui_footer("Ignore", "OK", "Snooze"); break;
    }
  };

  ui_header("Detector", col::bad);
  footer();
  sniff_start(1, want);
  sniff_hop(true, 230);
  ble_start();
  leds_base(0x001A00);
  FrameInfo f;

  while (true) {
    Key k = ui_tick();
    bool force = false;
    Hit* curHit = cur[0] ? find(cur) : nullptr;

    // ---------- input ----------
    if (mode == LIST) {
      if (k == K_BACK) break;
      if (k == K_UP && sel > 0) sel--, force = true;
      if (k == K_DOWN && sel + 1 < hitN) sel++, force = true;
      if (k == K_OK && hitN) {
        strlcpy(cur, hits[sel].id, sizeof cur);
        mode = DETAIL;
        footer();
        force = true;
      }
    } else if (mode == DETAIL) {
      if (k == K_BACK || k == K_OK) mode = LIST, footer(), force = true;
      else if (k == K_UP && curHit) {
        curHit->ignored = !curHit->ignored;
        footer();
        force = true;
      } else if (k == K_DOWN && curHit) {
        mode = HUNT;
        ema = emaPrev = curHit->rssi;
        footer();
        force = true;
      }
    } else if (mode == HUNT) {
      if (k == K_BACK || k == K_OK) mode = DETAIL, footer(), force = true;
    } else if (mode == ALERT) {
      bool done = k != K_NONE || millis() > alertUntil;
      if (curHit && k == K_UP) curHit->ignored = true;
      if (curHit && k == K_DOWN) curHit->snoozeUntil = millis() + 30UL * 60 * 1000;
      if (done) {
        mode = back;
        footer();
        force = true;
        if (k == K_UP) ui_toast("Ignored", col::dim), ui_header("Detector", col::bad);
        if (k == K_DOWN) ui_toast("Snoozed 30 min", col::dim), ui_header("Detector", col::bad);
      }
    }

    // ---------- ingest ----------
    Hit* fire = nullptr;
    int budget = 40;
    while (budget-- > 0 && sniff_pop(f)) {
      char mac[18];
      fmt_mac(f.a2, mac);
      SigHit s = sig_oui(f.a2);
      if (s.type == DT_FLOCK && s.conf == CF_LOW && f.type == 0 && f.sub == 4 && f.ssidLen == 0)
        s = SigHit(DT_FLOCK, CF_MED, "Flock probe");  // camera LOWI scan behaviour
      if (f.type == 0 && f.ssidLen > 0) s = better(s, sig_ssid(f.ssid));
      if (sig_is_pwnagotchi(f.a2)) s = SigHit(DT_HACKER, CF_HIGH, "Pwnagotchi");
      RidInfo rid;
      bool hasRid = false;
      if (f.ridLen) {
        memset(&rid, 0, sizeof rid);
        hasRid = rid_decode(f.rid, f.ridLen, rid);
        if (hasRid) s = SigHit(DT_DRONE, CF_HIGH, "Remote ID");
      }
      const char* nm = (f.type == 0 && f.ssidLen > 0 && (f.sub == 8 || f.sub == 5)) ? f.ssid : nullptr;
      Hit* h = ingest(mac, s, f.rssi, nm, false, hasRid ? &rid : nullptr);
      if (h && !fire) fire = h;
    }
    if (millis() - lastBle > 700) {
      lastBle = millis();
      int n = ble_snapshot(snap, MAX_HIT, 15000);
      for (int i = 0; i < n; i++) {
        if (!snap[i].type || millis() - snap[i].last > 1500) continue;
        SigHit s(DetType(snap[i].type), Conf(snap[i].conf), snap[i].label);
        Hit* h = ingest(snap[i].addr, s, snap[i].rssi, snap[i].name, true, snap[i].hasRid ? &snap[i].rid : nullptr);
        if (h && !fire) fire = h;
      }
    }
    if (fire && mode != ALERT && mode != HUNT) {
      back = mode;
      mode = ALERT;
      strlcpy(cur, fire->id, sizeof cur);
      alertUntil = millis() + 10000;
      footer();
      leds_flash(det_color(fire->type), 1500);
      alertSound(fire->type);
      force = true;
    }

    // ---------- hunt geiger ----------
    curHit = cur[0] ? find(cur) : nullptr;
    if (mode == HUNT && curHit) {
      if (millis() - curHit->last < 3000 && millis() > nextTick) {
        int iv = map(constrain(curHit->rssi, -95, -35), -95, -35, 1400, 90);
        nextTick = millis() + iv;
        beep(2200, 12);
        leds_flash(det_color(curHit->type), 40);
      }
    }

    // ---------- draw ----------
    if (!force && millis() - lastDraw < (mode == HUNT ? 250u : 500u)) {
      delay(5);
      continue;
    }
    lastDraw = millis();
    bool anyLive = false;
    for (int i = 0; i < hitN; i++)
      if (millis() - hits[i].last < LIVE_MS && hits[i].conf >= gSet.alertLvl && !hits[i].ignored) anyLive = true;
    leds_base(anyLive ? 0x200000 : 0x001A00);

    if (mode == ALERT && curHit) {
      drawAlert(*curHit);
    } else if (mode == DETAIL && curHit) {
      drawDetail(*curHit);
    } else if (mode == HUNT && curHit) {
      body.fillScreen(col::bg);
      bool live = millis() - curHit->last < 3000;
      ema = ema * 0.6f + curHit->rssi * 0.4f;
      if (millis() - trendT > 1500) {
        trendT = millis();
        emaPrev = ema;
      }
      float d = ema - emaPrev;
      body.setTextDatum(top_left);
      ui_smallfont();
      body.setTextColor(det_color(curHit->type));
      char v[48];
      snprintf(v, sizeof v, "HUNT  %s  %s", det_name(curHit->type), curHit->label);
      draw_fit(v, 10, 4, SCR_W - 20);
      body.setTextDatum(middle_center);
      body.setFont(&fonts::FreeSansBold24pt7b);
      body.setTextColor(live ? rssi_color(curHit->rssi) : col::dim);
      snprintf(v, sizeof v, "%d", curHit->rssi);
      body.drawString(v, SCR_W / 2, 70);
      ui_smallfont();
      body.setTextColor(col::dim);
      body.drawString("dBm", SCR_W / 2, 100);
      draw_meter(16, 118, SCR_W - 32, 18, curHit->rssi);
      body.setFont(&fonts::FreeSansBold12pt7b);
      const char* tr = !live ? "LOST SIGNAL" : (d > 2 ? "WARMER" : (d < -2 ? "COLDER" : "STEADY"));
      body.setTextColor(!live ? col::dim : (d > 2 ? col::good : (d < -2 ? col::bad : col::text)));
      body.drawString(tr, SCR_W / 2, 162);
    } else {
      if (mode != LIST) mode = LIST, footer();
      // sort: live first, then confidence, then signal
      char keep[18] = "";
      if (hitN && sel < hitN) strlcpy(keep, hits[sel].id, sizeof keep);
      uint32_t now = millis();
      std::sort(hits, hits + hitN, [now](const Hit& a, const Hit& b) {
        bool la = now - a.last < LIVE_MS, lb = now - b.last < LIVE_MS;
        if (la != lb) return la;
        if (a.conf != b.conf) return a.conf > b.conf;
        return a.rssi > b.rssi;
      });
      sel = 0;
      for (int i = 0; i < hitN; i++)
        if (!strcmp(hits[i].id, keep)) sel = i;
      char note[20];
      snprintf(note, sizeof note, "ch %d + BLE", sniff_cur_channel());
      ui_header_note(note, col::dim);
      ui_list(hitN, sel, top,
              [&](int i, int y, int h, bool s) {
                const Hit& x = hits[i];
                bool live = now - x.last < LIVE_MS && !x.ignored;
                int cy = y + h / 2;
                drawTag(14, cy, x.type, live);
                int tx = 14 + body.textWidth(det_name(x.type)) + 16;
                char r[8];
                snprintf(r, sizeof r, "%d", x.rssi);
                ui_smallfont();
                body.setTextDatum(middle_right);
                body.setTextColor(live ? rssi_color(x.rssi) : col::dim);
                body.drawString(r, SCR_W - 12, cy);
                ui_rowfont();
                body.setTextDatum(middle_left);
                body.setTextColor(live ? col::text : col::dim);
                draw_fit(x.name[0] ? x.name : x.label, tx, cy, SCR_W - tx - 48);
              },
              "Watching Wi-Fi + BLE...");
    }
    ui_push();
  }
  ble_stop();
  sniff_stop();
  leds_off();
  free(hits);
  hits = nullptr;
}
