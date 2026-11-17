#include "common.h"
#include <Preferences.h>
#include <Adafruit_NeoPixel.h>

M5Canvas body(&M5.Display);
Settings gSet;
bool gSdOk = false;

bool type_enabled(uint8_t t) {
  uint16_t m = gSet.typeMask ? gSet.typeMask : det_default_mask();
  return (m >> t) & 1;
}

// ================= settings =================
void settings_load() {
  Preferences p;
  if (!p.begin("guarddog", true)) return;
  gSet.bright = p.getUChar("br", gSet.bright);
  gSet.sound = p.getBool("snd", gSet.sound);
  gSet.leds = p.getBool("led", gSet.leds);
  gSet.big = p.getBool("big", gSet.big);
  gSet.alertLvl = p.getUChar("alv", gSet.alertLvl);
  gSet.typeMask = p.getUShort("tmask", 0);
  p.end();
}

void settings_save() {
  Preferences p;
  if (!p.begin("guarddog", false)) return;
  p.putUChar("br", gSet.bright);
  p.putBool("snd", gSet.sound);
  p.putBool("led", gSet.leds);
  p.putBool("big", gSet.big);
  p.putUChar("alv", gSet.alertLvl);
  p.putUShort("tmask", gSet.typeMask);
  p.end();
}

// ================= leds (M5GO bottom: 10x SK6812 on GPIO15) =================
static Adafruit_NeoPixel px(10, 15, NEO_GRB + NEO_KHZ800);
static uint32_t ledBase = 0, ledFlash = 0, ledUntil = 0, ledShown = 0xFFFFFFFF;

void leds_begin() {
  px.begin();
  px.setBrightness(40);
  px.clear();
  px.show();
}
void leds_base(uint32_t c) { ledBase = c; }
void leds_flash(uint32_t c, uint16_t ms) {
  ledFlash = c;
  ledUntil = millis() + ms;
}
void leds_off() {
  ledBase = 0;
  ledUntil = 0;
}
void leds_tick() {
  uint32_t c = 0;
  if (gSet.leds) c = (millis() < ledUntil) ? ledFlash : ledBase;
  if (c == ledShown) return;
  ledShown = c;
  for (int i = 0; i < 10; i++) px.setPixelColor(i, (c >> 16) & 255, (c >> 8) & 255, c & 255);
  px.show();
}

void beep(uint16_t f, uint16_t ms) {
  if (gSet.sound) M5.Speaker.tone(f, ms);
}

// ================= sd =================
void sd_begin() {
  gSdOk = SD.begin(4, SPI, 25000000);
  if (gSdOk && !SD.exists("/guarddog")) SD.mkdir("/guarddog");
}

bool sd_append(const char* path, const char* line) {
  if (!gSdOk) return false;
  File f = SD.open(path, FILE_APPEND);
  if (!f) return false;
  f.println(line);
  f.close();
  return true;
}

// ================= helpers =================
void fmt_mac(const uint8_t* m, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void fmt_age(uint32_t ms, char* out) {
  uint32_t s = ms / 1000;
  if (s < 60) snprintf(out, 12, "%lus", (unsigned long)s);
  else if (s < 3600) snprintf(out, 12, "%lum", (unsigned long)(s / 60));
  else snprintf(out, 12, "%luh", (unsigned long)(s / 3600));
}

uint32_t rssi_color(int r) {
  if (r >= -55) return col::good;
  if (r >= -70) return col::warn;
  if (r >= -80) return col::accent;
  return col::bad;
}

bool ci_contains(const char* hay, const char* needle) {
  if (!hay || !needle || !*needle) return false;
  size_t n = strlen(needle);
  for (const char* p = hay; *p; p++) {
    if (strncasecmp(p, needle, n) == 0) return true;
  }
  return false;
}

void draw_meter(int x, int y, int w, int h, int rssi) {
  int pct = constrain((rssi + 100) * 100 / 65, 0, 100);
  body.fillRoundRect(x, y, w, h, h / 2, col::line);
  int fw = w * pct / 100;
  if (fw > h) body.fillRoundRect(x, y, fw, h, h / 2, rssi_color(rssi));
}

void ui_rowfont() { body.setFont(gSet.big ? &fonts::FreeSansBold12pt7b : &fonts::FreeSansBold9pt7b); }
void ui_smallfont() { body.setFont(&fonts::FreeSans9pt7b); }
int ui_rowh() { return gSet.big ? 32 : 24; }

void draw_fit(const char* s, int x, int y, int maxw) {
  if (body.textWidth(s) <= maxw) {
    body.drawString(s, x, y);
    return;
  }
  char buf[48];
  strlcpy(buf, s, sizeof(buf));
  int n = strlen(buf);
  while (n > 1) {
    buf[--n] = 0;
    char t[52];
    snprintf(t, sizeof(t), "%s..", buf);
    if (body.textWidth(t) <= maxw) {
      body.drawString(t, x, y);
      return;
    }
  }
}

// Sasquatch footprint glyph
void draw_foot(lgfx::LovyanGFX& d, int cx, int cy, int s, uint32_t c) {
  // s ~ half-height of the sole
  d.fillEllipse(cx, cy, s * 6 / 10, s, c);
  d.fillEllipse(cx + s / 10, cy + s * 7 / 10, s * 5 / 10, s * 4 / 10, c);
  d.fillCircle(cx - s * 4 / 10, cy - s * 13 / 10, s * 27 / 100, c);
  d.fillCircle(cx + s * 5 / 100, cy - s * 14 / 10, s * 21 / 100, c);
  d.fillCircle(cx + s * 4 / 10, cy - s * 13 / 10, s * 18 / 100, c);
  d.fillCircle(cx + s * 65 / 100, cy - s * 108 / 100, s * 15 / 100, c);
  d.fillCircle(cx + s * 80 / 100, cy - s * 80 / 100, s * 12 / 100, c);
}

// ================= chrome =================
static void ui_battery() {
  auto& d = M5.Display;
  int lvl = M5.Power.getBatteryLevel();
  bool chg = M5.Power.isCharging() == m5::Power_Class::is_charging;
  d.fillRect(250, 0, 70, HDR_H - 2, col::panel);
  int x = 286, y = 7;
  d.drawRoundRect(x, y, 26, 12, 2, col::dim);
  d.fillRect(x + 26, y + 3, 2, 6, col::dim);
  if (lvl >= 0) {
    uint32_t c = lvl <= 20 ? col::bad : (lvl <= 40 ? col::warn : col::good);
    d.fillRect(x + 2, y + 2, 22 * constrain(lvl, 0, 100) / 100, 8, c);
  }
  d.setFont(&fonts::Font2);
  d.setTextDatum(middle_right);
  d.setTextColor(chg ? col::info : col::dim, col::panel);
  char b[8];
  if (lvl >= 0) snprintf(b, sizeof(b), chg ? "+%d%%" : "%d%%", lvl);
  else strcpy(b, "USB");
  d.drawString(b, x - 4, y + 6);
}

void ui_header(const char* title, uint32_t tint) {
  auto& d = M5.Display;
  d.fillRect(0, 0, SCR_W, HDR_H - 2, col::panel);
  d.fillRect(0, HDR_H - 2, SCR_W, 2, tint);
  draw_foot(d, 13, 14, 6, col::accent);
  d.setFont(&fonts::FreeSansBold9pt7b);
  d.setTextDatum(middle_left);
  d.setTextColor(col::text, col::panel);
  d.drawString(title, 26, 12);
  ui_battery();
}

void ui_header_note(const char* note, uint32_t color) {
  auto& d = M5.Display;
  d.fillRect(170, 0, 80, HDR_H - 2, col::panel);
  d.setFont(&fonts::Font2);
  d.setTextDatum(middle_right);
  d.setTextColor(color, col::panel);
  d.drawString(note, 246, 12);
}

static void footArrow(int cx, int cy, bool up) {
  auto& d = M5.Display;
  if (up) d.fillTriangle(cx - 8, cy + 4, cx + 8, cy + 4, cx, cy - 5, col::text);
  else d.fillTriangle(cx - 8, cy - 4, cx + 8, cy - 4, cx, cy + 5, col::text);
}

void ui_footer(const char* a, const char* b, const char* c) {
  auto& d = M5.Display;
  int y0 = SCR_H - FTR_H;
  d.fillRect(0, y0, SCR_W, FTR_H, col::bg);
  d.drawFastHLine(0, y0, SCR_W, col::line);
  d.setFont(&fonts::FreeSans9pt7b);
  d.setTextDatum(middle_center);
  d.setTextColor(col::text, col::bg);
  const char* lab[3] = {a, b, c};
  const int xs[3] = {64, 160, 256};
  for (int i = 0; i < 3; i++) {
    if (!lab[i] || !*lab[i]) continue;
    if (!strcmp(lab[i], "^")) footArrow(xs[i], y0 + 12, true);
    else if (!strcmp(lab[i], "v")) footArrow(xs[i], y0 + 12, false);
    else d.drawString(lab[i], xs[i], y0 + 12);
  }
}

void ui_push() { body.pushSprite(0, BODY_Y); }

void ui_list(int count, int sel, int& top, const std::function<void(int, int, int, bool)>& row,
             const char* empty) {
  int h = ui_rowh();
  int vis = BODY_H / h;
  if (sel < top) top = sel;
  if (sel >= top + vis) top = sel - vis + 1;
  if (top > count - vis) top = count - vis;
  if (top < 0) top = 0;
  body.fillScreen(col::bg);
  if (count == 0) {
    ui_smallfont();
    body.setTextDatum(middle_center);
    body.setTextColor(col::dim);
    body.drawString(empty, SCR_W / 2, BODY_H / 2);
    return;
  }
  for (int i = 0; i < vis && top + i < count; i++) {
    int idx = top + i, y = i * h + (BODY_H - vis * h) / 2;
    bool s = idx == sel;
    if (s) {
      body.fillRoundRect(2, y + 1, SCR_W - 10, h - 2, 6, col::panel);
      body.fillRect(4, y + 5, 3, h - 10, col::accent);
    }
    row(idx, y, h, s);
  }
  if (count > vis) {
    int bh = max(14, BODY_H * vis / count);
    int by = (BODY_H - bh) * top / max(1, count - vis);
    body.fillRect(SCR_W - 4, 0, 3, BODY_H, col::line);
    body.fillRect(SCR_W - 4, by, 3, bh, col::accent);
  }
}

void ui_toast(const char* msg, uint32_t color) {
  auto& d = M5.Display;
  d.setFont(&fonts::FreeSansBold9pt7b);
  int w = d.textWidth(msg) + 32;
  int x = (SCR_W - w) / 2, y = SCR_H / 2 - 22;
  d.fillRoundRect(x, y, w, 44, 10, col::panel);
  d.drawRoundRect(x, y, w, 44, 10, color);
  d.setTextDatum(middle_center);
  d.setTextColor(color, col::panel);
  d.drawString(msg, SCR_W / 2, SCR_H / 2);
  delay(900);
}

void ui_splash() {
  auto& d = M5.Display;
  d.fillScreen(col::bg);
  draw_foot(d, 66, 132, 38, col::accent);
  d.setTextDatum(middle_left);
  d.setFont(&fonts::FreeSansBold18pt7b);
  d.setTextColor(col::text);
  d.drawString("GUARD", 120, 92);
  d.setTextColor(col::accent);
  d.drawString("DOG", 120, 130);
  d.setFont(&fonts::FreeSans9pt7b);
  d.setTextColor(col::dim);
  d.drawString("wireless recon  v" SW_VERSION, 122, 166);
  d.setTextDatum(bottom_center);
  d.setFont(&fonts::Font2);
  d.drawString("67SASQUATCH", SCR_W / 2, SCR_H - 6);
  for (int i = 0; i < 10; i++) {
    px.setPixelColor(i, 255, 110, 20);
    px.show();
    delay(40);
  }
  beep(1400, 50);
  delay(80);
  beep(2000, 70);
  delay(900);
}

// ================= input =================
Key ui_tick() {
  M5.update();
  leds_tick();
  sniff_tick();
  static uint32_t lastBat = 0;
  if (millis() - lastBat > 10000) {
    lastBat = millis();
    ui_battery();
  }
  static uint32_t rep = 0;
  auto& A = M5.BtnA;
  auto& B = M5.BtnB;
  auto& C = M5.BtnC;
  if (A.wasPressed()) {
    rep = millis() + 420;
    return K_UP;
  }
  if (C.wasPressed()) {
    rep = millis() + 420;
    return K_DOWN;
  }
  if ((A.isPressed() || C.isPressed()) && millis() > rep) {
    rep = millis() + 110;
    return A.isPressed() ? K_UP : K_DOWN;
  }
  if (B.wasHold()) return K_BACK;
  if (B.wasClicked()) return K_OK;
  return K_NONE;
}

// ================= settings app =================
void app_settings() {
  int sel = 0, top = 0;
  const uint8_t levels[] = {40, 80, 140, 200, 255};
  ui_header("Settings", col::dim);
  ui_footer("^", "Change", "v");
  bool dirty = true;
  uint32_t lastDraw = 0;
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_UP && sel > 0) sel--, dirty = true;
    if (k == K_DOWN && sel < 9) sel++, dirty = true;
    if (k == K_OK) {
      dirty = true;
      if (sel == 0) {
        int i = 0;
        while (i < 5 && levels[i] <= gSet.bright) i++;
        gSet.bright = levels[i % 5];
        M5.Display.setBrightness(gSet.bright);
      } else if (sel == 1) {
        gSet.sound = !gSet.sound;
        beep(1800, 40);
      } else if (sel == 2) {
        gSet.leds = !gSet.leds;
        if (gSet.leds) leds_flash(0x00FF60, 300);
      } else if (sel == 3) {
        gSet.big = !gSet.big;
      } else if (sel == 4) {
        gSet.alertLvl = gSet.alertLvl >= CF_HIGH ? CF_LOW : gSet.alertLvl + 1;
      } else if (sel == 5) {
        app_types();
        ui_header("Settings", col::dim);
        ui_footer("^", "Change", "v");
      } else if (sel == 6) {
        sd_begin();
      }
      settings_save();
    }
    if (millis() - lastDraw > 2000) dirty = true;
    if (!dirty) {
      delay(10);
      continue;
    }
    dirty = false;
    lastDraw = millis();
    ui_list(10, sel, top, [&](int i, int y, int h, bool s) {
      char v[24];
      const char* label = "";
      uint32_t vc = col::text;
      switch (i) {
        case 0: label = "Brightness"; snprintf(v, sizeof v, "%d%%", gSet.bright * 100 / 255); break;
        case 1: label = "Sound"; strcpy(v, gSet.sound ? "On" : "Off"); vc = gSet.sound ? col::good : col::dim; break;
        case 2: label = "LED bar"; strcpy(v, gSet.leds ? "On" : "Off"); vc = gSet.leds ? col::good : col::dim; break;
        case 3: label = "Large text"; strcpy(v, gSet.big ? "On" : "Off"); vc = gSet.big ? col::good : col::dim; break;
        case 4: label = "Alert level"; strcpy(v, gSet.alertLvl == CF_LOW ? "All" : (gSet.alertLvl == CF_MED ? "Med+" : "High only")); vc = col::accent; break;
        case 5: label = "Detect types"; strcpy(v, ">"); vc = col::accent; break;
        case 6: label = "SD card"; strcpy(v, gSdOk ? "Ready" : "None"); vc = gSdOk ? col::good : col::bad; break;
        case 7: label = "Battery"; snprintf(v, sizeof v, "%d%%", M5.Power.getBatteryLevel()); break;
        case 8: label = "Free RAM"; snprintf(v, sizeof v, "%u KB", (unsigned)(ESP.getFreeHeap() / 1024)); break;
        case 9: label = "Version"; strcpy(v, SW_VERSION); break;
      }
      ui_rowfont();
      body.setTextDatum(middle_left);
      body.setTextColor(col::text);
      body.drawString(label, 14, y + h / 2);
      body.setTextDatum(middle_right);
      body.setTextColor(vc);
      body.drawString(v, SCR_W - 14, y + h / 2);
    });
    ui_push();
  }
}

// ================= detection type toggles =================
void app_types() {
  int sel = 0, top = 0;
  const int N = DT_COUNT - 1;
  ui_header("Detect types", col::accent);
  ui_footer("^", "On / Off", "v");
  bool dirty = true;
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_UP && sel > 0) sel--, dirty = true;
    if (k == K_DOWN && sel < N - 1) sel++, dirty = true;
    if (k == K_OK) {
      uint16_t m = gSet.typeMask ? gSet.typeMask : det_default_mask();
      m ^= 1 << (sel + 1);
      gSet.typeMask = m ? m : 1;  // keep non-zero so "defaults" stays distinct
      settings_save();
      dirty = true;
    }
    if (!dirty) {
      delay(10);
      continue;
    }
    dirty = false;
    ui_list(N, sel, top, [&](int i, int y, int h, bool s) {
      uint8_t t = i + 1;
      bool on = type_enabled(t);
      body.fillRoundRect(16, y + h / 2 - 7, 14, 14, 3, det_color(t));
      ui_rowfont();
      body.setTextDatum(middle_left);
      body.setTextColor(on ? col::text : col::dim);
      body.drawString(det_name(t), 40, y + h / 2);
      body.setTextDatum(middle_right);
      body.setTextColor(on ? col::good : col::dim);
      body.drawString(on ? "On" : "Off", SCR_W - 14, y + h / 2);
    });
    ui_push();
  }
}
