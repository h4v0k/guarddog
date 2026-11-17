// Guard Dog — 67SASQUATCH wireless recon firmware for M5Stack Fire / Core
// Buttons: A = up, C = down, B click = select, B hold = back
#include "common.h"

struct MenuItem {
  const char* name;
  uint32_t color;
  void (*fn)();
};

static const MenuItem MENU[] = {
    {"Detector", col::bad, app_detector},
    {"Wi-Fi Survey", col::info, app_survey},
    {"Channel Map", col::info, app_channels},
    {"BLE Scanner", col::purple, app_ble},
    {"Packet Monitor", col::good, app_monitor},
    {"Wi-Fi Threats", col::bad, app_guard},
    {"Settings", col::dim, app_settings},
};
static const int MENU_N = sizeof(MENU) / sizeof(MENU[0]);
static int sel = 0, top = 0;

static void drawMenu() {
  ui_list(MENU_N, sel, top, [](int i, int y, int h, bool s) {
    int cy = y + h / 2;
    body.fillRoundRect(16, cy - 7, 14, 14, 3, MENU[i].color);
    ui_rowfont();
    body.setTextDatum(middle_left);
    body.setTextColor(s ? col::text : col::dim);
    body.drawString(MENU[i].name, 40, cy);
    if (s) {
      body.fillTriangle(SCR_W - 24, cy - 6, SCR_W - 24, cy + 6, SCR_W - 16, cy, col::accent);
    }
  });
  ui_push();
}

static void showMenu() {
  ui_header("GUARD DOG");
  ui_footer("^", "Open", "v");
  drawMenu();
}

void setup() {
  auto cfg = M5.config();
  cfg.serial_baudrate = 115200;
  M5.begin(cfg);
  settings_load();
  M5.Display.setBrightness(gSet.bright);
  M5.Speaker.setVolume(90);
  body.setColorDepth(8);
  body.createSprite(SCR_W, BODY_H);
  leds_begin();
  ui_splash();
  sd_begin();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  showMenu();
}

void loop() {
  Key k = ui_tick();
  if (k == K_UP) {
    sel = (sel + MENU_N - 1) % MENU_N;
    drawMenu();
  } else if (k == K_DOWN) {
    sel = (sel + 1) % MENU_N;
    drawMenu();
  } else if (k == K_OK) {
    beep(1600, 25);
    MENU[sel].fn();
    leds_off();
    beep(1100, 25);
    showMenu();
  }
  delay(10);
}
