// Guard: passive detection of deauth floods, evil twins, karma APs and beacon spam
#include "common.h"

namespace {

struct ApSeen {
  uint8_t bssid[6];
  uint32_t hash;
  char ssid[33];
  bool priv;
  uint8_t ch;
  uint32_t first, last;
};
struct Karma {
  uint8_t bssid[6];
  uint32_t hashes[6];
  uint8_t n;
  uint32_t last;
};
struct Ev {
  uint32_t t;
  uint32_t color;
  char msg[52];
};

const int MAX_AP = 120, MAX_K = 16, MAX_EV = 6, MAX_KEYS = 16;
ApSeen* aps = nullptr;
int apN = 0;
Karma karma[MAX_K];
int kN = 0;
Ev evs[MAX_EV];
int evN = 0;
uint32_t alertKeys[MAX_KEYS], alertT[MAX_KEYS];
uint32_t lastAlert = 0;
char lastAlertMsg[52] = "";

uint32_t fnv(const char* s) {
  uint32_t h = 2166136261u;
  while (*s) h = (h ^ (uint8_t)*s++) * 16777619u;
  return h;
}

bool want(const FrameInfo& f) {
  return f.type == 0 && (f.sub == 8 || f.sub == 5 || f.sub == 12 || f.sub == 10);
}

void alert(uint32_t key, uint32_t color, const char* msg) {
  uint32_t now = millis();
  int slot = 0;
  for (int i = 0; i < MAX_KEYS; i++) {
    if (alertKeys[i] == key) {
      if (now - alertT[i] < 30000) return;  // de-dupe for 30 s
      slot = i;
      break;
    }
    if (alertT[i] < alertT[slot]) slot = i;
  }
  alertKeys[slot] = key;
  alertT[slot] = now;
  memmove(&evs[1], &evs[0], sizeof(Ev) * (MAX_EV - 1));
  evs[0].t = now;
  evs[0].color = color;
  strlcpy(evs[0].msg, msg, sizeof(evs[0].msg));
  if (evN < MAX_EV) evN++;
  if (color == col::bad) {
    lastAlert = now;
    strlcpy(lastAlertMsg, msg, sizeof(lastAlertMsg));
    leds_flash(0xFF0010, 1500);
    beep(880, 120);
    delay(10);
    beep(660, 160);
  } else {
    leds_flash(0xFFA000, 600);
    beep(1200, 60);
  }
  char line[96];
  snprintf(line, sizeof line, "%lu,%s", (unsigned long)(now / 1000), msg);
  sd_append("/guarddog/guard.csv", line);
}

ApSeen* findAp(const uint8_t* b) {
  for (int i = 0; i < apN; i++)
    if (!memcmp(aps[i].bssid, b, 6)) return &aps[i];
  return nullptr;
}

}  // namespace

void app_guard() {
  aps = (ApSeen*)calloc(MAX_AP, sizeof(ApSeen));
  if (!aps) return;
  apN = kN = evN = 0;
  lastAlert = 0;
  memset(alertKeys, 0, sizeof alertKeys);
  memset(alertT, 0, sizeof alertT);
  bool locked = false;
  uint32_t secT = millis(), deauthSec = 0, deauthRate = 0, newSsidWin = 0, winT = millis();
  uint8_t topSrc[6] = {0};
  uint8_t floodCh = 0;
  ui_header("Wi-Fi Threats", col::bad);
  ui_footer("", "Lock ch", "");
  sniff_start(1, want);
  sniff_hop(true, 300);
  leds_base(0x001A00);
  uint32_t lastDraw = 0;
  FrameInfo f;
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_OK) {
      locked = !locked;
      sniff_hop(!locked, 300);
      ui_footer(locked ? "ch -" : "", locked ? "Hop" : "Lock ch", locked ? "ch +" : "");
    }
    if (locked && (k == K_UP || k == K_DOWN)) {
      uint8_t c = sniff_cur_channel();
      sniff_channel(k == K_UP ? (c <= 1 ? 13 : c - 1) : (c >= 13 ? 1 : c + 1));
    }

    int budget = 40;
    while (budget-- > 0 && sniff_pop(f)) {
      uint32_t now = millis();
      if (f.sub == 12 || f.sub == 10) {
        deauthSec++;
        memcpy(topSrc, f.a2, 6);
        floodCh = f.ch;
        continue;
      }
      if (sig_is_pwnagotchi(f.a2)) alert(0x9A9A, col::bad, "Pwnagotchi nearby");
      if (f.ssidLen > 0) {
        SigHit hs = sig_ssid(f.ssid);
        if (hs.type == DT_HACKER) {
          char m[52];
          snprintf(m, sizeof m, "%s: \"%.20s\" ch%d", hs.label, f.ssid, f.apCh ? f.apCh : f.ch);
          alert(fnv(f.ssid) ^ 0x4A4A, col::bad, m);
        }
      }
      if (f.ssidLen <= 0) continue;
      uint32_t h = fnv(f.ssid);
      if (f.sub == 5) {  // probe response: karma check
        Karma* kk = nullptr;
        for (int i = 0; i < kN; i++)
          if (!memcmp(karma[i].bssid, f.a3, 6)) kk = &karma[i];
        if (!kk) {
          int slot = kN < MAX_K ? kN++ : 0;
          if (kN == MAX_K)
            for (int i = 1; i < MAX_K; i++)
              if (karma[i].last < karma[slot].last) slot = i;
          kk = &karma[slot];
          memset(kk, 0, sizeof(Karma));
          memcpy(kk->bssid, f.a3, 6);
        }
        kk->last = now;
        bool known = false;
        for (int i = 0; i < kk->n; i++)
          if (kk->hashes[i] == h) known = true;
        if (!known && kk->n < 6) kk->hashes[kk->n++] = h;
        if (kk->n >= 4) {
          char mac[18], m[52];
          fmt_mac(kk->bssid, mac);
          snprintf(m, sizeof m, "Karma AP %s (%d SSIDs)", mac, kk->n);
          alert(fnv(mac) ^ 0x4B, col::bad, m);
        }
      }
      // beacon / probe response AP table
      ApSeen* a = findAp(f.a3);
      if (!a) {
        newSsidWin++;
        int slot;
        if (apN < MAX_AP) slot = apN++;
        else {
          slot = 0;
          for (int i = 1; i < apN; i++)
            if (aps[i].last < aps[slot].last) slot = i;
        }
        a = &aps[slot];
        memcpy(a->bssid, f.a3, 6);
        a->first = now;
        // evil twin: same SSID, different BSSID, different security
        for (int i = 0; i < apN; i++) {
          ApSeen& o = aps[i];
          if (&o == a || o.hash != h || now - o.last > 120000) continue;
          if (o.priv != f.priv) {
            char m[52];
            snprintf(m, sizeof m, "Evil twin? \"%.20s\" open+secured", f.ssid);
            alert(h ^ 0xE7, col::bad, m);
            break;
          }
        }
      }
      a->hash = h;
      strlcpy(a->ssid, f.ssid, sizeof(a->ssid));
      a->priv = f.priv;
      a->ch = f.apCh ? f.apCh : f.ch;
      a->last = now;
    }

    if (millis() - secT >= 1000) {
      secT = millis();
      deauthRate = deauthSec;
      deauthSec = 0;
      if (deauthRate >= 10) {
        char mac[18], m[52];
        fmt_mac(topSrc, mac);
        snprintf(m, sizeof m, "Deauth flood ch%d %s (%lu/s)", floodCh, mac, (unsigned long)deauthRate);
        alert(fnv(mac) ^ 0xDE, col::bad, m);
      } else if (deauthRate >= 3) {
        char m[52];
        snprintf(m, sizeof m, "Deauths on ch%d (%lu/s)", floodCh, (unsigned long)deauthRate);
        alert(0xD0 + floodCh, col::warn, m);
      }
    }
    if (millis() - winT >= 10000) {
      if (newSsidWin >= 40 && millis() > 30000) {
        char m[52];
        snprintf(m, sizeof m, "Beacon spam: %lu new APs/10s", (unsigned long)newSsidWin);
        alert(0xBEAC, col::bad, m);
      }
      newSsidWin = 0;
      winT = millis();
    }

    if (millis() - lastDraw < 400) {
      delay(5);
      continue;
    }
    lastDraw = millis();
    bool hot = lastAlert && millis() - lastAlert < 20000;
    leds_base(hot ? 0x200000 : 0x001A00);

    body.fillScreen(col::bg);
    body.fillRoundRect(6, 4, SCR_W - 12, 46, 8, hot ? col::bad : col::panel);
    body.setFont(&fonts::FreeSansBold12pt7b);
    body.setTextDatum(middle_left);
    body.setTextColor(hot ? col::text : col::good);
    if (hot) {
      body.setFont(&fonts::FreeSansBold9pt7b);
      draw_fit(lastAlertMsg, 16, 27, SCR_W - 32);
    } else {
      body.drawString("ALL CLEAR", 16, 27);
    }
    ui_smallfont();
    body.setTextDatum(top_left);
    body.setTextColor(col::dim);
    char b[64];
    snprintf(b, sizeof b, "%s %d   APs %d   deauth %lu/s", locked ? "LOCK" : "hop", sniff_cur_channel(), apN,
             (unsigned long)deauthRate);
    body.drawString(b, 8, 56);
    body.drawFastHLine(6, 78, SCR_W - 12, col::line);
    if (!evN) {
      body.setTextColor(col::dim);
      body.drawString("No events yet. Watching all channels.", 8, 88);
    }
    for (int i = 0; i < evN; i++) {
      int y = 84 + i * 21;
      char age[12];
      fmt_age(millis() - evs[i].t, age);
      body.fillCircle(12, y + 9, 4, evs[i].color);
      body.setTextColor(col::text);
      draw_fit(evs[i].msg, 22, y, SCR_W - 70);
      body.setTextDatum(top_right);
      body.setTextColor(col::dim);
      body.drawString(age, SCR_W - 8, y);
      body.setTextDatum(top_left);
    }
    ui_push();
  }
  sniff_stop();
  leds_off();
  free(aps);
  aps = nullptr;
}
