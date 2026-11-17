// Packet Monitor: per-channel traffic graph, deauth + EAPOL counters, PCAP to SD
#include "common.h"

void app_monitor() {
  uint8_t ch = 1;
  const int N = 64;
  uint32_t hist[N] = {0}, dhist[N] = {0};
  int hi = 0;
  uint32_t lastP = 0, lastD = 0, lastE = 0, lastS = millis();
  uint32_t pps = 0;
  ui_header("Packet Monitor", col::good);
  ui_footer("ch -", "Record", "ch +");
  sniff_start(ch, nullptr);
  leds_base(0x001808);
  bool dirty = true;
  while (true) {
    Key k = ui_tick();
    if (k == K_BACK) break;
    if (k == K_UP || k == K_DOWN) {
      ch = k == K_UP ? (ch <= 1 ? 13 : ch - 1) : (ch >= 13 ? 1 : ch + 1);
      sniff_channel(ch);
      sniff_reset_stats();
      memset(hist, 0, sizeof hist);
      memset(dhist, 0, sizeof dhist);
      lastP = lastD = lastE = 0;
      dirty = true;
    }
    if (k == K_OK) {
      if (pcap_active()) {
        pcap_stop();
        ui_footer("ch -", "Record", "ch +");
        ui_toast("PCAP saved", col::good);
        ui_header("Packet Monitor", col::good);
      } else if (!gSdOk) {
        ui_toast("No SD card", col::bad);
        ui_header("Packet Monitor", col::good);
      } else if (pcap_start()) {
        ui_footer("ch -", "Stop", "ch +");
        beep(1500, 40);
      } else {
        ui_toast("SD write failed", col::bad);
        ui_header("Packet Monitor", col::good);
      }
      dirty = true;
    }
    if (gStats.eapol != lastE) {
      lastE = gStats.eapol;
      leds_flash(0x2060FF, 400);
      beep(2600, 30);
    }
    if (millis() - lastS >= 500) {
      lastS = millis();
      uint32_t p = gStats.pkts, d = gStats.deauth + gStats.disassoc;
      pps = (p - lastP) * 2;
      hist[hi] = (p - lastP) * 2;
      dhist[hi] = (d - lastD) * 2;
      if (d != lastD) leds_flash(0xFF0010, 250);
      hi = (hi + 1) % N;
      lastP = p;
      lastD = d;
      dirty = true;
    }
    if (!dirty) {
      delay(5);
      continue;
    }
    dirty = false;

    body.fillScreen(col::bg);
    // graph
    const int gx = 0, gy = 4, gw = 320, gh = 86, bw = gw / N;
    uint32_t mx = 20;
    for (int i = 0; i < N; i++) mx = max<uint32_t>(mx, hist[i]);
    body.fillRect(gx, gy, gw, gh, col::panel);
    for (int i = 0; i < N; i++) {
      int idx = (hi + i) % N;
      int h = hist[idx] * gh / mx;
      int hd = min<int>(gh, (int)(dhist[idx] * gh / mx));
      if (h) body.fillRect(gx + i * bw, gy + gh - h, bw - 1, h, col::good);
      if (hd) body.fillRect(gx + i * bw, gy + gh - hd, bw - 1, hd, col::bad);
    }
    char b[64];
    body.setFont(&fonts::Font2);
    body.setTextDatum(top_right);
    body.setTextColor(col::dim);
    snprintf(b, sizeof b, "max %lu/s", (unsigned long)mx);
    body.drawString(b, SCR_W - 4, gy + 2);

    // stats
    int y = gy + gh + 6;
    body.setFont(&fonts::FreeSansBold12pt7b);
    body.setTextDatum(top_left);
    body.setTextColor(col::accent);
    snprintf(b, sizeof b, "CH %d", ch);
    body.drawString(b, 8, y);
    body.setTextColor(col::text);
    snprintf(b, sizeof b, "%lu pkt/s", (unsigned long)pps);
    body.setTextDatum(top_right);
    body.drawString(b, SCR_W - 8, y);
    y += 30;
    ui_smallfont();
    body.setTextDatum(top_left);
    body.setTextColor(col::dim);
    snprintf(b, sizeof b, "Beacon %lu   Probe %lu   Data %lu", (unsigned long)gStats.beacons,
             (unsigned long)gStats.probes, (unsigned long)gStats.data);
    body.drawString(b, 8, y);
    y += 21;
    body.setTextColor(gStats.deauth + gStats.disassoc ? col::bad : col::dim);
    snprintf(b, sizeof b, "Deauth %lu", (unsigned long)(gStats.deauth + gStats.disassoc));
    body.drawString(b, 8, y);
    body.setTextColor(gStats.eapol ? col::info : col::dim);
    snprintf(b, sizeof b, "EAPOL %lu%s", (unsigned long)gStats.eapol, gStats.eapol >= 2 ? "  handshake?" : "");
    body.drawString(b, 130, y);
    y += 21;
    if (pcap_active()) {
      body.fillCircle(14, y + 8, 6, (millis() / 500) % 2 ? col::bad : col::panel);
      body.setTextColor(col::text);
      snprintf(b, sizeof b, "%s  %lu KB%s", pcap_name(), (unsigned long)(pcap_bytes() / 1024),
               pcap_drops() ? "  (drops)" : "");
      body.drawString(b, 26, y);
    } else {
      body.setTextColor(col::dim);
      body.drawString(gSdOk ? "PCAP off - press Record" : "PCAP off - no SD card", 8, y);
    }
    ui_push();
  }
  sniff_stop();
  leds_off();
}
