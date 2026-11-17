// Promiscuous-mode engine shared by Packet Monitor, Guard and Flock Detector.
// Passive receive only: this firmware never transmits management frames.
#include "common.h"
#include "freertos/queue.h"

SniffStats gStats;

static QueueHandle_t q = nullptr;
static volatile FrameFilter gFilter = nullptr;
static bool running = false;
static uint8_t curCh = 1;
static bool hopping = false;
static uint16_t dwell = 250;
static uint32_t lastHop = 0;

// ---------------- PCAP ring ----------------
#define PCAP_SNAP 512
#define RING_N 24
struct Slot {
  uint32_t sec, usec;
  uint16_t len, orig;
  uint8_t d[PCAP_SNAP];
};
static Slot* ring = nullptr;
static volatile uint16_t rHead = 0, rTail = 0;
static volatile bool pcapOn = false;
static File pcapFile;
static char pcapFileName[32] = "";
static uint32_t pcapBytesW = 0, lastFlush = 0;
static volatile uint32_t pcapDropN = 0;

static inline bool isEapol(const uint8_t* p, int len) {
  uint8_t fc1 = p[1];
  if (fc1 & 0x40) return false;  // protected
  int hdr = 24;
  if ((fc1 & 0x03) == 0x03) hdr += 6;  // 4-address
  if ((p[0] >> 4) & 0x08) hdr += 2;    // QoS
  if (len < hdr + 8) return false;
  const uint8_t* l = p + hdr;
  return l[0] == 0xAA && l[1] == 0xAA && l[2] == 0x03 && l[6] == 0x88 && l[7] == 0x8E;
}

static bool parseFrame(const uint8_t* p, int len, FrameInfo& f) {
  if (len < 24) return false;
  f.type = (p[0] >> 2) & 3;
  f.sub = (p[0] >> 4) & 0xF;
  if (f.type == 1) return false;  // control frames: no addr2/addr3 guaranteed
  memcpy(f.a1, p + 4, 6);
  memcpy(f.a2, p + 10, 6);
  memcpy(f.a3, p + 16, 6);
  f.ssid[0] = 0;
  f.ssidLen = -1;
  f.apCh = 0;
  f.priv = false;
  if (f.type != 0) return true;
  int ie = -1;
  if (f.sub == 8 || f.sub == 5) {  // beacon / probe response
    if (len < 36) return true;
    f.priv = p[34] & 0x10;
    ie = 36;
  } else if (f.sub == 4) {  // probe request
    ie = 24;
  }
  if (ie < 0) return true;
  while (ie + 2 <= len) {
    uint8_t id = p[ie], l = p[ie + 1];
    if (ie + 2 + l > len) break;
    if (id == 0 && f.ssidLen < 0) {
      int n = l > 32 ? 32 : l;
      if (n > 0 && p[ie + 2] == 0) n = 0;  // null-padded hidden SSID
      memcpy(f.ssid, p + ie + 2, n);
      f.ssid[n] = 0;
      for (int i = 0; i < n; i++)
        if ((uint8_t)f.ssid[i] < 0x20) f.ssid[i] = '?';
      f.ssidLen = n;
    } else if (id == 3 && l == 1) {
      f.apCh = p[ie + 2];
    }
    ie += 2 + l;
  }
  return true;
}

static void rxCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  auto* pkt = (wifi_promiscuous_pkt_t*)buf;
  int len = pkt->rx_ctrl.sig_len;
  if (len > 4) len -= 4;  // strip FCS
  if (len < 10) return;
  const uint8_t* p = pkt->payload;
  gStats.pkts++;
  uint8_t ft = (p[0] >> 2) & 3, st = (p[0] >> 4) & 0xF;
  if (ft == 0) {
    gStats.mgmt++;
    if (st == 8) gStats.beacons++;
    else if (st == 4) gStats.probes++;
    else if (st == 12) gStats.deauth++;
    else if (st == 10) gStats.disassoc++;
  } else if (ft == 2) {
    gStats.data++;
    if (len >= 32 && isEapol(p, len)) gStats.eapol++;
  }

  if (pcapOn && ring) {
    uint16_t next = (rHead + 1) % RING_N;
    if (next == rTail) {
      pcapDropN++;
    } else {
      Slot& s = ring[rHead];
      int64_t t = esp_timer_get_time();
      s.sec = (uint32_t)(t / 1000000);
      s.usec = (uint32_t)(t % 1000000);
      s.orig = len;
      s.len = len > PCAP_SNAP ? PCAP_SNAP : len;
      memcpy(s.d, p, s.len);
      rHead = next;
    }
  }

  FrameFilter flt = gFilter;
  if (q && flt) {
    FrameInfo f;
    if (parseFrame(p, len, f)) {
      f.rssi = pkt->rx_ctrl.rssi;
      f.ch = pkt->rx_ctrl.channel;
      if (flt(f)) xQueueSend(q, &f, 0);
    }
  }
}

void sniff_reset_stats() { memset((void*)&gStats, 0, sizeof(gStats)); }

void sniff_start(uint8_t ch, FrameFilter filter) {
  if (!q) q = xQueueCreate(48, sizeof(FrameInfo));
  xQueueReset(q);
  sniff_reset_stats();
  gFilter = filter;
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(false);
  wifi_promiscuous_filter_t flt;
  flt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&flt);
  esp_wifi_set_promiscuous_rx_cb(&rxCb);
  esp_wifi_set_promiscuous(true);
  hopping = false;
  running = true;
  sniff_channel(ch);
}

void sniff_stop() {
  pcap_stop();
  esp_wifi_set_promiscuous(false);
  gFilter = nullptr;
  running = false;
  hopping = false;
  if (q) xQueueReset(q);
}

void sniff_channel(uint8_t ch) {
  if (ch < 1) ch = 13;
  if (ch > 13) ch = 1;
  curCh = ch;
  esp_wifi_set_channel(curCh, WIFI_SECOND_CHAN_NONE);
}

void sniff_hop(bool on, uint16_t ms) {
  hopping = on;
  dwell = ms;
  lastHop = millis();
}

uint8_t sniff_cur_channel() { return curCh; }

bool sniff_pop(FrameInfo& f) { return q && xQueueReceive(q, &f, 0) == pdTRUE; }

// ---------------- PCAP file ----------------
bool pcap_start() {
  if (!gSdOk || pcapOn) return false;
  if (!ring) ring = (Slot*)malloc(sizeof(Slot) * RING_N);
  if (!ring) return false;
  for (int i = 1; i < 10000; i++) {
    snprintf(pcapFileName, sizeof(pcapFileName), "/guarddog/cap_%04d.pcap", i);
    if (!SD.exists(pcapFileName)) break;
  }
  pcapFile = SD.open(pcapFileName, FILE_WRITE);
  if (!pcapFile) return false;
  struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t vmaj, vmin;
    int32_t zone;
    uint32_t sigfigs, snap, net;
  } gh = {0xa1b2c3d4, 2, 4, 0, 0, PCAP_SNAP, 105};  // 105 = IEEE 802.11
  pcapFile.write((const uint8_t*)&gh, sizeof(gh));
  pcapBytesW = sizeof(gh);
  pcapDropN = 0;
  rHead = rTail = 0;
  lastFlush = millis();
  pcapOn = true;
  return true;
}

static void pcap_drain() {
  int n = 0;
  while (rTail != rHead && n++ < 16) {
    Slot& s = ring[rTail];
    uint32_t rh[4] = {s.sec, s.usec, s.len, s.orig};
    pcapFile.write((const uint8_t*)rh, sizeof(rh));
    pcapFile.write(s.d, s.len);
    pcapBytesW += sizeof(rh) + s.len;
    rTail = (rTail + 1) % RING_N;
  }
  if (millis() - lastFlush > 2000) {
    lastFlush = millis();
    pcapFile.flush();
  }
}

void pcap_stop() {
  if (!pcapOn) return;
  pcapOn = false;
  delay(5);
  pcap_drain();
  pcapFile.close();
}

bool pcap_active() { return pcapOn; }
const char* pcap_name() { return pcapFileName[0] ? pcapFileName + 10 : ""; }  // strip "/guarddog/"
uint32_t pcap_bytes() { return pcapBytesW; }
uint32_t pcap_drops() { return pcapDropN; }

void sniff_tick() {
  if (!running) return;
  if (hopping && millis() - lastHop >= dwell) {
    lastHop = millis();
    sniff_channel(curCh % 13 + 1);
  }
  if (pcapOn) pcap_drain();
}
