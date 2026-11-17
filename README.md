# Guard Dog

67SASQUATCH wireless recon firmware for the **M5Stack Fire** (also runs on M5Stack Core Basic/Gray).
Receive-only: nothing in this firmware transmits deauth, beacon or probe frames.

## Apps

| App | What it does |
|---|---|
| Detector | One screen for everything nearby that watches, tracks or attacks: Flock ALPR / Penguin, Raven + ShotSpotter, Axon / WatchGuard / Digital Ally body cams, Motorola + Genetec ALPR, Meta / Snap / Vuzix camera glasses, card-skimmer BT modules, drones (ASTM F3411 Remote ID over Wi-Fi beacon + BLE, decoded to UAS ID, drone position/altitude/speed and pilot position; DJI/Skydio/Parrot by MAC), FindMy / Tile / SmartTag / Google Find Hub tags, hacker gear (Flipper Zero, Pwnagotchi, WiFi Pineapple, ESP deauthers), optional Ring and pro/home cameras. Each signature carries Low/Med/High confidence. Full-screen alerts (Ignore / OK / Snooze 30 min), auto-snooze (after 3 alerts a device must come 7 dB closer), hunt mode (live dBm, warmer/colder, Geiger beeps). Logs to `/guarddog/detect.csv`. |
| Wi-Fi Survey | Live AP list sorted by signal. Detail view: BSSID (flags randomized MACs), channel, RSSI, auth, pairwise/group cipher, PHY b/g/n/LR, WPS, country. Color bar: red = open/WEP, yellow = WPS/WPA1/TKIP, green = fine. |
| Channel Map | AP count per 2.4 GHz channel, colored by strongest signal, with an overlap-weighted pick among 1/6/11. |
| BLE Scanner | Nearby BLE devices with vendor tags; Apple FindMy (AirTag), Tile and Samsung SmartTag flagged on top. |
| Packet Monitor | Per-channel packets/s graph (deauths in red), beacon/probe/data counts, EAPOL counter (LED flashes blue on handshake frames), PCAP recording to SD. |
| Wi-Fi Threats | Channel-hopping watch for deauth/disassoc floods, evil twins (same SSID seen open and secured), karma/pineapple APs (one BSSID answering 4+ SSIDs), beacon spam, Pwnagotchis, WiFi Pineapple and ESP-deauther SSIDs. Logs to `/guarddog/guard.csv`. |
| Settings | Brightness, sound, LED bar, large text, alert level (All / Med+ / High only), detection type on/off, SD status, battery, free RAM. |

## Controls

- **A** (left): up / previous · **C** (right): down / next (hold to scroll)
- **B** (middle) click: select / action · **hold B**: back

## Flashing

Easiest: open the GitHub Pages flasher for this repo in desktop Chrome/Edge and click **Install**.

Manual:

```
esptool.py --chip esp32 --baud 921600 write_flash 0x0 guarddog.bin
```

`guarddog.bin` is a merged image (bootloader + partitions + app), so it goes at offset `0x0`.
To return to stock, flash the factory firmware from M5Burner.

## Building

```
pip install platformio
pio run -e m5stack            # build
pio run -e m5stack -t upload  # flash over USB
```

GitHub Actions builds on every push to `main`, uploads the merged image as an artifact and publishes the web flasher to GitHub Pages.

## SD card

FAT32 microSD. Files go in `/guarddog/`:
- `cap_NNNN.pcap` — 802.11 captures (linktype 105), open in Wireshark
- `guard.csv` — Wi-Fi Threats alerts
- `detect.csv` — Detector sightings (`uptime_s,source,type,match,id,rssi,name,lat,lon`)

## Notes and limits

- The ESP32 is 2.4 GHz only. 5 GHz networks and 5 GHz Flock radios are invisible to it.
- Most Flock prefixes belong to radio-module vendors, so a prefix alone is Low confidence and won't pop an alert at the default Med+ level. Espressif and Samsung blocks are excluded so ordinary ESP32 gadgets and Samsung TVs don't read as Flock cameras.
- Ring and home/pro camera detection is off by default (they're on every street). Turn them on under Settings > Detect types.
- Remote ID over Bluetooth 5 long range and Wi-Fi NAN isn't decoded (the classic ESP32 can't receive BLE extended advertising); Wi-Fi beacon and BLE 4 legacy Remote ID are.
- PCAP capture and handshake counting are for networks you own or are authorized to test.

## Credits

Flock/Raven signatures from [colonelpanichacks/flock-you](https://github.com/colonelpanichacks/flock-you) (MIT), with OUI research from @NitekryDPaul and DeFlockJoplin. Additional prefix/UUID/company-ID research (IEEE-registry-checked) from [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD); signature facts only, no code.
