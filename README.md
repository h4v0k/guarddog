# Guard Dog

67SASQUATCH wireless recon firmware for the **M5Stack Fire** (also runs on M5Stack Core Basic/Gray).
Receive-only: nothing in this firmware transmits deauth, beacon or probe frames.

## Apps

| App | What it does |
|---|---|
| Wi-Fi Survey | Live AP list sorted by signal. Detail view: BSSID (flags randomized MACs), channel, RSSI, auth, pairwise/group cipher, PHY b/g/n/LR, WPS, country. Color bar: red = open/WEP, yellow = WPS/WPA1/TKIP, green = fine. |
| Channel Map | AP count per 2.4 GHz channel, colored by strongest signal, with an overlap-weighted pick among 1/6/11. |
| BLE Scanner | Nearby BLE devices with vendor tags; Apple FindMy (AirTag), Tile and Samsung SmartTag flagged on top. |
| Packet Monitor | Per-channel packets/s graph (deauths in red), beacon/probe/data counts, EAPOL counter (LED flashes blue on handshake frames), PCAP recording to SD. |
| Wi-Fi Threats | Channel-hopping watch for deauth/disassoc floods, evil twins (same SSID seen open and secured), karma/pineapple APs (one BSSID answering 4+ SSIDs) and beacon spam. Logs to `/guarddog/guard.csv`. |
| Flock Detector | Flock Safety ALPR cameras, Penguin battery packs and Raven sensors via Wi-Fi OUI + wildcard-probe behaviour + SSID keywords, plus BLE names, manufacturer ID 0x09C8 and GATT UUIDs. Geiger-style beeping speeds up as signal gets stronger. Logs to `/guarddog/flock.csv`. |
| Settings | Brightness, sound, LED bar, large text, SD status, battery, free RAM. |

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
- `flock.csv` — Flock detections (`uptime_s,source,id,method,score,rssi,ssid`)

## Notes and limits

- The ESP32 is 2.4 GHz only. 5 GHz networks and 5 GHz Flock radios are invisible to it.
- Flock OUI list includes generic Espressif/Qualcomm prefixes; an OUI hit alone is shown as a weak (yellow) hit and doesn't trigger the alarm. Strong hits need the Flock-owned OUI, a matching SSID, a wildcard probe from a listed OUI, or a BLE signature.
- PCAP capture and handshake counting are for networks you own or are authorized to test.

## Credits

Flock/Raven signatures from [colonelpanichacks/flock-you](https://github.com/colonelpanichacks/flock-you) (MIT), with OUI research from @NitekryDPaul and DeFlockJoplin.
