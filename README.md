# PHANTOM — CYD passive RF scanner

Touchscreen, dark-neon firmware for the ESP32-2432S028R ("Cheap Yellow Display"), plus a browser USB flasher.

Home launcher you swipe through, with apps:
- **Scanner** — police / ambulance / fire / fleet-vehicle gear
- **Wi-Fi** — every access point + rogue / evil-twin / deauth-attack detection
- **Bluetooth** — live map of nearby BLE devices
- **Trackers** — AirTag / Tile / SmartTag detection, flags one that follows you
- **Settings** — sound, brightness, accent colour, clear, about

## Receive-only
PHANTOM only listens. BLE and Wi-Fi scan passively; the Wi-Fi radio is put in
promiscuous mode solely to **count** deauth/disassoc frames for the detector.
There is no deauth, jamming, beacon or BLE spam, and it never connects or spoofs.

## Put the flasher online (free)
1. Push this folder to a GitHub repo's `main` branch.
2. Settings → Pages → Source → **GitHub Actions**.
3. It builds both board images and publishes `web/` to `https://<you>.github.io/<repo>/`.
4. Open that in desktop Chrome/Edge, pick your board, Connect & Flash.

## Build locally
```
pip install platformio
pio run -e cyd -t upload       # single USB  (-e cyd2usb for dual USB)
pio device monitor
```

## Notes
- Two builds: `cyd` (single micro-USB) and `cyd2usb` (dual USB, inverted colours). If colours look wrong, flash the other.
- Touch off? Tweak `T_MINX`..`T_MAXY` at the top of `src/main.cpp`.
- Add detection rules in the `RULES` table in `src/main.cpp`.
