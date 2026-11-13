# CYD Emergency Scanner

Passive BLE + Wi-Fi scanner firmware (police, EMS, fire, emergency-vehicle gear) for the ESP32-2432S028R ("Cheap Yellow Display"), plus a browser-based USB flasher.

## Get the web flasher live (about 5 minutes, free)
1. Create a new GitHub repo and push this folder to the `main` branch.
2. In the repo, go to **Settings → Pages → Source** and choose **GitHub Actions**.
3. The workflow compiles the firmware, packs it into one `.bin` and publishes `web/` to
   `https://<you>.github.io/<repo>/`.
4. Open that URL in desktop Chrome or Edge, plug in the CYD and click **Flash to my CYD**.

## Build locally instead
```
pip install platformio
pio run -e cyd -t upload      # single USB (use -e cyd2usb for dual USB)
pio device monitor            # view HIT,... lines
```

## Add detection rules
Edit the `RULES` table at the top of `src/main.cpp`. Each rule sets source (BLE/Wi-Fi/any), MAC prefix or name keyword, label and category.
Use Survey view (tap BOOT) to discover the real SSIDs and device names around you.

## Notes
- Receive-only. BLE and Wi-Fi both scan passively, with no scan or probe requests, and it never connects or spoofs.
- Two builds: `cyd` (single micro-USB) and `cyd2usb` (USB-C + micro-USB, inverted colours).
  Pick yours from the dropdown on the flasher page. If the colours look wrong, flash the other one.
- If the Dual USB screen stays blank, your board may use an ST7789 panel. In `platformio.ini`, change
  `-DILI9341_2_DRIVER=1` to `-DST7789_DRIVER=1`.
