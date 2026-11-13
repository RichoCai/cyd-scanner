/*
 * PHANTOM  v3.0
 * Passive RF scanner + recon for the ESP32-2432S028R "Cheap Yellow Display".
 * Touchscreen, swipeable home launcher, dark neon UI.
 *
 * RECEIVE-ONLY. Bluetooth LE and Wi-Fi both scan passively (no scan requests,
 * no probe requests). PHANTOM never transmits attacks: no deauth, no jamming,
 * no beacon/BLE spam. It connects to, pairs with and spoofs nothing.
 *
 * Apps (tap a tile on the home screen, drag to scroll, tap "<" to go back):
 *   SCANNER  - emergency gear: police / ambulance / fire / fleet vehicles
 *   WIFI     - every access point: SSID, channel, signal, lock, + rogue/evil-twin
 *              and deauth-attack detection (defensive: spots attacks on you)
 *   BLUETOOTH- every BLE device around you
 *   TRACKERS - AirTag / Tile / SmartTag detection, flags one that follows you
 *   SETTINGS - sound, brightness, accent colour, clear, about
 */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <XPT2046_Touchscreen.h>
#include <NimBLEDevice.h>
#include <TFT_eSPI.h>

// ---------- CYD hardware ----------
#define LED_R 4
#define LED_G 16
#define LED_B 17
#define SPEAKER 26
#define BTN_BOOT 0
// resistive touch (XPT2046) on its own SPI bus
#define T_CLK 25
#define T_CS  33
#define T_MOSI 32
#define T_MISO 39
#define T_IRQ 36
// touch raw -> screen calibration (tweak in Settings > About if off)
#define T_MINX 200
#define T_MAXX 3700
#define T_MINY 240
#define T_MAXY 3800

// ======================================================================
//  Detection rules (emergency scanner)
// ======================================================================
enum Cat : uint8_t { CAT_POLICE = 0, CAT_EMS, CAT_FIRE, CAT_VEHICLE, CAT_COUNT };
enum Src : uint8_t { S_BLE = 1, S_WIFI = 2, S_ANY = 3 };
enum Kind : uint8_t { BY_MAC, BY_NAME };
struct Rule { uint8_t src; uint8_t kind; const char *pattern; const char *label; uint8_t cat; };

static const Rule RULES[] = {
  {S_ANY,  BY_MAC,  "00:25:df",     "Axon device",        CAT_POLICE},
  {S_ANY,  BY_NAME, "axon",         "Axon",               CAT_POLICE},
  {S_BLE,  BY_NAME, "body 3",       "Axon Body 3",        CAT_POLICE},
  {S_BLE,  BY_NAME, "body 4",       "Axon Body 4",        CAT_POLICE},
  {S_ANY,  BY_NAME, "fleet 3",      "Axon Fleet in-car",  CAT_POLICE},
  {S_ANY,  BY_NAME, "watchguard",   "WatchGuard cam",     CAT_POLICE},
  {S_ANY,  BY_NAME, "apx",          "Motorola APX radio", CAT_POLICE},
  {S_ANY,  BY_NAME, "police",       "Police network",     CAT_POLICE},
  {S_ANY,  BY_NAME, "ambulance",    "Ambulance",          CAT_EMS},
  {S_ANY,  BY_NAME, "paramedic",    "Paramedic",          CAT_EMS},
  {S_ANY,  BY_NAME, "st john",      "St John",            CAT_EMS},
  {S_ANY,  BY_NAME, "sjwa",         "St John WA",         CAT_EMS},
  {S_ANY,  BY_NAME, "lifepak",      "LIFEPAK monitor",    CAT_EMS},
  {S_ANY,  BY_NAME, "zoll",         "ZOLL monitor",       CAT_EMS},
  {S_ANY,  BY_NAME, "dfes",         "DFES",               CAT_FIRE},
  {S_ANY,  BY_NAME, "fire rescue",  "Fire & Rescue",      CAT_FIRE},
  {S_ANY,  BY_NAME, "fire brigade", "Fire brigade",       CAT_FIRE},
  {S_WIFI, BY_NAME, "ses ",         "SES",                CAT_FIRE},
  {S_WIFI, BY_MAC,  "00:30:44",     "Cradlepoint router", CAT_VEHICLE},
  {S_WIFI, BY_NAME, "cradlepoint",  "Cradlepoint router", CAT_VEHICLE},
  {S_WIFI, BY_NAME, "airlink",      "Sierra AirLink",     CAT_VEHICLE},
  {S_WIFI, BY_NAME, "pepwave",      "Peplink router",     CAT_VEHICLE},
  {S_ANY,  BY_NAME, "toughbook",    "Toughbook MDT",      CAT_VEHICLE},
  {S_ANY,  BY_NAME, "getac",        "Getac MDT",          CAT_VEHICLE},
};
static const char *CAT_TILE[CAT_COUNT] = {"Police", "Ambulance", "Fire", "Vehicle"};

// ======================================================================
//  Palette (RGB565) - dark neon
// ======================================================================
#define C_BG     0x0841   // near black
#define C_PANEL  0x1082   // #101418
#define C_PANEL2 0x18E3
#define C_LINE   0x2104
#define C_TXT    0xFFFF
#define C_MUTED  0x7BCF
#define C_DIM    0x4208
#define C_RED    0xF949
#define C_AMBER  0xFD20
#define C_BLUE   0x3D3F
// scanner category colours
static const uint16_t CAT_COL[CAT_COUNT] = {0x3D3F, 0xFFFF, 0xFB80, 0xFD20};
// accent themes (neon)
static const uint16_t ACCENTS[] = {0x2FEB /*green*/, 0x05FF /*cyan*/, 0xF81F /*magenta*/, 0xFD20 /*amber*/};
static const char *ACCENT_NAME[] = {"Phantom Green", "Ice Cyan", "Magenta", "Amber"};
static uint8_t accentIdx = 0;
#define ACC (ACCENTS[accentIdx])

// ======================================================================
//  Device table (shared by all apps)
// ======================================================================
enum Trk : uint8_t { T_NONE = 0, T_AIRTAG, T_FINDMY, T_TILE, T_SMARTTAG };
struct Dev {
  char mac[18]; char name[26];
  char src;          // 'B' ble, 'W' wifi
  int rssi;
  uint8_t chan;      // wifi channel
  uint8_t enc;       // wifi: 0 open else locked
  uint8_t tracker;   // Trk
  uint8_t cat;       // emergency cat or 255
  bool evilTwin;     // wifi: same SSID seen on 2+ BSSIDs
  uint32_t firstSeen, lastSeen;
};
static const int MAX_DEV = 96;
static Dev dev[MAX_DEV];
static int devCount = 0;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t lastBleMs = 0, lastWifiMs = 0;
static volatile int pendingAlert = -1;
static uint32_t alertUntil = 0; static uint8_t alertCat = 0;

// deauth / attack detector (promiscuous sniff of mgmt frames)
static volatile uint32_t deauthCount = 0, deauthWindow = 0;
static volatile uint32_t lastDeauthMs = 0;

// settings
static bool soundOn = true;
static uint8_t brightness = 230;

TFT_eSPI tft;
TFT_eSprite spr(&tft);
SPIClass tsSPI(VSPI);
XPT2046_Touchscreen ts(T_CS, T_IRQ);
NimBLEScan *bleScan;

// ======================================================================
//  Helpers
// ======================================================================
static void lowerCopy(char *d, const char *s, size_t n) {
  size_t i = 0; for (; s[i] && i < n - 1; i++) d[i] = tolower((uint8_t)s[i]); d[i] = 0;
}
static const Rule *matchRule(char src, const char *macL, const char *name) {
  char low[40]; lowerCopy(low, name, sizeof(low));
  uint8_t s = src == 'B' ? S_BLE : S_WIFI;
  for (auto &r : RULES) {
    if (!(r.src & s)) continue;
    if (r.kind == BY_MAC) { if (!strncmp(macL, r.pattern, strlen(r.pattern))) return &r; }
    else if (low[0] && strstr(low, r.pattern)) return &r;
  }
  return nullptr;
}
static int findDev(const char *macL) {
  for (int i = 0; i < devCount; i++) if (!strcmp(dev[i].mac, macL)) return i;
  return -1;
}
static int newDevSlot() {
  if (devCount < MAX_DEV) return devCount++;
  int s = 0; for (int i = 1; i < MAX_DEV; i++) if (dev[i].lastSeen < dev[s].lastSeen) s = i;
  return s;
}

static uint8_t classifyTracker(NimBLEAdvertisedDevice *d) {
  if (d->haveManufacturerData()) {
    std::string m = d->getManufacturerData();
    if (m.size() >= 3 && (uint8_t)m[0] == 0x4C && (uint8_t)m[1] == 0x00) {
      uint8_t t = (uint8_t)m[2];
      if (t == 0x12) return T_AIRTAG;     // offline-finding / AirTag
      if (t == 0x07) return T_FINDMY;     // nearby Find My accessory
    }
  }
  for (int i = 0; i < d->getServiceUUIDCount(); i++) {
    NimBLEUUID u = d->getServiceUUID(i);
    if (u == NimBLEUUID((uint16_t)0xFEED)) return T_TILE;
    if (u == NimBLEUUID((uint16_t)0xFD5A)) return T_SMARTTAG;  // Samsung
    if (u == NimBLEUUID((uint16_t)0xFD59)) return T_SMARTTAG;
  }
  return T_NONE;
}

static void observe(char src, const char *mac, const char *name, int rssi,
                    uint8_t chan, uint8_t enc, uint8_t trk) {
  char macL[18]; lowerCopy(macL, mac, sizeof(macL));
  uint32_t now = millis();
  const Rule *r = matchRule(src, macL, name);
  bool isNew = false;
  portENTER_CRITICAL(&mux);
  int i = findDev(macL);
  if (i < 0) { i = newDevSlot(); Dev &d = dev[i];
    memset(&d, 0, sizeof(d));
    strlcpy(d.mac, macL, sizeof(d.mac));
    d.firstSeen = now; d.cat = r ? r->cat : 255;
    isNew = r != nullptr;
  }
  Dev &d = dev[i];
  if (name[0]) strlcpy(d.name, name, sizeof(d.name));
  d.src = src; d.rssi = rssi; d.chan = chan; d.enc = enc; d.lastSeen = now;
  if (trk) d.tracker = trk;
  if (r) d.cat = r->cat;
  // evil-twin: same SSID on a different BSSID
  if (src == 'W' && name[0]) {
    for (int k = 0; k < devCount; k++)
      if (k != i && dev[k].src == 'W' && !strcmp(dev[k].name, name) && strcmp(dev[k].mac, macL)) {
        d.evilTwin = true; dev[k].evilTwin = true;
      }
  }
  if (isNew && (pendingAlert < 0 || r->cat < pendingAlert)) pendingAlert = r->cat;
  portEXIT_CRITICAL(&mux);
}

class BleCB : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice *d) override {
    lastBleMs = millis();
    std::string mac = d->getAddress().toString();
    std::string name = d->haveName() ? d->getName() : "";
    observe('B', mac.c_str(), name.c_str(), d->getRSSI(), 0, 0, classifyTracker(d));
  }
};

static void wifiScanStep() {
  static uint32_t started = 0;
  int n = WiFi.scanComplete();
  if (n >= 0) {
    lastWifiMs = millis();
    for (int i = 0; i < n; i++)
      observe('W', WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i),
              WiFi.channel(i), WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? 0 : 1, 0);
    WiFi.scanDelete();
    started = 0;
  } else if (n == WIFI_SCAN_FAILED && millis() - started > 5000) {
    started = millis();
    WiFi.scanNetworks(true, true, true, 110);   // async, hidden, PASSIVE
  }
}

// ---- deauth-attack detector (defensive) ----
// A promiscuous sniffer that only COUNTS deauth/disassoc frames. It never sends.
static void IRAM_ATTR promiscCB(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  const wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;
  uint8_t sub = (p->payload[0] >> 4) & 0xF;        // frame subtype
  if (sub == 0x0C || sub == 0x0A) { deauthCount++; lastDeauthMs = millis(); }  // deauth / disassoc
}

// ======================================================================
//  LED + sound
// ======================================================================
static void setLed(bool r, bool g, bool b) {
  digitalWrite(LED_R, r ? LOW : HIGH); digitalWrite(LED_G, g ? LOW : HIGH); digitalWrite(LED_B, b ? LOW : HIGH);
}
static void tone_(int f, int ms) { if (!soundOn) return; ledcWriteTone(0, f); delay(ms); ledcWriteTone(0, 0); }
static void beepTap() { if (soundOn) { ledcWriteTone(0, 2600); delay(8); ledcWriteTone(0, 0); } }
static void alertSound(uint8_t c) {
  switch (c) {
    case CAT_POLICE: for (int i=0;i<3;i++){tone_(1800,80);tone_(2600,80);} break;
    case CAT_EMS:    for (int i=0;i<2;i++){tone_(1400,160);tone_(1000,160);} break;
    case CAT_FIRE:   tone_(900,110);tone_(1500,110);tone_(2100,220); break;
    default:         tone_(2000,70); break;
  }
}

// ======================================================================
//  Drawing (banded off-screen sprite -> flicker free)
// ======================================================================
static TFT_eSPI *G = &tft;
static int OY = 0, bandH = 0;
#define Y(v) ((v) + OY)
static void setBright(uint8_t b) { ledcWrite(1, b); }

static void tt(const char *s, int x, int y, uint16_t c, uint8_t font, uint8_t d) {
  G->setTextFont(font); G->setTextColor(c); G->setTextDatum(d); G->drawString(s, x, Y(y));
}
static void ff(const char *s, int x, int y, uint16_t c, const GFXfont *f, uint8_t d, bool bold=false) {
  G->setFreeFont(f); G->setTextColor(c); G->setTextDatum(d);
  G->drawString(s, x, Y(y));
  if (bold) G->drawString(s, x + 1, Y(y));   // fake-bold: second pass offset 1px
}
static int rssiLvl(int r) { return r > -55 ? 5 : r > -65 ? 4 : r > -75 ? 3 : r > -85 ? 2 : 1; }
static void bars(int x, int y, int lvl, uint16_t on, int w, int gap, int maxH) {
  for (int i = 0; i < 5; i++) { int h = maxH * (i + 1) / 5;
    G->fillRect(x + i * (w + gap), Y(y + maxH - h), w, h, i < lvl ? on : C_LINE); }
}
static void fmtAgo(char *b, size_t n, uint32_t ms) {
  uint32_t s = ms / 1000;
  if (s < 3) snprintf(b, n, "live"); else if (s < 60) snprintf(b, n, "%lus", (unsigned long)s);
  else snprintf(b, n, "%lum", (unsigned long)(s / 60));
}

// ======================================================================
//  Views + input
// ======================================================================
enum View { V_HOME, V_SCANNER, V_WIFI, V_BT, V_TRACK, V_SET, V_COUNT };
static uint8_t view = V_HOME;
static int scroll[V_COUNT] = {0};

struct App { const char *name; const char *sub; View view; uint16_t col; char icon; };
static const App APPS[] = {
  {"Scanner",   "Police / EMS / Fire", V_SCANNER, 0xFB80, 'S'},
  {"Wi-Fi",     "APs, rogue & deauth", V_WIFI,    0x05FF, 'W'},
  {"Bluetooth", "Nearby BLE devices",  V_BT,      0x3D3F, 'B'},
  {"Trackers",  "AirTag / Tile / tag", V_TRACK,   0xF81F, 'T'},
  {"Settings",  "Sound, theme, about", V_SET,     0x7BCF, 'G'},
};
static const int NAPPS = sizeof(APPS) / sizeof(APPS[0]);

// touch input state
static bool pressed = false, moved = false;
static int pressX, pressY, lastTX, lastTY; static uint32_t pressMs;
static int tapX = -1, tapY = -1;     // consumed by the active view each frame

static bool readTouch(int &sx, int &sy) {
  if (!ts.touched()) return false;
  TS_Point p = ts.getPoint();
  if (p.z < 200) return false;
  sx = constrain((int)map(p.x, T_MINX, T_MAXX, 0, 320), 0, 319);
  sy = constrain((int)map(p.y, T_MINY, T_MAXY, 0, 240), 0, 239);
  return true;
}
static int maxScroll = 0;   // set by each list view while drawing
static void handleTouch() {
  int x, y; bool down = readTouch(x, y);
  uint32_t now = millis();
  if (down) {
    if (!pressed) { pressed = true; moved = false; pressX = lastTX = x; pressY = lastTY = y; pressMs = now; }
    int dy = y - lastTY;
    if (abs(y - pressY) > 6 || abs(x - pressX) > 6) moved = true;
    if (moved && view != V_HOME) { scroll[view] -= dy; }   // drag to scroll lists
    if (moved && view == V_HOME) { scroll[view] -= dy; }
    lastTX = x; lastTY = y;
  } else if (pressed) {
    pressed = false;
    if (!moved && now - pressMs < 600) { tapX = pressX; tapY = pressY; }   // register a tap
  }
  if (scroll[view] < 0) scroll[view] = 0;
  if (scroll[view] > maxScroll) scroll[view] = maxScroll;
}
static bool tapIn(int x, int y, int w, int h) {
  if (tapX < 0) return false;
  bool hit = tapX >= x && tapX < x + w && tapY >= y && tapY < y + h;
  return hit;
}

// ======================================================================
//  Header + home
// ======================================================================
static void header(const char *title, bool back) {
  G->fillRect(0, 0, 320, 30, C_PANEL);
  G->drawFastHLine(0, Y(30), 320, ACC);
  if (back) {
    ff("<", 16, 15, ACC, &FreeSansBold12pt7b, MC_DATUM, true);
    ff(title, 40, 15, C_TXT, &FreeSansBold9pt7b, ML_DATUM, true);
  } else {
    // PHANTOM wordmark
    ff("PHANTOM", 10, 15, ACC, &FreeSansBold12pt7b, ML_DATUM, true);
    ff("passive", 150, 16, C_MUTED, &FreeSans9pt7b, ML_DATUM);
  }
  uint32_t now = millis();
  bool ble = now - lastBleMs < 3000, wf = now - lastWifiMs < 15000;
  G->fillCircle(298, Y(15), 4, ble ? ACC : C_DIM);
  G->fillCircle(312, Y(15), 4, wf ? ACC : C_DIM);
}

static void drawHome() {
  // big glitchy title block
  ff("PHANTOM", 160, 52, ACC, &FreeSansBold18pt7b, MC_DATUM, true);
  tt("RF RECON  -  RX ONLY", 160, 78, C_MUTED, 2, MC_DATUM);

  int live = 0, trk = 0, wifi = 0, bt = 0;
  uint32_t now = millis();
  portENTER_CRITICAL(&mux);
  int dc = devCount;
  for (int i = 0; i < dc; i++) { if (now - dev[i].lastSeen > 30000) continue;
    live++; if (dev[i].tracker) trk++; if (dev[i].src=='W') wifi++; else bt++; }
  portEXIT_CRITICAL(&mux);

  const int top = 98, rowH = 46, pad = 10;
  maxScroll = (NAPPS * rowH) - (240 - top) + 8; if (maxScroll < 0) maxScroll = 0;
  int sc = scroll[V_HOME];
  for (int i = 0; i < NAPPS; i++) {
    int y = top + i * rowH - sc;
    if (y > 240 || y < top - rowH) continue;
    bool tapped = tapIn(pad, y, 300, rowH - 8);
    uint16_t col = APPS[i].col;
    G->fillRoundRect(pad, Y(y), 300, rowH - 8, 8, tapped ? C_PANEL2 : C_PANEL);
    G->fillRoundRect(pad, Y(y), 4, rowH - 8, 2, col);
    // icon chip
    G->fillRoundRect(pad + 12, Y(y + 6), 26, 26, 6, C_BG);
    char ic[2] = {APPS[i].icon, 0};
    ff(ic, pad + 25, y + 19, col, &FreeSansBold12pt7b, MC_DATUM, true);
    ff(APPS[i].name, pad + 48, y + 13, C_TXT, &FreeSansBold9pt7b, ML_DATUM, true);
    tt(APPS[i].sub, pad + 48, y + 28, C_MUTED, 1, ML_DATUM);
    // count badge
    char b[12]; int cnt = APPS[i].view==V_WIFI?wifi:APPS[i].view==V_BT?bt:APPS[i].view==V_TRACK?trk:APPS[i].view==V_SCANNER?0:-1;
    if (cnt >= 0) { snprintf(b, sizeof(b), "%d", cnt); ff(b, 296, y + 19, col, &FreeSansBold12pt7b, MR_DATUM, true); }
    else ff(">", 296, y + 19, C_MUTED, &FreeSansBold9pt7b, MR_DATUM);
    if (tapped) { view = APPS[i].view; scroll[view] = 0; beepTap(); }
  }
}

// ======================================================================
//  App: Scanner (emergency)
// ======================================================================
static void appScanner() {
  static Dev hits[MAX_DEV]; int hn = 0; uint32_t now = millis();
  portENTER_CRITICAL(&mux);
  for (int i = 0; i < devCount; i++) if (dev[i].cat < CAT_COUNT) hits[hn++] = dev[i];
  portEXIT_CRITICAL(&mux);
  for (int i = 0; i < hn; i++) for (int j = i+1; j < hn; j++)
    if (hits[j].lastSeen > hits[i].lastSeen) { Dev t=hits[i];hits[i]=hits[j];hits[j]=t; }

  if (!hn) { ff("All clear", 160, 110, 0x2FEB, &FreeSansBold18pt7b, MC_DATUM, true);
    tt("No emergency gear detected", 160, 140, C_MUTED, 2, MC_DATUM); maxScroll = 0; return; }

  const int top = 40, rowH = 42;
  maxScroll = hn * rowH - (240 - top) + 8; if (maxScroll < 0) maxScroll = 0;
  for (int i = 0; i < hn; i++) {
    int y = top + i * rowH - scroll[V_SCANNER];
    if (y > 240 || y < top - rowH) continue;
    Dev &h = hits[i]; bool stale = now - h.lastSeen > 60000;
    uint16_t cc = stale ? C_DIM : CAT_COL[h.cat];
    G->fillRoundRect(8, Y(y), 304, rowH - 7, 7, C_PANEL);
    G->fillRoundRect(8, Y(y), 5, rowH - 7, 2, cc);
    G->fillRoundRect(18, Y(y + 7), 54, 18, 4, cc);
    tt(CAT_TILE[h.cat], 45, y + 16, C_BG, 2, MC_DATUM);
    ff(h.name[0] ? h.name : "(unnamed)", 80, y + 7, stale ? C_MUTED : C_TXT, &FreeSans9pt7b, TL_DATUM);
    char sub[48], ago[12]; fmtAgo(ago, sizeof(ago), now - h.lastSeen);
    snprintf(sub, sizeof(sub), "%s  %c  %s", h.mac, h.src, ago);
    tt(sub, 80, y + 26, C_MUTED, 1, TL_DATUM);
    bars(278, y + 8, rssiLvl(h.rssi), cc, 5, 3, 18);
  }
}

// ======================================================================
//  App: Wi-Fi  (+ rogue / evil-twin / deauth detector)
// ======================================================================
static void appWifi() {
  static Dev aps[MAX_DEV]; int an = 0; uint32_t now = millis();
  portENTER_CRITICAL(&mux);
  for (int i = 0; i < devCount; i++) if (dev[i].src == 'W' && now - dev[i].lastSeen < 30000) aps[an++] = dev[i];
  portEXIT_CRITICAL(&mux);
  for (int i = 0; i < an; i++) for (int j = i+1; j < an; j++)
    if (aps[j].rssi > aps[i].rssi) { Dev t=aps[i];aps[i]=aps[j];aps[j]=t; }

  // threat banner
  bool deauth = now - lastDeauthMs < 4000 && deauthWindow > 8;
  int evil = 0; for (int i = 0; i < an; i++) if (aps[i].evilTwin) evil++;
  const int top = deauth || evil ? 66 : 40;
  if (deauth || evil) {
    G->fillRoundRect(8, Y(36), 304, 24, 6, 0x3000);
    G->drawRoundRect(8, Y(36), 304, 24, 6, C_RED);
    char w[48];
    if (deauth) snprintf(w, sizeof(w), "DEAUTH ATTACK  %lu/s", (unsigned long)deauthWindow);
    else snprintf(w, sizeof(w), "EVIL TWIN: %d duplicate SSID", evil);
    ff(w, 160, 48, C_RED, &FreeSansBold9pt7b, MC_DATUM, true);
  }

  if (!an) { tt("Scanning Wi-Fi...", 160, 120, C_MUTED, 2, MC_DATUM); maxScroll = 0; return; }
  const int rowH = 40;
  maxScroll = an * rowH - (240 - top) + 8; if (maxScroll < 0) maxScroll = 0;
  for (int i = 0; i < an; i++) {
    int y = top + i * rowH - scroll[V_WIFI];
    if (y > 240 || y < top - rowH) continue;
    Dev &a = aps[i];
    G->fillRoundRect(8, Y(y), 304, rowH - 7, 7, C_PANEL);
    uint16_t side = a.evilTwin ? C_RED : a.enc ? ACC : C_AMBER;
    G->fillRoundRect(8, Y(y), 4, rowH - 7, 2, side);
    ff(a.name[0] ? a.name : "(hidden)", 18, y + 6, a.name[0] ? C_TXT : C_MUTED, &FreeSans9pt7b, TL_DATUM);
    char sub[48]; snprintf(sub, sizeof(sub), "ch%-3d  %s  %s", a.chan, a.enc ? "secured" : "OPEN", a.mac);
    tt(sub, 18, y + 24, a.enc ? C_MUTED : C_AMBER, 1, TL_DATUM);
    char r[8]; snprintf(r, sizeof(r), "%d", a.rssi);
    tt(r, 300, y + 6, C_MUTED, 1, TR_DATUM);
    bars(272, y + 18, rssiLvl(a.rssi), side, 5, 3, 14);
    if (a.evilTwin) tt("TWIN", 300, y + 24, C_RED, 1, TR_DATUM);
  }
}

// ======================================================================
//  App: Bluetooth
// ======================================================================
static void appBt() {
  static Dev ds[MAX_DEV]; int dn = 0; uint32_t now = millis();
  portENTER_CRITICAL(&mux);
  for (int i = 0; i < devCount; i++) if (dev[i].src == 'B' && now - dev[i].lastSeen < 30000) ds[dn++] = dev[i];
  portEXIT_CRITICAL(&mux);
  for (int i = 0; i < dn; i++) for (int j = i+1; j < dn; j++)
    if (ds[j].rssi > ds[i].rssi) { Dev t=ds[i];ds[i]=ds[j];ds[j]=t; }

  if (!dn) { tt("Scanning Bluetooth...", 160, 120, C_MUTED, 2, MC_DATUM); maxScroll = 0; return; }
  const int top = 40, rowH = 38;
  maxScroll = dn * rowH - (240 - top) + 8; if (maxScroll < 0) maxScroll = 0;
  for (int i = 0; i < dn; i++) {
    int y = top + i * rowH - scroll[V_BT];
    if (y > 240 || y < top - rowH) continue;
    Dev &d = ds[i];
    G->fillRoundRect(8, Y(y), 304, rowH - 7, 7, C_PANEL);
    G->fillRoundRect(8, Y(y), 4, rowH - 7, 2, d.tracker ? 0xF81F : ACC);
    ff(d.name[0] ? d.name : "(no name)", 18, y + 5, d.name[0] ? C_TXT : C_MUTED, &FreeSans9pt7b, TL_DATUM);
    tt(d.mac, 18, y + 23, C_MUTED, 1, TL_DATUM);
    char r[8]; snprintf(r, sizeof(r), "%d", d.rssi);
    tt(r, 300, y + 5, C_MUTED, 1, TR_DATUM);
    bars(272, y + 16, rssiLvl(d.rssi), ACC, 5, 3, 14);
  }
}

// ======================================================================
//  App: Trackers
// ======================================================================
static const char *TRK_NAME[] = {"", "AirTag", "Find My", "Tile", "SmartTag"};
static void appTrack() {
  static Dev ts2[MAX_DEV]; int tn = 0; uint32_t now = millis();
  portENTER_CRITICAL(&mux);
  for (int i = 0; i < devCount; i++) if (dev[i].tracker && now - dev[i].lastSeen < 60000) ts2[tn++] = dev[i];
  portEXIT_CRITICAL(&mux);
  for (int i = 0; i < tn; i++) for (int j = i+1; j < tn; j++)
    if (ts2[j].rssi > ts2[i].rssi) { Dev t=ts2[i];ts2[i]=ts2[j];ts2[j]=t; }

  if (!tn) { ff("No trackers", 160, 108, 0x2FEB, &FreeSansBold18pt7b, MC_DATUM, true);
    tt("No AirTags or tags nearby", 160, 138, C_MUTED, 2, MC_DATUM); maxScroll = 0; return; }
  const int top = 40, rowH = 46;
  maxScroll = tn * rowH - (240 - top) + 8; if (maxScroll < 0) maxScroll = 0;
  for (int i = 0; i < tn; i++) {
    int y = top + i * rowH - scroll[V_TRACK];
    if (y > 240 || y < top - rowH) continue;
    Dev &d = ts2[i];
    uint32_t dur = (now - d.firstSeen) / 1000;
    bool follow = dur > 90;   // seen with you for over 90s
    G->fillRoundRect(8, Y(y), 304, rowH - 7, 7, follow ? 0x3000 : C_PANEL);
    if (follow) G->drawRoundRect(8, Y(y), 304, rowH - 7, 7, C_RED);
    G->fillRoundRect(8, Y(y), 5, rowH - 7, 2, follow ? C_RED : 0xF81F);
    ff(TRK_NAME[d.tracker], 18, y + 7, C_TXT, &FreeSansBold9pt7b, TL_DATUM, true);
    if (follow) ff("FOLLOWING YOU?", 300, y + 8, C_RED, &FreeSansBold9pt7b, TR_DATUM, true);
    char sub[56]; snprintf(sub, sizeof(sub), "%s  with you %lum%lus", d.mac,
                           (unsigned long)(dur/60), (unsigned long)(dur%60));
    tt(sub, 18, y + 27, follow ? C_RED : C_MUTED, 1, TL_DATUM);
    bars(278, y + 10, rssiLvl(d.rssi), follow ? C_RED : 0xF81F, 5, 3, 20);
  }
}

// ======================================================================
//  App: Settings
// ======================================================================
static void appSettings() {
  maxScroll = 0;
  const int x = 10, w = 300; int y = 42;
  // sound
  G->fillRoundRect(x, Y(y), w, 40, 8, C_PANEL);
  ff("Sound", x + 14, y + 20, C_TXT, &FreeSans9pt7b, ML_DATUM);
  G->fillRoundRect(x + w - 70, Y(y + 9), 56, 22, 11, soundOn ? ACC : C_LINE);
  G->fillCircle(soundOn ? x + w - 28 : x + w - 58, Y(y + 20), 8, C_BG);
  if (tapIn(x + w - 70, y + 6, 60, 28)) { soundOn = !soundOn; beepTap(); }
  y += 50;
  // brightness
  G->fillRoundRect(x, Y(y), w, 48, 8, C_PANEL);
  ff("Brightness", x + 14, y + 16, C_TXT, &FreeSans9pt7b, ML_DATUM);
  int bx = x + 14, bw = w - 28, by = y + 30;
  G->fillRoundRect(bx, Y(by), bw, 8, 4, C_LINE);
  int fillw = map(brightness, 20, 255, 10, bw);
  G->fillRoundRect(bx, Y(by), fillw, 8, 4, ACC);
  G->fillCircle(bx + fillw, Y(by + 4), 9, ACC);
  if (tapIn(bx - 4, by - 12, bw + 8, 30)) {
    brightness = constrain((int)map(tapX, bx, bx + bw, 20, 255), 20, 255); setBright(brightness); beepTap();
  }
  y += 58;
  // theme
  G->fillRoundRect(x, Y(y), w, 48, 8, C_PANEL);
  ff("Accent", x + 14, y + 16, C_TXT, &FreeSans9pt7b, ML_DATUM);
  tt(ACCENT_NAME[accentIdx], x + 14, y + 33, C_MUTED, 1, ML_DATUM);
  for (int i = 0; i < 4; i++) {
    int cx = x + w - 30 - i * 34, cy = y + 24;
    G->fillCircle(cx, Y(cy), 11, ACCENTS[i]);
    if (i == accentIdx) G->drawCircle(cx, Y(cy), 14, C_TXT);
    if (tapIn(cx - 14, cy - 14, 28, 28)) { accentIdx = i; beepTap(); }
  }
  y += 58;
  // clear
  G->fillRoundRect(x, Y(y), w, 40, 8, C_PANEL);
  ff("Clear all detections", x + 14, y + 20, C_RED, &FreeSans9pt7b, ML_DATUM);
  ff(">", x + w - 16, y + 20, C_RED, &FreeSansBold9pt7b, MR_DATUM);
  if (tapIn(x, y, w, 40)) { portENTER_CRITICAL(&mux); devCount = 0; portEXIT_CRITICAL(&mux); beepTap(); }
  y += 50;
  // about
  G->fillRoundRect(x, Y(y), w, 58, 8, C_PANEL);
  tt("PHANTOM v3.0  -  receive only", x + 14, y + 14, C_MUTED, 1, TL_DATUM);
  tt("No deauth / jam / spam. Passive RX.", x + 14, y + 28, C_MUTED, 1, TL_DATUM);
  tt("Touch off? edit T_MINX..T_MAXY in src", x + 14, y + 42, C_DIM, 1, TL_DATUM);
}

// ======================================================================
//  Frame
// ======================================================================
static void drawView(bool alerting) {
  if (view == V_HOME) { header("", false); drawHome(); }
  else {
    header(APPS[view - 1].name, true);
    switch (view) {
      case V_SCANNER: appScanner(); break;
      case V_WIFI:    appWifi(); break;
      case V_BT:      appBt(); break;
      case V_TRACK:   appTrack(); break;
      case V_SET:     appSettings(); break;
    }
    if (tapIn(0, 0, 56, 30)) { view = V_HOME; beepTap(); }   // back
  }
}
static void render(bool alerting) {
  if (bandH) { G = &spr;
    for (int y0 = 0; y0 < 240; y0 += bandH) { OY = -y0; spr.fillSprite(C_BG); drawView(alerting); spr.pushSprite(0, y0); }
  } else { G = &tft; OY = 0; tft.fillScreen(C_BG); drawView(alerting); }
  tapX = tapY = -1;   // consume tap after a full frame
}

static void splash() {
  tft.fillScreen(C_BG);
  tft.setTextDatum(MC_DATUM); tft.setTextColor(ACC);
  tft.setFreeFont(&FreeSansBold18pt7b);
  tft.drawString("PHANTOM", 160, 110); tft.drawString("PHANTOM", 161, 110);
  tft.setTextFont(2); tft.setTextColor(C_MUTED);
  tft.drawString("passive RF recon  -  booting radios", 160, 150);
}

// ======================================================================
//  Setup / loop
// ======================================================================
void setup() {
  Serial.begin(115200);
  pinMode(LED_R, OUTPUT); pinMode(LED_G, OUTPUT); pinMode(LED_B, OUTPUT);
  pinMode(BTN_BOOT, INPUT_PULLUP);
  setLed(false, false, false);
  ledcSetup(0, 2000, 8); ledcAttachPin(SPEAKER, 0);
  ledcSetup(1, 5000, 8); ledcAttachPin(TFT_BL, 1); setBright(brightness);

  tft.init(); tft.setRotation(1);
#ifdef CYD_INVERT
  tft.invertDisplay(true);
#endif
  tsSPI.begin(T_CLK, T_MISO, T_MOSI, T_CS);
  ts.begin(tsSPI); ts.setRotation(1);
  splash();

  spr.setColorDepth(16);
  for (int h : {120, 80, 60, 48, 40}) if (spr.createSprite(320, h)) { bandH = h; break; }

  WiFi.mode(WIFI_STA); WiFi.disconnect();
  esp_wifi_set_promiscuous(true);                 // for the deauth DETECTOR (counts only)
  esp_wifi_set_promiscuous_rx_cb(&promiscCB);

  NimBLEDevice::init("");
  bleScan = NimBLEDevice::getScan();
  bleScan->setAdvertisedDeviceCallbacks(new BleCB(), true);
  bleScan->setActiveScan(false);
  bleScan->setInterval(160); bleScan->setWindow(80);
  bleScan->setMaxResults(0);
  bleScan->start(0, nullptr, false);

  delay(700);
  Serial.println("PHANTOM up (passive BLE + Wi-Fi, deauth detector)");
}

void loop() {
  static uint32_t lastDraw = 0, lastWin = 0, chanHop = 0;
  static uint8_t ch = 1;
  static bool alerting = false;
  uint32_t now = millis();

  handleTouch();

  // deauth detector channel hop + 1s window
  if (now - chanHop > 250) { chanHop = now; ch = ch % 13 + 1; esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE); }
  if (now - lastWin > 1000) { lastWin = now; deauthWindow = deauthCount; deauthCount = 0; }

  wifiScanStep();

  int pa = pendingAlert;
  if (pa >= 0) { pendingAlert = -1;
    if (!(now < alertUntil && alertCat < pa)) alertCat = pa;
    alertUntil = now + 6000;
    if (view == V_HOME || view == V_SCANNER) { view = V_SCANNER; }
    alertSound(alertCat); lastDraw = 0;
  }
  bool a = now < alertUntil;
  if (a != alerting) { alerting = a; if (!a) setLed(false,false,false); lastDraw = 0; }
  if (alerting) { bool ph = (now/220)%2;
    switch (alertCat) { case CAT_POLICE: setLed(ph,0,!ph); break; case CAT_EMS: setLed(1,!ph,!ph); break;
      case CAT_FIRE: setLed(ph,0,0); break; default: setLed(ph,ph,0); } }

  uint32_t every = bandH ? (pressed ? 33 : 120) : 400;
  if (!lastDraw || now - lastDraw >= every || tapX >= 0) { lastDraw = now; render(alerting); }

  if (!bleScan->isScanning()) bleScan->start(0, nullptr, false);
  delay(4);
}
