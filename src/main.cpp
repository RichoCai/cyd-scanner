/*
 * CYD Emergency Scanner  v2.1
 * For the ESP32-2432S028R "Cheap Yellow Display" (single or dual USB).
 *
 * RECEIVE-ONLY. Two passive radios run side by side:
 *   - Bluetooth LE: passive scan (no scan requests sent)
 *   - Wi-Fi:        passive scan (listens for beacons, sends no probe requests)
 * Nothing is ever connected to, paired with, spoofed or jammed. No GPS needed.
 *
 * Screens (tap BOOT to switch):
 *   1. Home    - big status card ("All clear" / "Police nearby"), signal bars, category tiles
 *   2. List    - every detection with how long ago and how strong
 *   3. Nearby  - every named Bluetooth / Wi-Fi signal around you (use it to add new rules)
 *
 * BOOT button (GPIO0):  tap        = next screen
 *                       hold 1-3 s = sound on / off
 *                       hold 3 s+  = clear detections
 */
#include <Arduino.h>
#include <WiFi.h>
#include <NimBLEDevice.h>
#include <TFT_eSPI.h>

// ---------- CYD hardware ----------
#define LED_R 4      // RGB LED, active LOW
#define LED_G 16
#define LED_B 17
#define SPEAKER 26
#define BTN_BOOT 0

// ---------- Rules ----------
enum Cat : uint8_t { CAT_POLICE = 0, CAT_EMS, CAT_FIRE, CAT_VEHICLE, CAT_COUNT };
enum Src : uint8_t { S_BLE = 1, S_WIFI = 2, S_ANY = 3 };
enum Kind : uint8_t { BY_MAC, BY_NAME };

struct Rule { uint8_t src; uint8_t kind; const char *pattern; const char *label; uint8_t cat; };

// MAC prefixes: lowercase "xx:xx:xx". Name patterns: lowercase substring of BLE name or Wi-Fi SSID.
static const Rule RULES[] = {
  // --- Police: body cams, in-car video, radios ---
  {S_ANY,  BY_MAC,  "00:25:df",       "Axon device",        CAT_POLICE},  // Axon Enterprise OUI
  {S_ANY,  BY_NAME, "axon",           "Axon",               CAT_POLICE},
  {S_BLE,  BY_NAME, "body 2",         "Axon Body 2",        CAT_POLICE},
  {S_BLE,  BY_NAME, "body 3",         "Axon Body 3",        CAT_POLICE},
  {S_BLE,  BY_NAME, "body 4",         "Axon Body 4",        CAT_POLICE},
  {S_BLE,  BY_NAME, "flex 2",         "Axon Flex",          CAT_POLICE},
  {S_ANY,  BY_NAME, "fleet 3",        "Axon Fleet in-car",  CAT_POLICE},
  {S_ANY,  BY_NAME, "watchguard",     "WatchGuard cam",     CAT_POLICE},
  {S_ANY,  BY_NAME, "v300",           "WatchGuard V300",    CAT_POLICE},
  {S_ANY,  BY_NAME, "apx",            "Motorola APX radio", CAT_POLICE},
  {S_ANY,  BY_NAME, "police",         "Police network",     CAT_POLICE},
  {S_ANY,  BY_NAME, "polair",         "Police air",         CAT_POLICE},

  // --- EMS / ambulance ---
  {S_ANY,  BY_NAME, "ambulance",      "Ambulance",          CAT_EMS},
  {S_ANY,  BY_NAME, "paramedic",      "Paramedic",          CAT_EMS},
  {S_ANY,  BY_NAME, "st john",        "St John",            CAT_EMS},
  {S_ANY,  BY_NAME, "stjohn",         "St John",            CAT_EMS},
  {S_ANY,  BY_NAME, "sjwa",           "St John WA",         CAT_EMS},
  {S_ANY,  BY_NAME, "rfds",           "Flying Doctor",      CAT_EMS},
  {S_ANY,  BY_NAME, "corpuls",        "Corpuls monitor",    CAT_EMS},
  {S_ANY,  BY_NAME, "lifepak",        "LIFEPAK monitor",    CAT_EMS},
  {S_ANY,  BY_NAME, "zoll",           "ZOLL monitor",       CAT_EMS},

  // --- Fire / SES ---
  {S_ANY,  BY_NAME, "dfes",           "DFES",               CAT_FIRE},
  {S_ANY,  BY_NAME, "fire rescue",    "Fire & Rescue",      CAT_FIRE},
  {S_ANY,  BY_NAME, "firerescue",     "Fire & Rescue",      CAT_FIRE},
  {S_ANY,  BY_NAME, "fire-rescue",    "Fire & Rescue",      CAT_FIRE},
  {S_ANY,  BY_NAME, "fire brigade",   "Fire brigade",       CAT_FIRE},
  {S_ANY,  BY_NAME, "bushfire",       "Bushfire unit",      CAT_FIRE},
  {S_WIFI, BY_NAME, "ses ",           "SES",                CAT_FIRE},

  // --- In-vehicle gear (emergency fleets AND others: buses, utilities, trucks) ---
  {S_WIFI, BY_MAC,  "00:30:44",       "Cradlepoint router", CAT_VEHICLE},
  {S_WIFI, BY_NAME, "cradlepoint",    "Cradlepoint router", CAT_VEHICLE},
  {S_WIFI, BY_NAME, "ibr900",         "Cradlepoint IBR900", CAT_VEHICLE},
  {S_WIFI, BY_NAME, "ibr1700",        "Cradlepoint IBR1700",CAT_VEHICLE},
  {S_WIFI, BY_NAME, "r1900",          "Cradlepoint R1900",  CAT_VEHICLE},
  {S_WIFI, BY_MAC,  "00:a0:d5",       "Sierra AirLink",     CAT_VEHICLE},
  {S_WIFI, BY_NAME, "airlink",        "Sierra AirLink",     CAT_VEHICLE},
  {S_WIFI, BY_NAME, "mp70",           "AirLink MP70",       CAT_VEHICLE},
  {S_WIFI, BY_NAME, "rv55",           "AirLink RV55",       CAT_VEHICLE},
  {S_WIFI, BY_NAME, "pepwave",        "Peplink router",     CAT_VEHICLE},
  {S_ANY,  BY_NAME, "toughbook",      "Toughbook MDT",      CAT_VEHICLE},
  {S_ANY,  BY_NAME, "getac",          "Getac MDT",          CAT_VEHICLE},
};


// ---------- Palette (RGB565) ----------
#define C_BG        0x0862   // #0a0d14
#define C_CARD      0x10C4   // #161b26
#define C_LINE      0x2988   // #283040
#define C_TEXT      0xFFFF
#define C_MUTED     0x8CB4   // #8c96a5
#define C_GREEN     0x262B   // #22c55e
#define C_GREEN2    0x13C7
#define C_GREEN3    0x0A24
#define C_GREEN4    0x0942
#define C_AMBER     0xED81
#define C_CYAN_DK   0x0ACD
#define C_PURP_DK   0x5952
#define C_RED_DIM   0x58A2
#define C_BLUE_DIM  0x110B

//                                         police  ambulance  fire    vehicle
static const uint16_t CAT_COL[CAT_COUNT]  = {0x3C1E, 0xEA28,   0xFB82, 0xED81};
static const uint16_t CAT_DARK[CAT_COUNT] = {0x112A, 0x4041,   0x40A0, 0x4100};
static const char *CAT_BIG[CAT_COUNT]     = {"Police", "Ambulance", "Fire crew", "Vehicle?"};
static const char *CAT_TILE[CAT_COUNT]    = {"Police", "Ambulance", "Fire", "Vehicle"};
static const char *PROX[6]                = {"", "FAR", "MEDIUM", "NEAR", "CLOSE", "VERY CLOSE"};

// ---------- State ----------
struct Hit {
  char mac[18]; char name[26]; char label[22];
  uint8_t cat; char src; int rssi;
  uint32_t firstSeen, lastSeen, count;
};
struct Seen { char mac[18]; char name[26]; char src; int rssi; uint32_t lastSeen; };

static const int MAX_HITS = 32, MAX_SEEN = 40;
static const uint32_t ACTIVE_MS = 60000;
static Hit hits[MAX_HITS];  static int hitCount = 0;
static Seen seen[MAX_SEEN]; static int seenCount = 0;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static volatile int pendingAlert = -1;
static volatile uint32_t lastBleMs = 0, lastWifiMs = 0;
static bool muted = false;
static uint32_t alertUntil = 0; static uint8_t alertCat = 0;
enum View { V_HOME, V_LIST, V_NEARBY, V_COUNT };
static uint8_t view = V_HOME;

TFT_eSPI tft;
TFT_eSprite spr(&tft);
NimBLEScan *bleScan;

// ---------- Matching ----------
static void lowerCopy(char *dst, const char *src, size_t n) {
  size_t i = 0; for (; src[i] && i < n - 1; i++) dst[i] = tolower((unsigned char)src[i]); dst[i] = 0;
}

static const Rule *match(char src, const char *macLower, const char *name) {
  char low[40]; lowerCopy(low, name, sizeof(low));
  uint8_t s = src == 'B' ? S_BLE : S_WIFI;
  for (auto &r : RULES) {
    if (!(r.src & s)) continue;
    if (r.kind == BY_MAC) { if (strncmp(macLower, r.pattern, strlen(r.pattern)) == 0) return &r; }
    else if (low[0] && strstr(low, r.pattern)) return &r;
  }
  return nullptr;
}

static void observe(char src, const char *mac, const char *name, int rssi) {
  char macL[18]; lowerCopy(macL, mac, sizeof(macL));
  uint32_t now = millis();
  const Rule *r = match(src, macL, name);
  bool isNew = false;

  portENTER_CRITICAL(&mux);
  if (name[0] || r) {                                   // "Nearby" list: named things only
    int i = 0; for (; i < seenCount; i++) if (!strcmp(seen[i].mac, macL)) break;
    if (i == seenCount) {
      if (seenCount < MAX_SEEN) seenCount++;
      else { i = 0; for (int k = 1; k < MAX_SEEN; k++) if (seen[k].lastSeen < seen[i].lastSeen) i = k; }
      strlcpy(seen[i].mac, macL, sizeof(seen[i].mac));
      seen[i].name[0] = 0;
    }
    if (name[0]) strlcpy(seen[i].name, name, sizeof(seen[i].name));
    seen[i].src = src; seen[i].rssi = rssi; seen[i].lastSeen = now;
  }
  if (r) {
    int i = 0; for (; i < hitCount; i++) if (!strcmp(hits[i].mac, macL)) break;
    if (i == hitCount) {
      if (hitCount < MAX_HITS) hitCount++;
      else { i = 0; for (int k = 1; k < MAX_HITS; k++) if (hits[k].lastSeen < hits[i].lastSeen) i = k; }
      Hit &h = hits[i];
      strlcpy(h.mac, macL, sizeof(h.mac)); h.name[0] = 0;
      strlcpy(h.label, r->label, sizeof(h.label));
      h.cat = r->cat; h.src = src; h.firstSeen = now; h.count = 0;
      isNew = true;
      if (pendingAlert < 0 || r->cat < pendingAlert) pendingAlert = r->cat;
    }
    Hit &h = hits[i];
    if (name[0]) strlcpy(h.name, name, sizeof(h.name));
    h.rssi = rssi; h.lastSeen = now; h.count++;
  }
  portEXIT_CRITICAL(&mux);

  if (isNew) Serial.printf("HIT,%s,%s,%c,%s,%s,%d\n", CAT_TILE[r->cat], r->label, src, macL, name, rssi);
}

class BleCallbacks : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice *d) override {
    lastBleMs = millis();
    std::string mac = d->getAddress().toString();
    std::string name = d->haveName() ? d->getName() : "";
    observe('B', mac.c_str(), name.c_str(), d->getRSSI());
  }
};

static void handleWifi() {
  static uint32_t lastStart = 0;
  int n = WiFi.scanComplete();
  if (n >= 0) {
    lastWifiMs = millis();
    for (int i = 0; i < n; i++)
      observe('W', WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i));
    WiFi.scanDelete();
  } else if (n == WIFI_SCAN_FAILED && millis() - lastStart > 6000) {
    lastStart = millis();
    WiFi.scanNetworks(true, true, true, 110);   // async, hidden too, PASSIVE, 110 ms/channel
  }
}

// ---------- LED + sound ----------
static void setLed(bool r, bool g, bool b) {
  digitalWrite(LED_R, r ? LOW : HIGH); digitalWrite(LED_G, g ? LOW : HIGH); digitalWrite(LED_B, b ? LOW : HIGH);
}
static void tone_(int f, int ms) { if (muted) return; ledcWriteTone(0, f); delay(ms); ledcWriteTone(0, 0); }

static void alertSound(uint8_t cat) {
  switch (cat) {
    case CAT_POLICE:  for (int i = 0; i < 3; i++) { tone_(1800, 90); tone_(2600, 90); } break;
    case CAT_EMS:     for (int i = 0; i < 2; i++) { tone_(1400, 180); tone_(1000, 180); } break;
    case CAT_FIRE:    tone_(900, 120); tone_(1500, 120); tone_(2100, 250); break;
    default:          tone_(2000, 80); break;
  }
}

static void alertLed(uint8_t cat, uint32_t now) {
  bool ph = (now / 220) % 2;
  switch (cat) {
    case CAT_POLICE:  setLed(ph, false, !ph); break;   // red / blue
    case CAT_EMS:     setLed(true, !ph, !ph); break;   // red / white
    case CAT_FIRE:    setLed(ph, false, false); break; // red strobe
    default:          setLed(ph, ph, false); break;    // yellow
  }
}

// ---------- Drawing helpers ----------
// The screen is drawn into an off-screen sprite in horizontal bands, then pushed,
// so nothing flickers. G = current target, OY = vertical offset of the band.
static TFT_eSPI *G = &tft;
static int OY = 0;
static int bandH = 0;            // 0 = no sprite, draw straight to screen
#define Y(v) ((v) + OY)

static void txtF(const char *s, int x, int y, uint16_t c, const GFXfont *f, uint8_t d) {
  G->setFreeFont(f); G->setTextColor(c); G->setTextDatum(d); G->drawString(s, x, Y(y));
}
static void txtN(const char *s, int x, int y, uint16_t c, uint8_t font, uint8_t d) {
  G->setTextFont(font); G->setTextColor(c); G->setTextDatum(d); G->drawString(s, x, Y(y));
}
static int rssiLevel(int r) { return r > -55 ? 5 : r > -65 ? 4 : r > -75 ? 3 : r > -85 ? 2 : 1; }

static void bars(int x, int y, int lvl, uint16_t on, int w, int gap, int maxH) {
  for (int i = 0; i < 5; i++) {
    int h = maxH * (i + 1) / 5;
    G->fillRoundRect(x + i * (w + gap), Y(y + maxH - h), w, h, 1, i < lvl ? on : C_LINE);
  }
}
static void fmtAgo(char *b, size_t n, uint32_t ms) {
  unsigned long s = ms / 1000;
  if (s < 3) snprintf(b, n, "just now");
  else if (s < 60) snprintf(b, n, "%lus ago", s);
  else snprintf(b, n, "%lum ago", s / 60);
}
static const char *srcName(char s) { return s == 'W' ? "Wi-Fi" : "Bluetooth"; }
static uint32_t hashStr(const char *s) { uint32_t h = 5381; while (*s) h = h * 33 + (uint8_t)*s++; return h; }

// ---------- Snapshot of shared state ----------
struct UiState {
  int counts[CAT_COUNT]; int active; bool hasTop; Hit top; int nearby;
};
static Hit hs[MAX_HITS];  static int hn = 0;
static Seen ss[MAX_SEEN]; static int sn = 0;

static void snapshot(UiState &u, uint32_t now) {
  portENTER_CRITICAL(&mux);
  hn = hitCount;  memcpy(hs, hits, sizeof(Hit) * hn);
  sn = seenCount; memcpy(ss, seen, sizeof(Seen) * sn);
  portEXIT_CRITICAL(&mux);

  memset(&u, 0, sizeof(u));
  for (int i = 0; i < hn; i++) {
    Hit &h = hs[i];
    if (now - h.lastSeen >= ACTIVE_MS) continue;
    u.counts[h.cat]++; u.active++;
    if (!u.hasTop || h.cat < u.top.cat || (h.cat == u.top.cat && h.rssi > u.top.rssi)) { u.top = h; u.hasTop = true; }
  }
  for (int i = 0; i < hn; i++) for (int j = i + 1; j < hn; j++)
    if (hs[j].lastSeen > hs[i].lastSeen) { Hit t = hs[i]; hs[i] = hs[j]; hs[j] = t; }
  int m = 0; for (int i = 0; i < sn; i++) if (now - ss[i].lastSeen < 20000) ss[m++] = ss[i];
  sn = m;
  for (int i = 0; i < sn; i++) for (int j = i + 1; j < sn; j++)
    if (ss[j].rssi > ss[i].rssi) { Seen t = ss[i]; ss[i] = ss[j]; ss[j] = t; }
  u.nearby = sn;
}

// ---------- Screen parts ----------
static void drawHeader(const UiState &u, uint32_t now, bool alerting) {
  bool ph = (now / 250) % 2;
  G->fillCircle(14, Y(15), 5, alerting && ph ? CAT_COL[CAT_EMS] : C_RED_DIM);
  G->fillCircle(28, Y(15), 5, alerting && !ph ? CAT_COL[CAT_POLICE] : C_BLUE_DIM);
  txtF("Emergency Scanner", 42, 15, C_TEXT, &FreeSansBold9pt7b, ML_DATUM);

  bool bleOn = now - lastBleMs < 3000, wifiOn = now - lastWifiMs < 15000;
  G->fillRoundRect(236, Y(6), 30, 18, 9, bleOn ? C_PURP_DK : C_CARD);
  txtN("BT", 251, 15, bleOn ? C_TEXT : C_MUTED, 2, MC_DATUM);
  G->fillRoundRect(270, Y(6), 42, 18, 9, wifiOn ? C_CYAN_DK : C_CARD);
  txtN("WiFi", 291, 15, wifiOn ? C_TEXT : C_MUTED, 2, MC_DATUM);
  G->drawFastHLine(0, Y(30), 320, C_LINE);
}

static void drawRadar(int cx, int cy, uint32_t now) {
  for (int r = 12; r <= 36; r += 12) G->drawCircle(cx, Y(cy), r, C_LINE);
  G->drawFastHLine(cx - 36, Y(cy), 73, C_LINE);
  G->drawFastVLine(cx, Y(cy - 36), 73, C_LINE);
  for (int i = 0; i < sn; i++) {                         // a dot for every signal heard
    float a = (hashStr(ss[i].mac) % 360) * DEG_TO_RAD;
    int r = map(constrain(ss[i].rssi, -100, -40), -100, -40, 34, 6);
    G->fillCircle(cx + cosf(a) * r, Y(cy) + sinf(a) * r, 2, C_GREEN2);
  }
  const uint16_t trail[4] = {C_GREEN, C_GREEN2, C_GREEN3, C_GREEN4};
  float a = (now % 3000) / 3000.0f * TWO_PI;
  for (int k = 3; k >= 0; k--) {
    float b = a - k * 0.10f;
    G->drawLine(cx, Y(cy), cx + cosf(b) * 36, Y(cy) + sinf(b) * 36, trail[k]);
  }
  G->fillCircle(cx, Y(cy), 2, C_GREEN);
}

static void drawFooter(uint32_t now) {
  G->drawFastHLine(0, Y(214), 320, C_LINE);
  if (muted) txtN("Sound OFF  -  hold BOOT to turn on", 10, 227, C_AMBER, 2, ML_DATUM);
  else       txtN("BOOT: tap = next screen, hold = mute", 10, 227, C_MUTED, 2, ML_DATUM);
  for (int i = 0; i < V_COUNT; i++)
    G->fillCircle(290 + i * 10, Y(227), i == view ? 3 : 2, i == view ? C_TEXT : C_LINE);
}

static void drawHome(const UiState &u, uint32_t now, bool alerting) {
  const int x = 8, y = 36, w = 304, h = 106;
  if (!u.hasTop) {
    G->fillRoundRect(x, Y(y), w, h, 10, C_CARD);
    G->fillRoundRect(x, Y(y + 12), 4, h - 24, 2, C_GREEN);
    txtF("All clear", 22, 46, C_GREEN, &FreeSansBold18pt7b, TL_DATUM);
    txtF("No emergency gear nearby", 22, 86, C_TEXT, &FreeSans9pt7b, TL_DATUM);
    char s[40]; snprintf(s, sizeof(s), "Listening to %d signals", u.nearby);
    txtN(s, 22, 112, C_MUTED, 2, TL_DATUM);
    drawRadar(268, 89, now);
  } else {
    const Hit &t = u.top;
    uint16_t cc = CAT_COL[t.cat];
    G->fillRoundRect(x, Y(y), w, h, 10, CAT_DARK[t.cat]);
    if (!alerting || (now / 300) % 2) {
      G->drawRoundRect(x, Y(y), w, h, 10, cc);
      G->drawRoundRect(x + 1, Y(y + 1), w - 2, h - 2, 9, cc);
    }
    txtN("DETECTED NEARBY", 20, 46, cc, 2, TL_DATUM);
    txtF(CAT_BIG[t.cat], 20, 62, C_TEXT, &FreeSansBold18pt7b, TL_DATUM);
    txtF(t.label, 20, 98, C_TEXT, &FreeSans9pt7b, TL_DATUM);
    char ago[16], s[64]; fmtAgo(ago, sizeof(ago), millis() - t.lastSeen);
    if (u.active > 1) snprintf(s, sizeof(s), "%s - %s - +%d more", ago, srcName(t.src), u.active - 1);
    else              snprintf(s, sizeof(s), "%s - via %s", ago, srcName(t.src));
    txtN(s, 20, 120, C_MUTED, 2, TL_DATUM);
    int lvl = rssiLevel(t.rssi);
    bars(250, 48, lvl, cc, 8, 4, 44);
    txtN(PROX[lvl], 274, 104, cc, 2, TC_DATUM);
  }

  for (int c = 0; c < CAT_COUNT; c++) {                 // category tiles
    int tx = 8 + c * 77, ty = 148, tw = 72, th = 60;
    bool on = u.counts[c] > 0;
    G->fillRoundRect(tx, Y(ty), tw, th, 8, C_CARD);
    G->fillRoundRect(tx + 10, Y(ty), tw - 20, 3, 1, on ? CAT_COL[c] : C_LINE);
    char n[6]; snprintf(n, sizeof(n), "%d", u.counts[c]);
    txtF(n, tx + tw / 2, ty + 24, on ? CAT_COL[c] : C_MUTED, &FreeSansBold12pt7b, MC_DATUM);
    txtN(CAT_TILE[c], tx + tw / 2, ty + 47, on ? C_TEXT : C_MUTED, 2, MC_DATUM);
  }
}

static void drawList(uint32_t now) {
  int shown = 0; for (int i = 0; i < hn; i++) if (now - hs[i].lastSeen < 600000) shown++;
  txtF("Detections", 12, 46, C_TEXT, &FreeSansBold9pt7b, ML_DATUM);
  char t[24]; snprintf(t, sizeof(t), "%d in last 10 min", shown);
  txtN(t, 308, 46, C_MUTED, 2, MR_DATUM);
  if (!shown) {
    txtF("Nothing yet", 160, 116, C_MUTED, &FreeSans9pt7b, MC_DATUM);
    txtN("Anything detected shows up here", 160, 140, C_MUTED, 2, MC_DATUM);
    return;
  }
  int row = 0;
  for (int i = 0; i < hn && row < 5; i++) {
    const Hit &h = hs[i];
    uint32_t age = now - h.lastSeen;
    if (age >= 600000) continue;
    int y = 60 + row++ * 30;
    bool stale = age > ACTIVE_MS;
    uint16_t cc = stale ? C_LINE : CAT_COL[h.cat];
    G->fillRoundRect(8, Y(y), 304, 27, 6, C_CARD);
    G->fillRoundRect(8, Y(y), 5, 27, 2, cc);
    txtN(h.label, 20, y + 2, stale ? C_MUTED : C_TEXT, 2, TL_DATUM);
    char ago[16], sub[48]; fmtAgo(ago, sizeof(ago), age);
    snprintf(sub, sizeof(sub), "%s - %s - %s", CAT_TILE[h.cat], ago, srcName(h.src));
    txtN(sub, 20, y + 18, C_MUTED, 1, TL_DATUM);
    bars(270, y + 5, rssiLevel(h.rssi), cc, 5, 3, 17);
  }
}

static void drawNearby() {
  txtF("Nearby signals", 12, 46, C_TEXT, &FreeSansBold9pt7b, ML_DATUM);
  char t[24]; snprintf(t, sizeof(t), "%d heard", sn);
  txtN(t, 308, 46, C_MUTED, 2, MR_DATUM);
  if (!sn) { txtN("Nothing named nearby yet", 160, 120, C_MUTED, 2, MC_DATUM); return; }
  for (int i = 0; i < sn && i < 12; i++) {
    const Seen &s = ss[i]; int y = 60 + i * 13;
    bool wf = s.src == 'W';
    G->fillRoundRect(10, Y(y), 28, 11, 3, wf ? C_CYAN_DK : C_PURP_DK);
    txtN(wf ? "WiFi" : "BT", 24, y + 6, C_TEXT, 1, MC_DATUM);
    bars(44, y + 1, rssiLevel(s.rssi), C_GREEN, 3, 1, 9);
    char nm[32]; snprintf(nm, sizeof(nm), "%.30s", s.name[0] ? s.name : "(hidden network)");
    txtN(nm, 70, y + 2, s.name[0] ? C_TEXT : C_MUTED, 1, TL_DATUM);
    char mac[9]; strlcpy(mac, s.mac, sizeof(mac));
    txtN(mac, 310, y + 2, C_MUTED, 1, TR_DATUM);
  }
}

static void drawAll(const UiState &u, uint32_t now, bool alerting) {
  drawHeader(u, now, alerting);
  if (view == V_HOME) drawHome(u, now, alerting);
  else if (view == V_LIST) drawList(now);
  else drawNearby();
  drawFooter(now);
}

static void render(uint32_t now, bool alerting) {
  static UiState u;
  snapshot(u, now);
  if (bandH) {
    G = &spr;
    for (int y0 = 0; y0 < 240; y0 += bandH) {
      OY = -y0;
      spr.fillSprite(C_BG);
      drawAll(u, now, alerting);
      spr.pushSprite(0, y0);
    }
  } else {
    G = &tft; OY = 0;
    tft.fillScreen(C_BG);
    drawAll(u, now, alerting);
  }
}

static void splash() {
  tft.fillScreen(C_BG);
  tft.fillCircle(146, 70, 9, CAT_COL[CAT_EMS]);
  tft.fillCircle(174, 70, 9, CAT_COL[CAT_POLICE]);
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(C_TEXT);
  tft.setFreeFont(&FreeSansBold18pt7b);
  tft.drawString("Emergency", 160, 112);
  tft.drawString("Scanner", 160, 146);
  tft.setTextFont(2);
  tft.setTextColor(C_MUTED);
  tft.drawString("Passive Bluetooth + Wi-Fi  -  receive only", 160, 190);
  tft.setTextColor(C_GREEN);
  tft.drawString("Starting radios...", 160, 212);
}

// ---------- Setup / loop ----------
void setup() {
  Serial.begin(115200);
  pinMode(LED_R, OUTPUT); pinMode(LED_G, OUTPUT); pinMode(LED_B, OUTPUT);
  pinMode(BTN_BOOT, INPUT_PULLUP);
  setLed(false, false, false);
  ledcSetup(0, 2000, 8); ledcAttachPin(SPEAKER, 0);

  tft.init();
  tft.setRotation(1);
#ifdef CYD_INVERT
  tft.invertDisplay(true);
#endif
  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, HIGH);
  splash();

  // grab the frame buffer before the radios take memory
  spr.setColorDepth(16);
  const int tryH[] = {120, 80, 60, 48, 40};
  for (int h : tryH) if (spr.createSprite(320, h)) { bandH = h; break; }
  Serial.printf("Frame band height: %d\n", bandH);

  WiFi.mode(WIFI_STA);          // station mode, never connects to anything
  WiFi.disconnect();

  NimBLEDevice::init("");
  bleScan = NimBLEDevice::getScan();
  bleScan->setAdvertisedDeviceCallbacks(new BleCallbacks(), true);
  bleScan->setActiveScan(false);   // passive
  bleScan->setInterval(160);       // share radio time with Wi-Fi
  bleScan->setWindow(80);
  bleScan->setMaxResults(0);
  bleScan->start(0, nullptr, false);

  delay(900);
  Serial.println("Emergency scanner started (passive BLE + passive Wi-Fi)");
}

void loop() {
  static uint32_t lastDraw = 0, btnDown = 0;
  static bool alerting = false;
  uint32_t now = millis();

  if (digitalRead(BTN_BOOT) == LOW) { if (!btnDown) btnDown = now; }
  else if (btnDown) {
    uint32_t d = now - btnDown; btnDown = 0;
    if (d >= 3000) { portENTER_CRITICAL(&mux); hitCount = 0; portEXIT_CRITICAL(&mux); }
    else if (d >= 1000) muted = !muted;
    else if (d > 40) view = (view + 1) % V_COUNT;
    lastDraw = 0;
  }

  handleWifi();

  int pa = pendingAlert;
  if (pa >= 0) {
    pendingAlert = -1;
    if (!(now < alertUntil && alertCat < pa)) alertCat = pa;
    alertUntil = now + 6000;
    view = V_HOME;
    render(now, true);
    alertSound(alertCat);
    lastDraw = 0;
  }

  bool a = now < alertUntil;
  if (a != alerting) { alerting = a; if (!a) setLed(false, false, false); }
  if (alerting) alertLed(alertCat, now);

  uint32_t every = !bandH ? 1000 : (view == V_HOME ? 60 : 400);
  if (!lastDraw || now - lastDraw >= every) {
    lastDraw = now;
    render(now, alerting);
  }

  if (!bleScan->isScanning()) bleScan->start(0, nullptr, false);
  delay(5);
}
