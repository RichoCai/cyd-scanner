/*
 * PHANTOM  v4.0  -  counter-surveillance / passive RF defense
 * ESP32-2432S028R "Cheap Yellow Display". Touchscreen, pure black + purple.
 *
 * RECEIVE-ONLY. BLE + Wi-Fi scan passively. Wi-Fi promiscuous mode only COUNTS
 * deauth/disassoc frames (attack detector). No deauth / jam / spam, no connect.
 *
 * UI: tap a tile on the grid home screen to open an app; tap "<" to go back;
 *     long lists use < / > page buttons (no swiping). Background is always black.
 */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <XPT2046_Touchscreen.h>
#include <NimBLEDevice.h>
#include <TFT_eSPI.h>
#include <Preferences.h>
#include "ghost_art.h"   // 1bpp stippled phantom (GHOST_BITS / GHOST_W / GHOST_H / GHOST_ROWBYTES)

// ---------- CYD hardware ----------
#define LED_R 4
#define LED_G 16
#define LED_B 17
#define SPEAKER 26
#define BTN_BOOT 0
#define T_CLK 25
#define T_CS 33
#define T_MOSI 32
#define T_MISO 39
#define T_IRQ 36
#define T_MINX 200
#define T_MAXX 3700
#define T_MINY 240
#define T_MAXY 3800
#define MADCTL_REG 0x36
#define MAD_MV 0x20
#define MAD_BGR 0x08

// ======================================================================
//  Emergency-scanner rules
// ======================================================================
enum Cat : uint8_t { CAT_POLICE=0, CAT_EMS, CAT_FIRE, CAT_VEHICLE, CAT_TRAFFIC, CAT_COUNT };
enum Src : uint8_t { S_BLE=1, S_WIFI=2, S_ANY=3 };
enum Kind : uint8_t { BY_MAC, BY_NAME };
struct Rule { uint8_t src; uint8_t kind; const char *pattern; const char *label; uint8_t cat; };
static const Rule RULES[] = {
  // --- POLICE: body cams, radios, units ---
  {S_ANY,BY_MAC,"00:25:df","Axon device",CAT_POLICE},
  {S_ANY,BY_NAME,"axon","Axon",CAT_POLICE},{S_ANY,BY_NAME,"taser","TASER/Axon",CAT_POLICE},
  {S_ANY,BY_NAME,"signal sidearm","Axon Signal",CAT_POLICE},
  {S_ANY,BY_NAME,"body worn","Body cam",CAT_POLICE},{S_ANY,BY_NAME,"bodyworn","Body cam",CAT_POLICE},
  {S_ANY,BY_NAME,"body cam","Body cam",CAT_POLICE},{S_ANY,BY_NAME,"bodycam","Body cam",CAT_POLICE},
  {S_BLE,BY_NAME,"body 3","Axon Body 3",CAT_POLICE},{S_BLE,BY_NAME,"body 4","Axon Body 4",CAT_POLICE},
  {S_ANY,BY_NAME,"fleet 3","Axon Fleet",CAT_POLICE},
  {S_ANY,BY_NAME,"watchguard","WatchGuard",CAT_POLICE},{S_ANY,BY_NAME,"v300","WatchGuard V300",CAT_POLICE},
  {S_ANY,BY_NAME,"digital ally","Digital Ally",CAT_POLICE},{S_ANY,BY_NAME,"reveal media","Reveal cam",CAT_POLICE},
  {S_ANY,BY_NAME,"apx","Motorola APX",CAT_POLICE},{S_ANY,BY_NAME,"mototrbo","Motorola radio",CAT_POLICE},
  {S_ANY,BY_NAME,"l3harris","L3Harris radio",CAT_POLICE},{S_ANY,BY_NAME,"tait ","Tait radio",CAT_POLICE},
  {S_ANY,BY_NAME,"police","Police",CAT_POLICE},{S_ANY,BY_NAME,"wapol","WA Police",CAT_POLICE},
  {S_ANY,BY_NAME,"patrol","Patrol",CAT_POLICE},
  // --- EMS / ambulance ---
  {S_ANY,BY_NAME,"ambulance","Ambulance",CAT_EMS},{S_ANY,BY_NAME,"paramedic","Paramedic",CAT_EMS},
  {S_ANY,BY_NAME,"st john","St John",CAT_EMS},{S_ANY,BY_NAME,"sjwa","St John WA",CAT_EMS},
  {S_ANY,BY_NAME,"rfds","Flying Doctor",CAT_EMS},{S_ANY,BY_NAME,"lifepak","LIFEPAK",CAT_EMS},
  {S_ANY,BY_NAME,"zoll","ZOLL",CAT_EMS},{S_ANY,BY_NAME,"corpuls","Corpuls",CAT_EMS},
  {S_ANY,BY_NAME,"lucas","LUCAS CPR",CAT_EMS},
  // --- FIRE / SES ---
  {S_ANY,BY_NAME,"dfes","DFES",CAT_FIRE},{S_ANY,BY_NAME,"fesa","FESA",CAT_FIRE},
  {S_ANY,BY_NAME,"fire rescue","Fire Rescue",CAT_FIRE},{S_ANY,BY_NAME,"fire brigade","Fire brigade",CAT_FIRE},
  {S_ANY,BY_NAME,"bushfire","Bushfire",CAT_FIRE},{S_WIFI,BY_NAME,"ses ","SES",CAT_FIRE},
  // --- VEHICLE: in-car routers / rugged laptops ---
  {S_WIFI,BY_MAC,"00:30:44","Cradlepoint",CAT_VEHICLE},{S_WIFI,BY_NAME,"cradlepoint","Cradlepoint",CAT_VEHICLE},
  {S_WIFI,BY_MAC,"00:a0:d5","Sierra AirLink",CAT_VEHICLE},{S_WIFI,BY_NAME,"airlink","Sierra AirLink",CAT_VEHICLE},
  {S_WIFI,BY_NAME,"mp70","AirLink MP70",CAT_VEHICLE},{S_WIFI,BY_NAME,"pepwave","Peplink",CAT_VEHICLE},
  {S_WIFI,BY_NAME,"peplink","Peplink",CAT_VEHICLE},{S_ANY,BY_NAME,"toughbook","Toughbook MDT",CAT_VEHICLE},
  {S_ANY,BY_NAME,"getac","Getac MDT",CAT_VEHICLE},
  // --- TRAFFIC: speed / red-light / ANPR camera gear (networking only, not the radar beam) ---
  {S_ANY,BY_NAME,"redflex","Redflex cam",CAT_TRAFFIC},{S_ANY,BY_NAME,"gatso","Gatso cam",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"jenoptik","Jenoptik cam",CAT_TRAFFIC},{S_ANY,BY_NAME,"vitronic","Vitronic cam",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"sensys","Sensys cam",CAT_TRAFFIC},{S_ANY,BY_NAME,"acusensor","Acusensor",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"safe-t-cam","Safe-T-Cam",CAT_TRAFFIC},{S_ANY,BY_NAME,"speed cam","Speed camera",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"speedcam","Speed camera",CAT_TRAFFIC},{S_ANY,BY_NAME,"mobile speed","Mobile speed",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"anpr","ANPR camera",CAT_TRAFFIC},{S_ANY,BY_NAME,"red light","Red-light cam",CAT_TRAFFIC},
  {S_ANY,BY_NAME,"redlight","Red-light cam",CAT_TRAFFIC},
};
static const char *CAT_TILE[CAT_COUNT] = {"POL","EMS","FIRE","VEH","SPD"};

// ======================================================================
//  Palette  -  pure black + purple
// ======================================================================
#define C_BG     0x0000
#define C_PANEL  0x1083
#define C_PANEL2 0x2165
#define C_LINE   0x38CB
#define C_TXT    0xFFFF
#define C_MUTED  0x8C71
#define C_DIM    0x4228
#define C_PURP   0xBA7F
#define C_PURP2  0x6973
#define C_RED    0xF9A6
static const uint16_t CAT_COL[CAT_COUNT] = {0xBA7F,0xFFFF,0xF9A6,0xFD40,0x07FF};  // POL EMS FIRE VEH SPD

// ======================================================================
//  Device table
// ======================================================================
enum Trk : uint8_t { T_NONE=0, T_AIRTAG, T_FINDMY, T_TILE, T_SMARTTAG };
static const char *TRK_NAME[] = {"", "AirTag", "Find My", "Tile", "SmartTag"};
struct Dev {
  char mac[18]; char name[26]; char src; int rssi;
  uint8_t chan, enc, tracker, cat; bool evilTwin, alarmed;
  uint32_t firstSeen, lastSeen;
};
static const int MAX_DEV=96;
static Dev dev[MAX_DEV];
static int devCount=0;
static portMUX_TYPE mux=portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t lastBleMs=0, lastWifiMs=0;
static volatile int pendingAlert=-1;
static volatile uint32_t deauthCount=0, deauthWindow=0, lastDeauthMs=0;
static uint32_t alertUntil=0; static uint8_t alertCat=0;
static uint32_t trkAlarmUntil=0;

static bool soundOn=true, colorBGR=false;
static bool invertOn=true;      // this CYD panel needs inversion ON for a black background
static bool stealth=false;      // ON = passive (transmit nothing, untraceable); OFF = active scan w/ random MAC
static uint8_t brightness=230;
Preferences prefs;

// ---- saved log (internal flash): trackers that trailed you + emergency hits ----
struct Saved { char mac[18]; char name[20]; uint8_t type; char cat; };  // type=Trk (0=emergency), cat=CAT index or 255
static const int MAX_SAVED=28;
static Saved saved[MAX_SAVED]; static int savedCount=0;
static void loadSaved(); static void persistSaved();
static void saveEntry(const char*,const char*,uint8_t,char); static void clearSaved(); static void autoLog(uint32_t);

TFT_eSPI tft;
TFT_eSprite spr(&tft);
SPIClass tsSPI(VSPI);
XPT2046_Touchscreen ts(T_CS, T_IRQ);
NimBLEScan *bleScan;

// ======================================================================
//  Ingest
// ======================================================================
static void lowerCopy(char*d,const char*s,size_t n){size_t i=0;for(;s[i]&&i<n-1;i++)d[i]=tolower((uint8_t)s[i]);d[i]=0;}
static const Rule* matchRule(char src,const char*macL,const char*name){
  char low[40]; lowerCopy(low,name,sizeof(low)); uint8_t s=src=='B'?S_BLE:S_WIFI;
  for(auto&r:RULES){ if(!(r.src&s))continue;
    if(r.kind==BY_MAC){ if(!strncmp(macL,r.pattern,strlen(r.pattern)))return &r; }
    else if(low[0]&&strstr(low,r.pattern))return &r; }
  return nullptr;
}
static int findDev(const char*m){ for(int i=0;i<devCount;i++)if(!strcmp(dev[i].mac,m))return i; return -1; }
static int newSlot(){ if(devCount<MAX_DEV)return devCount++; int s=0;
  for(int i=1;i<MAX_DEV;i++)if(dev[i].lastSeen<dev[s].lastSeen)s=i; return s; }
static uint8_t classifyTracker(NimBLEAdvertisedDevice*d){
  if(d->haveManufacturerData()){ std::string m=d->getManufacturerData();
    if(m.size()>=3&&(uint8_t)m[0]==0x4C&&(uint8_t)m[1]==0x00&&(uint8_t)m[2]==0x12) return T_FINDMY; }  // Apple Find My offline-finding (AirTag etc)
  for(int i=0;i<d->getServiceUUIDCount();i++){ NimBLEUUID u=d->getServiceUUID(i);
    if(u==NimBLEUUID((uint16_t)0xFEED))return T_TILE;
    if(u==NimBLEUUID((uint16_t)0xFD5A)||u==NimBLEUUID((uint16_t)0xFD59))return T_SMARTTAG; }
  return T_NONE;
}
// A tracker counts as "trailing you" only if it is CLOSE and has stayed with
// you a long time. Find My beacons from passing phones/AirPods are detected but
// won't trip a threat unless they're close (>-70dBm) for 5+ minutes.
static bool isTrail(const Dev&d,uint32_t now){
  return d.tracker && now-d.lastSeen<30000 && (now-d.firstSeen)>300000 && d.rssi>-70;
}
static void observe(char src,const char*mac,const char*name,int rssi,uint8_t chan,uint8_t enc,uint8_t trk){
  char macL[18]; lowerCopy(macL,mac,sizeof(macL)); uint32_t now=millis();
  const Rule*r=matchRule(src,macL,name); bool isNew=false;
  portENTER_CRITICAL(&mux);
  int i=findDev(macL);
  if(i<0){ i=newSlot(); Dev&d=dev[i]; memset(&d,0,sizeof(d));
    strlcpy(d.mac,macL,sizeof(d.mac)); d.firstSeen=now; d.cat=r?r->cat:255; isNew=r!=nullptr; }
  Dev&d=dev[i];
  if(name[0])strlcpy(d.name,name,sizeof(d.name));
  d.src=src; d.rssi=rssi; d.chan=chan; d.enc=enc; d.lastSeen=now;
  if(trk)d.tracker=trk; if(r)d.cat=r->cat;
  if(src=='W'&&name[0]) for(int k=0;k<devCount;k++)
    if(k!=i&&dev[k].src=='W'&&!strcmp(dev[k].name,name)&&strcmp(dev[k].mac,macL)){d.evilTwin=true;dev[k].evilTwin=true;}
  if(isNew&&(pendingAlert<0||r->cat<pendingAlert))pendingAlert=r->cat;
  portEXIT_CRITICAL(&mux);
}
class BleCB : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice*d) override { lastBleMs=millis();
    std::string mac=d->getAddress().toString(); std::string nm=d->haveName()?d->getName():"";
    observe('B',mac.c_str(),nm.c_str(),d->getRSSI(),0,0,classifyTracker(d)); }
};
// Replace the factory MAC with a random locally-administered one, so probe/scan
// requests never carry the hardware's real identity. Rotated periodically for
// unlinkability across time.
static void randomizeMac(){ uint8_t m[6]; for(int i=0;i<6;i++)m[i]=esp_random()&0xFF;
  m[0]=(m[0]&0xFE)|0x02; esp_wifi_set_mac(WIFI_IF_STA,m); }
static void wifiScanStep(){ static uint32_t st=0, lastMac=0; int n=WiFi.scanComplete();
  uint32_t now=millis();
  if(now-lastMac>180000){ lastMac=now; randomizeMac(); }           // new random identity every 3 min
  if(n>=0){ lastWifiMs=now;
    for(int i=0;i<n;i++) observe('W',WiFi.BSSIDstr(i).c_str(),WiFi.SSID(i).c_str(),WiFi.RSSI(i),
      WiFi.channel(i),WiFi.encryptionType(i)==WIFI_AUTH_OPEN?0:1,0);
    WiFi.scanDelete(); st=0;
  } else if(n==WIFI_SCAN_FAILED&&now-st>5000){ st=now;
    WiFi.scanNetworks(true,true,stealth,stealth?120:120); }        // stealth=true -> passive (sends nothing)
}
static void IRAM_ATTR promiscCB(void*buf,wifi_promiscuous_pkt_type_t type){
  if(type!=WIFI_PKT_MGMT)return; const wifi_promiscuous_pkt_t*p=(wifi_promiscuous_pkt_t*)buf;
  uint8_t sub=(p->payload[0]>>4)&0xF; if(sub==0x0C||sub==0x0A){deauthCount++;lastDeauthMs=millis();}
}

// ======================================================================
//  Output primitives
// ======================================================================
static void setLed(bool r,bool g,bool b){digitalWrite(LED_R,r?LOW:HIGH);digitalWrite(LED_G,g?LOW:HIGH);digitalWrite(LED_B,b?LOW:HIGH);}
static void tone_(int f,int ms){if(!soundOn)return;ledcWriteTone(0,f);delay(ms);ledcWriteTone(0,0);}
static void beepTap(){if(soundOn){ledcWriteTone(0,2600);delay(7);ledcWriteTone(0,0);}}
static void alertSound(uint8_t c){switch(c){
  case CAT_POLICE:for(int i=0;i<3;i++){tone_(1800,80);tone_(2600,80);}break;
  case CAT_EMS:for(int i=0;i<2;i++){tone_(1400,160);tone_(1000,160);}break;
  case CAT_FIRE:tone_(900,110);tone_(1500,110);tone_(2100,220);break;
  default:tone_(2000,70);} }
static void trackerAlarm(){for(int i=0;i<4;i++){tone_(2600,70);tone_(1900,70);}}
static void setBright(uint8_t b){ledcWrite(1,b);}
static void applyColorOrder(){ tft.writecommand(MADCTL_REG); uint8_t m=MAD_MV; if(colorBGR)m|=MAD_BGR; tft.writedata(m); }

static TFT_eSPI *G=&tft; static int OY=0, bandH=0;
#define Y(v) ((v)+OY)
static void px(const char*s,int x,int y,uint16_t c,uint8_t size,uint8_t d){
  G->setTextFont(1); G->setTextSize(size); G->setTextColor(c); G->setTextDatum(d); G->drawString(s,x,Y(y)); G->setTextSize(1);
}
static int rssiLvl(int r){return r>-55?5:r>-65?4:r>-75?3:r>-85?2:1;}
static void bars(int x,int y,int lvl,uint16_t on,int w,int gap,int mh){for(int i=0;i<5;i++){int h=mh*(i+1)/5;G->fillRect(x+i*(w+gap),Y(y+mh-h),w,h,i<lvl?on:C_LINE);}}
static void fmtAgo(char*b,size_t n,uint32_t ms){uint32_t s=ms/1000;if(s<3)snprintf(b,n,"live");else if(s<60)snprintf(b,n,"%lus",(unsigned long)s);else snprintf(b,n,"%lum",(unsigned long)(s/60));}
static uint32_t hashStr(const char*s){uint32_t h=5381;while(*s)h=h*33+(uint8_t)*s++;return h;}

static void drawGhost(int cx,int topY,int R,int H,uint16_t col){
  G->fillCircle(cx,Y(topY+R),R,col);
  G->fillRect(cx-R,Y(topY+R),2*R+1,H,col);
  int by=topY+R+H, n=4, sw=(2*R)/n;
  for(int i=0;i<=n;i++) G->fillCircle(cx-R+i*sw,Y(by),sw/2,C_BG);
  int ew=R/4; if(ew<2)ew=2; int eh=R/2, ey=topY+R-eh/2;
  G->fillRoundRect(cx-R/2,Y(ey),ew,eh,ew/2,C_BG);
  G->fillRoundRect(cx+R/2-ew,Y(ey),ew,eh,ew/2,C_BG);
}
static void radar(int cx,int cy,int R,uint32_t now,int filterTrk,int filterCat){
  for(int r=R/3;r<=R;r+=R/3)G->drawCircle(cx,Y(cy),r,C_LINE);
  G->drawFastHLine(cx-R,Y(cy),2*R+1,C_LINE); G->drawFastVLine(cx,Y(cy)-R,2*R+1,C_LINE);
  float a=(now%2600)/2600.0f*TWO_PI;
  for(int k=6;k>=0;k--){ float b=a-k*0.09f; uint8_t v=200-k*26;
    uint16_t tc=G->color565((0xBA)*v/255,(0x48)*v/255,(0xFF)*v/255);
    G->drawLine(cx,Y(cy),cx+cosf(b)*R,Y(cy)+sinf(b)*R,tc); }
  portENTER_CRITICAL(&mux); int dc=devCount; static Dev snap[MAX_DEV]; memcpy(snap,dev,sizeof(Dev)*dc); portEXIT_CRITICAL(&mux);
  for(int i=0;i<dc;i++){ Dev&d=snap[i];
    if(now-d.lastSeen>30000)continue;
    if(filterTrk>=0&&d.tracker==0)continue;
    if(filterCat>=0&&d.cat>=CAT_COUNT)continue;
    float ang=(hashStr(d.mac)%360)*DEG_TO_RAD;
    int rr=map(constrain(d.rssi,-100,-40),-100,-40,R-3,5);
    uint16_t bc=d.cat<CAT_COUNT?CAT_COL[d.cat]:C_PURP;
    int bx=cx+cosf(ang)*rr, by=cy+sinf(ang)*rr; bool nr=(a<ang+0.12f&&a>ang-0.12f);
    G->fillCircle(bx,Y(by),nr?3:2,bc); if(nr)G->drawCircle(bx,Y(by),5,bc); }
  G->fillCircle(cx,Y(cy),2,C_PURP);
}
// top-facing arc for the Wi-Fi glyph
static void iarc(int cx,int cy,int r,uint16_t c){
  for(float a=-2.45f;a<=-0.69f;a+=0.07f){ int x=cx+(int)(cosf(a)*r), yv=cy+(int)(sinf(a)*r);
    G->drawPixel(x,Y(yv),c); G->drawPixel(x,Y(yv)+1,c); }
}
// All icons apply Y() so they land in the correct render band.
static void icon(char k,int cx,int cy,uint16_t c){
  switch(k){
    case 'D': drawGhost(cx,cy-11,9,8,c); break;                                            // ghost (uses Y internally)
    case 'S': G->drawCircle(cx,Y(cy),12,c);G->drawCircle(cx,Y(cy),6,c);
              G->drawLine(cx,Y(cy),cx+9,Y(cy-8),c);G->fillCircle(cx,Y(cy),2,c); break;     // radar
    case 'W': iarc(cx,cy+7,13,c);iarc(cx,cy+7,9,c);iarc(cx,cy+7,5,c);G->fillCircle(cx,Y(cy+7),2,c); break; // wifi arcs
    case 'B': { int t=cy-11,b=cy+11,q1=cy-5,q3=cy+5,w=7,lx=cx-6;                            // bluetooth rune
              G->drawLine(cx,Y(t),cx,Y(b),c);
              G->drawLine(cx,Y(t),cx+w,Y(q1),c);G->drawLine(cx+w,Y(q1),cx,Y(cy),c);
              G->drawLine(cx,Y(cy),cx+w,Y(q3),c);G->drawLine(cx+w,Y(q3),cx,Y(b),c);
              G->drawLine(lx,Y(q1),cx+w,Y(q3),c);G->drawLine(lx,Y(q3),cx+w,Y(q1),c); } break;
    case 'G': G->drawCircle(cx,Y(cy),8,c);G->fillCircle(cx,Y(cy),3,c);                      // gear
              for(int i=0;i<8;i++){float a=i*PI/4;G->drawLine(cx+(int)(cosf(a)*8),Y(cy)+(int)(sinf(a)*8),cx+(int)(cosf(a)*12),Y(cy)+(int)(sinf(a)*12),c);} break;
    case 'i': G->drawCircle(cx,Y(cy),11,c); px("i",cx,cy-1,c,2,MC_DATUM); break;            // about
    case 'H': G->drawCircle(cx,Y(cy),10,c);G->drawCircle(cx,Y(cy),4,c);                      // crosshair (locate)
              G->drawLine(cx-14,Y(cy),cx-6,Y(cy),c);G->drawLine(cx+6,Y(cy),cx+14,Y(cy),c);
              G->drawLine(cx,Y(cy-14),cx,Y(cy-6),c);G->drawLine(cx,Y(cy+6),cx,Y(cy+14),c);
              G->fillCircle(cx,Y(cy),1,c); break;
  }
}

// ======================================================================
//  Touch (tap only)
// ======================================================================
enum View { V_HOME, V_TRACK, V_SCANNER, V_WIFI, V_BT, V_SET, V_ABOUT, V_SAVED, V_HUNT, V_COUNT };
static uint8_t view=V_HOME;
static int pageIdx[V_COUNT]={0};
static bool pressed=false, moved=false; static int pressX,pressY; static uint32_t pressMs;
static int tapX=-1, tapY=-1; static bool gDown=false; static int gX=0,gY=0;
static bool settingsDirty=false;
static char huntMac[18]={0}; static bool hunting=false; static float huntSm=-100;   // LOCATE target

static bool readTouch(int&sx,int&sy){ if(!ts.touched())return false; TS_Point p=ts.getPoint();
  if(p.z<200)return false;
  sx=constrain((int)map(p.x,T_MINX,T_MAXX,0,320),0,319);
  sy=constrain((int)map(p.y,T_MINY,T_MAXY,0,240),0,239); return true; }
static void handleTouch(){ int x,y; bool d=readTouch(x,y);
  gDown=d; if(d){gX=x;gY=y;}
  if(d){ if(!pressed){pressed=true;moved=false;pressX=x;pressY=y;pressMs=millis();}
    if(abs(x-pressX)>8||abs(y-pressY)>8)moved=true; }
  else if(pressed){ pressed=false;
    if(!moved&&millis()-pressMs<700){tapX=pressX;tapY=pressY;}
    if(view==V_SET)settingsDirty=true; }
}
static bool tapIn(int x,int y,int w,int h){return tapX>=0&&tapX>=x&&tapX<x+w&&tapY>=y&&tapY<y+h;}

// ======================================================================
//  Header, pager, home
// ======================================================================
static const char *VNAME[V_COUNT]={"PHANTOM","DEFENSE","SCANNER","WI-FI","BLUETOOTH","SETTINGS","ABOUT","SAVED LOG","LOCATE"};
static void header(bool back){
  G->drawFastHLine(0,Y(26),320,C_PURP2);
  if(back){ px("<",12,13,C_PURP,2,MC_DATUM); px(VNAME[view],34,13,C_TXT,2,ML_DATUM); }
  else px("PHANTOM",10,13,C_PURP,2,ML_DATUM);
  uint32_t now=millis(); bool ble=now-lastBleMs<3000, wf=now-lastWifiMs<15000;
  G->fillCircle(300,Y(13),4,ble?C_PURP:C_DIM); G->fillCircle(312,Y(13),4,wf?C_PURP:C_DIM);
}
static int pager(int total,int perPage){
  int pages=(total+perPage-1)/perPage; if(pages<1)pages=1;
  int &pg=pageIdx[view]; if(pg>=pages)pg=pages-1; if(pg<0)pg=0;
  if(pages>1){ G->drawFastHLine(0,Y(214),320,C_LINE);
    bool l=pg>0,r=pg<pages-1;
    px("<",30,226,l?C_PURP:C_DIM,2,MC_DATUM);
    px(">",290,226,r?C_PURP:C_DIM,2,MC_DATUM);
    char b[12]; snprintf(b,sizeof(b),"%d/%d",pg+1,pages); px(b,160,226,C_MUTED,1,MC_DATUM);
    if(tapIn(10,216,50,24)&&l){pg--;beepTap();}
    if(tapIn(270,216,50,24)&&r){pg++;beepTap();} }
  return pg*perPage;
}

struct App{const char*name;char icon;View view;};
static const App APPS[]={
  {"DEFENSE",'D',V_TRACK},{"SCANNER",'S',V_SCANNER},{"WI-FI",'W',V_WIFI},
  {"BLUETOOTH",'B',V_BT},{"SETTINGS",'G',V_SET},{"LOCATE",'H',V_HUNT},
};
static const char *APP_SUB[6]={"tracker watch","police radar","rogue & deauth","nearby BLE","colour / light","hunt a signal"};
static void drawHome(uint32_t now){
  int trail=0,wifi=0,bt=0;
  portENTER_CRITICAL(&mux); int dc=devCount;
  for(int i=0;i<dc;i++){ if(now-dev[i].lastSeen>30000)continue;
    if(dev[i].src=='W')wifi++; else bt++; if(isTrail(dev[i],now))trail++; }
  portEXIT_CRITICAL(&mux);
  if(tapIn(0,0,120,26)){ view=V_ABOUT; beepTap(); }        // tap PHANTOM header -> about
  const int gx=8, gy=34, cw=152, ch=64, gap=5;    // big buttons, fill the screen
  for(int i=0;i<6;i++){ int col=i%2,row=i/2;
    int x=gx+col*(cw+gap), y=gy+row*(ch+gap);
    bool tp=tapIn(x,y,cw,ch);
    G->drawRoundRect(x-1,Y(y-1),cw+2,ch+2,8,tp?C_PURP:C_LINE);          // outer halo
    G->fillRoundRect(x,Y(y),cw,ch,7,tp?C_PANEL2:C_PANEL);
    G->fillRoundRect(x,Y(y),4,ch,2,C_PURP);                            // accent bar
    G->drawFastHLine(x+8,Y(y+2),cw-16,C_LINE);                         // top sheen
    if(tp){ G->drawRoundRect(x,Y(y),cw,ch,7,C_PURP); G->drawRoundRect(x+1,Y(y+1),cw-2,ch-2,6,C_PURP2); }
    icon(APPS[i].icon,x+28,y+32,C_PURP);
    px(APPS[i].name,x+52,y+22,C_TXT,1,TL_DATUM);
    px(APP_SUB[i],x+52,y+36,C_MUTED,1,TL_DATUM);
    int cnt=APPS[i].view==V_TRACK?trail:APPS[i].view==V_WIFI?wifi:APPS[i].view==V_BT?bt:-1;
    if(cnt>=0){ char b[8];snprintf(b,sizeof(b),"%d",cnt);
      px(b,x+cw-12,y+20,(cnt&&APPS[i].view==V_TRACK)?C_RED:C_PURP,2,MR_DATUM); }
    else px(">",x+cw-12,y+20,C_PURP2,2,MR_DATUM);
    if(tp){view=APPS[i].view;pageIdx[view]=0;beepTap();}
  }
}

// ======================================================================
//  App: Defense
// ======================================================================
static void appDefense(uint32_t now){
  static Dev t[MAX_DEV]; int tn=0,trail=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].tracker&&now-dev[i].lastSeen<60000){ t[tn++]=dev[i]; if(isTrail(dev[i],now))trail++; }
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<tn;i++)for(int j=i+1;j<tn;j++)if(t[j].rssi>t[i].rssi){Dev x=t[i];t[i]=t[j];t[j]=x;}
  bool threat=trail>0;
  G->fillRoundRect(8,Y(30),304,28,7,C_PANEL); G->drawRoundRect(8,Y(30),304,28,7,threat?C_RED:C_PURP);
  px(threat?"THREAT":"SECURE",16,44,threat?C_RED:C_PURP,2,ML_DATUM);
  char s[20]; snprintf(s,sizeof(s),"%d TRAILING",trail); px(s,304,44,threat?C_RED:C_MUTED,1,MR_DATUM);
  // radar left
  radar(72,140,46,now,1,-1);
  char n[16]; snprintf(n,sizeof(n),"%d FIND MY",tn); px(n,72,196,C_PURP,1,MC_DATUM);
  px("incl phones",72,208,C_DIM,1,MC_DATUM);
  // tracker list right
  const int lx=130;
  if(!tn){ px("no trackers nearby",lx+92,138,C_MUTED,1,MC_DATUM); return; }
  int rows=tn<4?tn:4;
  for(int k=0;k<rows;k++){ Dev&d=t[k]; int y=66+k*36; bool fol=isTrail(d,now); uint16_t cc=fol?C_RED:C_PURP;
    G->fillRoundRect(lx,Y(y),182,32,6,fol?0x3000:C_PANEL); if(fol)G->drawRoundRect(lx,Y(y),182,32,6,C_RED);
    G->fillRect(lx,Y(y),3,32,cc);
    px(TRK_NAME[d.tracker],lx+8,y+5,fol?C_RED:C_TXT,1,TL_DATUM);
    if(fol)px("TRAILING",lx+174,y+5,C_RED,1,TR_DATUM);
    uint32_t dur=(now-d.firstSeen)/1000; char du[16];
    if(dur<60)snprintf(du,sizeof(du),"%lus near",(unsigned long)dur); else snprintf(du,sizeof(du),"%lum near",(unsigned long)(dur/60));
    px(du,lx+8,y+19,C_MUTED,1,TL_DATUM);
    bars(lx+152,y+17,rssiLvl(d.rssi),cc,4,2,12); }
  if(tn>4){ char m[12];snprintf(m,sizeof(m),"+%d more",tn-4);px(m,lx+90,210,C_DIM,1,MC_DATUM); }
}

// ======================================================================
//  App: Scanner (radar + counts + detected list)
// ======================================================================
static void appScanner(uint32_t now){
  static Dev h[MAX_DEV]; int hn=0; int cnt[CAT_COUNT]={0};
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].cat<CAT_COUNT&&now-dev[i].lastSeen<60000){ h[hn++]=dev[i]; cnt[dev[i].cat]++; }
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<hn;i++)for(int j=i+1;j<hn;j++)if(h[j].rssi>h[i].rssi){Dev x=h[i];h[i]=h[j];h[j]=x;}
  radar(160,74,42,now,-1,1);
  for(int c=0;c<CAT_COUNT;c++){ int x=6+c*62; G->fillCircle(x+3,Y(126),3,CAT_COL[c]);
    char s[12]; snprintf(s,sizeof(s),"%s %d",CAT_TILE[c],cnt[c]); px(s,x+10,122,cnt[c]?C_TXT:C_DIM,1,TL_DATUM); }
  G->drawFastHLine(8,Y(138),304,C_LINE);
  if(!hn){ px("no emergency gear detected",160,172,C_MUTED,1,MC_DATUM); return; }
  int rows=hn<3?hn:3;
  for(int k=0;k<rows;k++){ Dev&d=h[k]; int y=144+k*23; uint16_t cc=CAT_COL[d.cat];
    G->fillRect(8,Y(y),3,20,cc);
    px(CAT_TILE[d.cat],14,y+2,cc,1,TL_DATUM);
    px(d.name[0]?d.name:"(unnamed)",48,y+2,C_TXT,1,TL_DATUM);
    char ago[10]; fmtAgo(ago,sizeof(ago),now-d.lastSeen); px(ago,236,y+2,C_MUTED,1,TL_DATUM);
    bars(282,y+2,rssiLvl(d.rssi),cc,5,3,16); }
  if(hn>3){ char m[16]; snprintf(m,sizeof(m),"+%d more",hn-3); px(m,160,214,C_DIM,1,MC_DATUM); }
}

// ======================================================================
//  App: Wi-Fi  (paginated)
// ======================================================================
static void appWifi(uint32_t now){
  static Dev a[MAX_DEV]; int an=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].src=='W'&&now-dev[i].lastSeen<30000) a[an++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<an;i++)for(int j=i+1;j<an;j++)if(a[j].rssi>a[i].rssi){Dev x=a[i];a[i]=a[j];a[j]=x;}
  bool deauth=now-lastDeauthMs<4000&&deauthWindow>8; int evil=0;for(int i=0;i<an;i++)if(a[i].evilTwin)evil++;
  int top=32;
  if(deauth||evil){ G->fillRoundRect(8,Y(30),304,22,6,C_PANEL); G->drawRoundRect(8,Y(30),304,22,6,C_RED);
    char w[40]; if(deauth)snprintf(w,sizeof(w),"DEAUTH ATTACK %lu/s",(unsigned long)deauthWindow);
    else snprintf(w,sizeof(w),"EVIL TWIN x%d",evil);
    px(w,160,41,C_RED,1,MC_DATUM); top=58; }
  if(!an){ px("SCANNING WI-FI...",160,120,C_MUTED,1,MC_DATUM); return; }
  const int rowH=30, perPage=(214-top)/rowH; int start=pager(an,perPage);
  for(int k=0;k<perPage;k++){ int i=start+k; if(i>=an)break; Dev&d=a[i]; int y=top+k*rowH;
    uint16_t sd=d.evilTwin?C_RED:d.enc?C_PURP:C_MUTED;
    G->fillRect(8,Y(y),3,rowH-5,sd);
    px(d.name[0]?d.name:"(hidden)",16,y,d.name[0]?C_TXT:C_MUTED,1,TL_DATUM);
    char s[40]; snprintf(s,sizeof(s),"CH%-3d %s",d.chan,d.enc?"SECURED":"OPEN");
    px(s,16,y+11,d.enc?C_MUTED:C_RED,1,TL_DATUM);
    bars(276,y+2,rssiLvl(d.rssi),sd,5,3,16); }
}

// ======================================================================
//  App: Bluetooth (paginated)
// ======================================================================
static void appBt(uint32_t now){
  static Dev ds[MAX_DEV]; int dn=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].src=='B'&&now-dev[i].lastSeen<30000) ds[dn++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<dn;i++)for(int j=i+1;j<dn;j++)if(ds[j].rssi>ds[i].rssi){Dev x=ds[i];ds[i]=ds[j];ds[j]=x;}
  if(!dn){ px("SCANNING BLUETOOTH...",160,120,C_MUTED,1,MC_DATUM); return; }
  const int top=32,rowH=30, perPage=(214-top)/rowH; int start=pager(dn,perPage);
  for(int k=0;k<perPage;k++){ int i=start+k; if(i>=dn)break; Dev&d=ds[i]; int y=top+k*rowH;
    uint16_t fc=d.tracker?C_PURP:(d.cat<CAT_COUNT?CAT_COL[d.cat]:C_PURP2);
    G->fillRect(8,Y(y),3,rowH-5,fc);
    px(d.name[0]?d.name:"(no name)",16,y,d.name[0]?C_TXT:C_MUTED,1,TL_DATUM);
    px(d.mac,16,y+11,C_MUTED,1,TL_DATUM);
    if(d.tracker)px(TRK_NAME[d.tracker],312,y,C_PURP,1,TR_DATUM);          // tag on top line
    else if(d.cat<CAT_COUNT)px(CAT_TILE[d.cat],312,y,CAT_COL[d.cat],1,TR_DATUM);
    bars(282,y+13,rssiLvl(d.rssi),fc,5,3,12); }                           // bars on bottom line
}

// ======================================================================
//  App: Settings
// ======================================================================
// slim row helpers
static void rowBox(int x,int w,int y,int rh){ G->fillRoundRect(x,Y(y),w,rh,5,C_PANEL); }
static void pill(int x,int w,int y,int rh,bool on){ int pw=40,ph=18,px0=x+w-pw-10,py=y+(rh-ph)/2;
  G->fillRoundRect(px0,Y(py),pw,ph,ph/2,on?C_PURP:C_LINE); G->fillCircle(on?px0+pw-ph/2:px0+ph/2,Y(py+ph/2),ph/2-2,C_BG); }
static bool pillTap(int x,int w,int y,int rh){ return tapIn(x+w-60,y,56,rh); }

static void appSettings(uint32_t now){
  const int x=8,w=304,rh=26; int y=30;
  // COLOUR (RGB/BGR)
  rowBox(x,w,y,rh); px("COLOUR",x+12,y+rh/2,C_TXT,1,ML_DATUM);
  for(int i=0;i<2;i++){bool on=(i==1)==colorBGR;int bx=x+w-104+i*50;
    G->fillRoundRect(bx,Y(y+4),46,rh-8,4,on?C_PURP:C_LINE);
    px(i?"BGR":"RGB",bx+23,y+rh/2,on?C_BG:C_MUTED,1,MC_DATUM);
    if(tapIn(bx,y+1,48,rh-1)){colorBGR=i;applyColorOrder();settingsDirty=true;beepTap();}}
  y+=rh+4;
  // STEALTH (passive, sends nothing)
  rowBox(x,w,y,rh); px("STEALTH",x+12,y+rh/2-3,C_TXT,1,ML_DATUM);
  px(stealth?"silent / untraceable":"active scan + rand MAC",x+12,y+rh/2+6,C_MUTED,1,ML_DATUM);
  pill(x,w,y,rh,stealth);
  if(pillTap(x,w,y,rh)){ stealth=!stealth; bleScan->setActiveScan(!stealth); bleScan->stop(); bleScan->start(0,nullptr,false); settingsDirty=true; beepTap(); }
  y+=rh+4;
  // INVERT
  rowBox(x,w,y,rh); px("INVERT",x+12,y+rh/2,C_TXT,1,ML_DATUM); pill(x,w,y,rh,invertOn);
  if(pillTap(x,w,y,rh)){invertOn=!invertOn;tft.invertDisplay(invertOn);settingsDirty=true;beepTap();}
  y+=rh+4;
  // BRIGHTNESS (drag)
  rowBox(x,w,y,rh+4); px("BRIGHT",x+12,y+9,C_TXT,1,ML_DATUM);
  int bx=x+70,bw=w-84,by=y+(rh+4)/2;
  G->fillRoundRect(bx,Y(by-2),bw,5,2,C_LINE);
  if(gDown&&gX>=bx-12&&gX<=bx+bw+12&&gY>=y&&gY<=y+rh+6){brightness=constrain((int)map(gX,bx,bx+bw,25,255),25,255);setBright(brightness);settingsDirty=true;}
  int fw=map(brightness,25,255,6,bw); G->fillRoundRect(bx,Y(by-2),fw,5,2,C_PURP); G->fillCircle(bx+fw,Y(by),7,C_PURP);
  y+=rh+8;
  // SOUND
  rowBox(x,w,y,rh); px("SOUND",x+12,y+rh/2,C_TXT,1,ML_DATUM); pill(x,w,y,rh,soundOn);
  if(pillTap(x,w,y,rh)){soundOn=!soundOn;settingsDirty=true;beepTap();}
  y+=rh+4;
  // SAVED LOG (nav)
  rowBox(x,w,y,rh); char s[28]; snprintf(s,sizeof(s),"SAVED LOG  %d",savedCount);
  px(s,x+12,y+rh/2,C_PURP,1,ML_DATUM); px(">",x+w-14,y+rh/2,C_PURP,2,MR_DATUM);
  if(tapIn(x,y,w,rh)){view=V_SAVED;pageIdx[V_SAVED]=0;beepTap();}
  y+=rh+4;
  // CLEAR live detections
  rowBox(x,w,y,rh-2); px("CLEAR DETECTIONS",x+12,y+(rh-2)/2,C_RED,1,ML_DATUM); px(">",x+w-14,y+(rh-2)/2,C_RED,2,MR_DATUM);
  if(tapIn(x,y,w,rh-2)){portENTER_CRITICAL(&mux);devCount=0;portEXIT_CRITICAL(&mux);beepTap();}
}

// ======================================================================
//  App: Saved log
// ======================================================================
static void appSaved(uint32_t now){
  // clear button
  G->fillRoundRect(8,Y(30),304,22,6,C_PANEL); px("CLEAR SAVED LOG",160,41,C_RED,1,MC_DATUM);
  if(tapIn(8,30,304,22)){clearSaved();beepTap();}
  if(!savedCount){ px("NOTHING SAVED YET",160,120,C_MUTED,1,MC_DATUM);
    px("Trailing tags and police hits",160,138,C_DIM,1,MC_DATUM);
    px("auto-save here.",160,150,C_DIM,1,MC_DATUM); return; }
  const int top=58,rowH=26; int perPage=(206-top)/rowH; int start=pager(savedCount,perPage);
  for(int k=0;k<perPage;k++){ int i=start+k; if(i>=savedCount)break; Saved&s=saved[i]; int y=top+k*rowH;
    bool trk=s.type!=0; uint16_t cc=trk?C_PURP:((uint8_t)s.cat<CAT_COUNT?CAT_COL[(uint8_t)s.cat]:C_MUTED);
    G->fillRect(8,Y(y),3,rowH-5,cc);
    const char*tag=trk?TRK_NAME[s.type]:((uint8_t)s.cat<CAT_COUNT?CAT_TILE[(uint8_t)s.cat]:"?");
    px(tag,16,y,cc,1,TL_DATUM); px(s.name,74,y,C_TXT,1,TL_DATUM); px(s.mac,16,y+11,C_MUTED,1,TL_DATUM); }
}

// ======================================================================
//  App: About
// ======================================================================
static void appAbout(uint32_t now){
  drawGhost(160,46,26,22,C_PURP);
  px("PHANTOM",160,112,C_PURP,3,MC_DATUM);
  px("v5.0  -  ACTIVE SCAN",160,140,C_MUTED,1,MC_DATUM);
  px("BLE + Wi-Fi recon (sends",160,164,C_MUTED,1,MC_DATUM);
  px("random MAC). Stealth=silent.",160,180,C_MUTED,1,MC_DATUM);
  px("Counter-surveillance tool.",160,196,C_MUTED,1,MC_DATUM);
}

// ======================================================================
//  App: Locate  -  pick a signal, then home in on it (Geiger-style)
// ======================================================================
static void appHunt(uint32_t now){
  if(!hunting){
    static Dev c[MAX_DEV]; int cn=0;
    portENTER_CRITICAL(&mux);
    for(int i=0;i<devCount;i++) if(now-dev[i].lastSeen<30000) c[cn++]=dev[i];
    portEXIT_CRITICAL(&mux);
    for(int i=0;i<cn;i++)for(int j=i+1;j<cn;j++){ bool bi=c[i].tracker>0,bj=c[j].tracker>0;
      if((bj&&!bi)||(bj==bi&&c[j].rssi>c[i].rssi)){Dev x=c[i];c[i]=c[j];c[j]=x;} }
    px("PICK A SIGNAL TO LOCATE",160,36,C_PURP,1,MC_DATUM);
    if(!cn){ px("nothing nearby yet",160,120,C_MUTED,1,MC_DATUM); return; }
    const int top=52,rowH=28,perPage=(214-top)/rowH; int start=pager(cn,perPage);
    for(int k=0;k<perPage;k++){ int i=start+k; if(i>=cn)break; Dev&d=c[i]; int y=top+k*rowH;
      bool tp=tapIn(8,y,304,rowH-4);
      uint16_t cc=d.tracker?C_PURP:(d.cat<CAT_COUNT?CAT_COL[d.cat]:C_PURP2);
      G->fillRoundRect(8,Y(y),304,rowH-4,5,tp?C_PANEL2:C_PANEL); G->fillRect(8,Y(y),3,rowH-4,cc);
      const char*nm=d.name[0]?d.name:(d.tracker?TRK_NAME[d.tracker]:"(no name)");
      px(nm,16,y+3,C_TXT,1,TL_DATUM);
      char sub[34]; snprintf(sub,sizeof(sub),"%c %s %ddBm",d.src,d.mac,d.rssi); px(sub,16,y+14,C_MUTED,1,TL_DATUM);
      bars(284,y+4,rssiLvl(d.rssi),cc,4,2,14);
      if(tp){ strlcpy(huntMac,d.mac,sizeof(huntMac)); hunting=true; huntSm=d.rssi; beepTap(); } }
    return;
  }
  // locked on a target
  Dev tgt; bool found=false; uint32_t age=999999;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(!strcmp(dev[i].mac,huntMac)){ tgt=dev[i]; found=true; age=now-dev[i].lastSeen; break; }
  portEXIT_CRITICAL(&mux);
  G->fillRoundRect(8,Y(212),304,24,6,C_PANEL); px("< CHANGE TARGET",160,224,C_PURP,1,MC_DATUM);
  if(tapIn(8,210,304,28)){ hunting=false; beepTap(); return; }
  if(!found){ px("target not seen",160,120,C_MUTED,1,MC_DATUM); return; }
  const char*nm=tgt.name[0]?tgt.name:(tgt.tracker?TRK_NAME[tgt.tracker]:"TARGET");
  px(nm,160,36,C_TXT,2,MC_DATUM);
  bool live=age<8000;
  if(live) huntSm=huntSm*0.7f+tgt.rssi*0.3f;
  int rssi=(int)huntSm, lvl=rssiLvl(rssi);
  const char*heat; uint16_t hc;
  if(!live){heat="SIGNAL LOST";hc=C_DIM;}
  else if(rssi>-55){heat="VERY HOT";hc=C_RED;}
  else if(rssi>-67){heat="HOT";hc=0xFD40;}
  else if(rssi>-78){heat="WARM";hc=C_PURP;}
  else {heat="COLD";hc=C_PURP2;}
  int cx=160,cy=116;
  for(int r=1;r<=5;r++){ uint16_t col=(live&&r<=lvl)?hc:C_LINE;
    G->drawCircle(cx,Y(cy),r*11,col); if(live&&r<=lvl)G->drawCircle(cx,Y(cy),r*11-1,col); }
  G->fillCircle(cx,Y(cy),5,live?hc:C_DIM);
  px(heat,cx,182,hc,2,MC_DATUM);
  float dist=powf(10.0f,(-59.0f-rssi)/(10.0f*2.5f));
  char sub[28]; if(live){ if(dist<1.0f)snprintf(sub,sizeof(sub),"~%.1f m   %d dBm",dist,rssi);
    else snprintf(sub,sizeof(sub),"~%d m   %d dBm",(int)(dist+0.5f),rssi); }
  else snprintf(sub,sizeof(sub),"move around to re-acquire");
  px(sub,cx,200,C_MUTED,1,MC_DATUM);
}

// ======================================================================
//  Frame
// ======================================================================
static void drawView(uint32_t now){
  if(view==V_HOME){ header(false); drawHome(now); }
  else { header(true);
    switch(view){ case V_TRACK:appDefense(now);break; case V_SCANNER:appScanner(now);break;
      case V_WIFI:appWifi(now);break; case V_BT:appBt(now);break;
      case V_SET:appSettings(now);break; case V_ABOUT:appAbout(now);break; case V_SAVED:appSaved(now);break;
      case V_HUNT:appHunt(now);break; }
    if(tapIn(0,0,52,28)){ view=(view==V_SAVED)?V_SET:V_HOME; beepTap(); } }
}
static void render(uint32_t now){
  if(bandH){ G=&spr;
    for(int y0=0;y0<240;y0+=bandH){ OY=-y0; spr.fillSprite(C_BG); drawView(now); spr.pushSprite(0,y0); tapX=tapY=-1; }
  } else { G=&tft; OY=0; tft.fillScreen(C_BG); drawView(now); tapX=tapY=-1; }
}
static void drawGhostArt(int x0,int y0){
  for(int y=0;y<GHOST_H;y++){ const uint8_t*row=&GHOST_BITS[y*GHOST_ROWBYTES];
    for(int x=0;x<GHOST_W;x++) if(pgm_read_byte(&row[x>>3])&(0x80>>(x&7))) tft.drawPixel(x0+x,y0+y,C_PURP); }
}
static void splash(){
  G=&tft; OY=0; tft.fillScreen(C_BG);
  drawGhostArt((320-GHOST_W)/2, 4);
  px("PHANTOM",160,204,C_PURP,3,MC_DATUM);
}

// ======================================================================
//  Persistence
// ======================================================================
static void loadSettings(){ prefs.begin("phantom",true);
  soundOn=prefs.getBool("snd",true); brightness=prefs.getUChar("brt",230);
  colorBGR=prefs.getBool("bgr",false); invertOn=prefs.getBool("inv",true);
  stealth=prefs.getBool("stl",false); prefs.end(); }
static void saveSettings(){ prefs.begin("phantom",false);
  prefs.putBool("snd",soundOn); prefs.putUChar("brt",brightness);
  prefs.putBool("bgr",colorBGR); prefs.putBool("inv",invertOn); prefs.putBool("stl",stealth); prefs.end(); }

static void loadSaved(){ prefs.begin("log",true);
  savedCount=prefs.getUChar("n",0); if(savedCount>MAX_SAVED)savedCount=MAX_SAVED;
  size_t need=(size_t)savedCount*sizeof(Saved);
  if(need && prefs.getBytesLength("d")==need) prefs.getBytes("d",saved,need); else savedCount=0;
  prefs.end(); }
static void persistSaved(){ prefs.begin("log",false);
  prefs.putUChar("n",savedCount); prefs.putBytes("d",saved,(size_t)savedCount*sizeof(Saved)); prefs.end(); }
static void saveEntry(const char*mac,const char*name,uint8_t type,char cat){
  for(int i=0;i<savedCount;i++) if(!strcmp(saved[i].mac,mac))return;   // dedupe by MAC
  if(savedCount>=MAX_SAVED)return;
  Saved&s=saved[savedCount++]; strlcpy(s.mac,mac,sizeof(s.mac));
  strlcpy(s.name,name[0]?name:"(no name)",sizeof(s.name)); s.type=type; s.cat=cat;
  persistSaved();
}
static void clearSaved(){ savedCount=0; persistSaved(); }
// Called once per second from loop(): auto-log trailing trackers + emergency hits.
static void autoLog(uint32_t now){
  struct C{char mac[18];char name[20];uint8_t type;char cat;}; static C cand[MAX_DEV]; int cn=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount&&cn<MAX_DEV;i++){ Dev&d=dev[i];
    bool follow=isTrail(d,now);
    bool emg=d.cat<CAT_COUNT&&now-d.lastSeen<60000;
    if(follow||emg){ strlcpy(cand[cn].mac,d.mac,18); strlcpy(cand[cn].name,d.name,20);
      cand[cn].type=follow?d.tracker:0; cand[cn].cat=emg?(char)d.cat:(char)255; cn++; } }
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<cn;i++) saveEntry(cand[i].mac,cand[i].name,cand[i].type,cand[i].cat);  // dedupe inside
}

// ======================================================================
//  Setup / loop
// ======================================================================
void setup(){
  Serial.begin(115200);
  pinMode(LED_R,OUTPUT);pinMode(LED_G,OUTPUT);pinMode(LED_B,OUTPUT);pinMode(BTN_BOOT,INPUT_PULLUP);
  setLed(false,false,false);
  ledcSetup(0,2000,8);ledcAttachPin(SPEAKER,0);
  loadSettings(); loadSaved();

  tft.init(); tft.setRotation(1);
  tft.invertDisplay(invertOn);        // this panel needs inversion ON for a black background
  applyColorOrder();
  // attach backlight PWM AFTER tft.init() so TFT_eSPI doesn't reclaim the BL pin as a plain output
  ledcSetup(1,5000,8); ledcAttachPin(TFT_BL,1); setBright(brightness);
  tsSPI.begin(T_CLK,T_MISO,T_MOSI,T_CS); ts.begin(tsSPI); ts.setRotation(1);
  splash();
  spr.setColorDepth(16);
  for(int h:{120,80,60,48,40}) if(spr.createSprite(320,h)){bandH=h;break;}

  WiFi.mode(WIFI_STA); WiFi.disconnect();
  randomizeMac();                                   // never emit the real factory MAC
  esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&promiscCB);
  NimBLEDevice::init("");
  NimBLEDevice::setOwnAddrType(BLE_OWN_ADDR_RANDOM, true);   // non-resolvable private BLE address
  bleScan=NimBLEDevice::getScan();
  bleScan->setAdvertisedDeviceCallbacks(new BleCB(),true);
  bleScan->setActiveScan(!stealth); bleScan->setInterval(160); bleScan->setWindow(80);   // active unless stealth
  bleScan->setMaxResults(0); bleScan->start(0,nullptr,false);
  delay(900);
  Serial.println("PHANTOM 5.0 up");
}

void loop(){
  static uint32_t lastDraw=0,lastWin=0,chanHop=0,lastSave=0; static uint8_t ch=1; static bool alerting=false,trkAl=false;
  uint32_t now=millis();
  handleTouch();

  if(now-chanHop>400){chanHop=now;ch=ch%13+1;esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);}
  if(now-lastWin>1000){lastWin=now;deauthWindow=deauthCount;deauthCount=0; autoLog(now);
    setBright(brightness); }   // re-assert backlight so radio activity can't leave it dimmed
  wifiScanStep();

  bool follow=false;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(isTrail(dev[i],now)){
    follow=true; if(!dev[i].alarmed){dev[i].alarmed=true;trkAlarmUntil=now+6000;} }
  portEXIT_CRITICAL(&mux);
  if(now<trkAlarmUntil){ if(!trkAl){trkAl=true;trackerAlarm();} bool p=(now/200)%2; setLed(p,false,p);}
  else if(trkAl){trkAl=false;setLed(false,false,false);}

  int pa=pendingAlert;
  if(pa>=0){pendingAlert=-1; if(!(now<alertUntil&&alertCat<pa))alertCat=pa; alertUntil=now+6000;
    if(view==V_HOME)view=V_SCANNER; alertSound(alertCat); lastDraw=0;}
  bool a=now<alertUntil;
  if(a!=alerting){alerting=a; if(!a&&!trkAl)setLed(false,false,false); lastDraw=0;}
  if(alerting&&!trkAl){bool ph=(now/220)%2; switch(alertCat){case CAT_POLICE:setLed(ph,0,!ph);break;
    case CAT_EMS:setLed(1,!ph,!ph);break;case CAT_FIRE:setLed(ph,0,0);break;default:setLed(ph,ph,0);}}

  if(settingsDirty&&now-lastSave>400){saveSettings();settingsDirty=false;lastSave=now;}

  // LOCATE: Geiger-style beeping - faster as the target gets closer
  static uint32_t lastHuntBeep=0;
  if(view==V_HUNT&&hunting&&soundOn&&!alerting&&!trkAl){
    uint32_t iv=constrain((int)map((int)huntSm,-90,-45,1300,110),110,1300);
    if(now-lastHuntBeep>iv){ lastHuntBeep=now; ledcWriteTone(0,3100); delay(6); ledcWriteTone(0,0); }
  }

  bool anim=(view==V_TRACK||view==V_SCANNER||view==V_HUNT);
  uint32_t every=bandH?(gDown?33:(anim?70:150)):400;
  if(!lastDraw||now-lastDraw>=every||tapX>=0){lastDraw=now;render(now);}

  if(!bleScan->isScanning())bleScan->start(0,nullptr,false);
  delay(4);
}
