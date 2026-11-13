/*
 * PHANTOM  v3.5  -  counter-surveillance / passive RF defense
 * ESP32-2432S028R "Cheap Yellow Display". Touchscreen, dark neon UI.
 *
 * RECEIVE-ONLY. BLE + Wi-Fi scan passively. Wi-Fi promiscuous mode is used
 * only to COUNT deauth/disassoc frames (attack detector). PHANTOM never
 * transmits attacks (no deauth / jam / spam) and never connects or spoofs.
 *
 * Apps (tap a tile, drag to scroll, tap "<" to go back):
 *   DEFENSE  - tracker radar: AirTag / Tile / SmartTag, alarms if one trails you
 *   SCANNER  - emergency gear radar: police / ambulance / fire / fleet
 *   WIFI     - access points + rogue / evil-twin / deauth-attack detection
 *   BLUETOOTH- every nearby BLE device
 *   SETTINGS - colour order (RGB/BGR), brightness, sound, accent, clear
 *
 * Settings persist to flash (NVS).
 */
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SPI.h>
#include <XPT2046_Touchscreen.h>
#include <NimBLEDevice.h>
#include <TFT_eSPI.h>
#include <Preferences.h>

// ---------- CYD hardware ----------
#define LED_R 4
#define LED_G 16
#define LED_B 17
#define SPEAKER 26
#define BTN_BOOT 0
#define T_CLK 25
#define T_CS  33
#define T_MOSI 32
#define T_MISO 39
#define T_IRQ 36
#define T_MINX 200
#define T_MAXX 3700
#define T_MINY 240
#define T_MAXY 3800
// MADCTL for runtime RGB/BGR swap (ILI9341 family, rotation 1 base = MV)
#define MADCTL_REG 0x36
#define MAD_MV 0x20
#define MAD_BGR 0x08

// ======================================================================
//  Emergency-scanner rules
// ======================================================================
enum Cat : uint8_t { CAT_POLICE = 0, CAT_EMS, CAT_FIRE, CAT_VEHICLE, CAT_COUNT };
enum Src : uint8_t { S_BLE = 1, S_WIFI = 2, S_ANY = 3 };
enum Kind : uint8_t { BY_MAC, BY_NAME };
struct Rule { uint8_t src; uint8_t kind; const char *pattern; const char *label; uint8_t cat; };
static const Rule RULES[] = {
  {S_ANY, BY_MAC, "00:25:df","Axon device",CAT_POLICE},{S_ANY,BY_NAME,"axon","Axon",CAT_POLICE},
  {S_BLE, BY_NAME,"body 3","Axon Body 3",CAT_POLICE},{S_BLE,BY_NAME,"body 4","Axon Body 4",CAT_POLICE},
  {S_ANY, BY_NAME,"fleet 3","Axon Fleet",CAT_POLICE},{S_ANY,BY_NAME,"watchguard","WatchGuard",CAT_POLICE},
  {S_ANY, BY_NAME,"apx","Motorola APX",CAT_POLICE},{S_ANY,BY_NAME,"police","Police net",CAT_POLICE},
  {S_ANY, BY_NAME,"ambulance","Ambulance",CAT_EMS},{S_ANY,BY_NAME,"paramedic","Paramedic",CAT_EMS},
  {S_ANY, BY_NAME,"st john","St John",CAT_EMS},{S_ANY,BY_NAME,"lifepak","LIFEPAK",CAT_EMS},
  {S_ANY, BY_NAME,"zoll","ZOLL",CAT_EMS},{S_ANY,BY_NAME,"dfes","DFES",CAT_FIRE},
  {S_ANY, BY_NAME,"fire rescue","Fire & Rescue",CAT_FIRE},{S_ANY,BY_NAME,"fire brigade","Fire brigade",CAT_FIRE},
  {S_WIFI,BY_NAME,"ses ","SES",CAT_FIRE},{S_WIFI,BY_MAC,"00:30:44","Cradlepoint",CAT_VEHICLE},
  {S_WIFI,BY_NAME,"cradlepoint","Cradlepoint",CAT_VEHICLE},{S_WIFI,BY_NAME,"airlink","Sierra AirLink",CAT_VEHICLE},
  {S_WIFI,BY_NAME,"pepwave","Peplink",CAT_VEHICLE},{S_ANY,BY_NAME,"toughbook","Toughbook",CAT_VEHICLE},
  {S_ANY, BY_NAME,"getac","Getac",CAT_VEHICLE},
};
static const char *CAT_TILE[CAT_COUNT] = {"Police","Ambulance","Fire","Vehicle"};

// ======================================================================
//  Palette
// ======================================================================
#define C_BG     0x0041   // #04060a near-black, matches web flasher
#define C_PANEL  0x0882   // #0a0f14
#define C_PANEL2 0x10E3
#define C_LINE   0x1926   // #1b2630
#define C_TXT    0xFFFF
#define C_MUTED  0x6C92
#define C_DIM    0x4228
#define C_RED    0xF9A6
#define C_AMBER  0xFD40
#define C_GREENOK 0x1FF4
static const uint16_t CAT_COL[CAT_COUNT] = {0x4D9F,0xFFFF,0xFC00,0xFEA0};
static const uint16_t ACCENTS[]   = {0x1FF4,0x05FF,0xF81F,0xFD40,0xFB56};  // neon green #1dfca0 first
static const char *ACCENT_NAME[]  = {"Phantom Green","Ice Cyan","Magenta","Amber","Coral"};
static uint8_t accentIdx = 0;
#define ACC (ACCENTS[accentIdx])

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
static const int MAX_DEV = 96;
static Dev dev[MAX_DEV];
static int devCount = 0;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static volatile uint32_t lastBleMs=0, lastWifiMs=0;
static volatile int pendingAlert = -1;      // emergency category
static volatile uint32_t deauthCount=0, deauthWindow=0, lastDeauthMs=0;
static uint32_t alertUntil=0; static uint8_t alertCat=0;
static uint32_t trkAlarmUntil=0;            // tracker-follow alarm

// settings (persisted)
static bool soundOn=true, colorBGR=false;
#ifdef CYD_INVERT
static bool invertOn=true;
#else
static bool invertOn=false;
#endif
static uint8_t brightness=230;
Preferences prefs;

TFT_eSPI tft;
TFT_eSprite spr(&tft);
SPIClass tsSPI(VSPI);
XPT2046_Touchscreen ts(T_CS, T_IRQ);
NimBLEScan *bleScan;

// ======================================================================
//  Matching / ingest
// ======================================================================
static void lowerCopy(char *d,const char*s,size_t n){size_t i=0;for(;s[i]&&i<n-1;i++)d[i]=tolower((uint8_t)s[i]);d[i]=0;}
static const Rule* matchRule(char src,const char*macL,const char*name){
  char low[40]; lowerCopy(low,name,sizeof(low)); uint8_t s=src=='B'?S_BLE:S_WIFI;
  for(auto&r:RULES){ if(!(r.src&s))continue;
    if(r.kind==BY_MAC){if(!strncmp(macL,r.pattern,strlen(r.pattern)))return &r;}
    else if(low[0]&&strstr(low,r.pattern))return &r; }
  return nullptr;
}
static int findDev(const char*m){for(int i=0;i<devCount;i++)if(!strcmp(dev[i].mac,m))return i;return -1;}
static int newSlot(){ if(devCount<MAX_DEV)return devCount++; int s=0;
  for(int i=1;i<MAX_DEV;i++)if(dev[i].lastSeen<dev[s].lastSeen)s=i; return s; }

static uint8_t classifyTracker(NimBLEAdvertisedDevice*d){
  // Apple "Find My" offline-finding beacon (type 0x12). This is what AirTags
  // broadcast, but so do AirPods, iPhones and Macs acting as Find My beacons,
  // so we honestly label it "Find My", not "AirTag". Require the Find My
  // payload length (0x19) to cut out other Apple adverts (handoff, pairing).
  if(d->haveManufacturerData()){ std::string m=d->getManufacturerData();
    if(m.size()>=4&&(uint8_t)m[0]==0x4C&&(uint8_t)m[1]==0x00
       &&(uint8_t)m[2]==0x12&&(uint8_t)m[3]==0x19) return T_FINDMY; }
  for(int i=0;i<d->getServiceUUIDCount();i++){ NimBLEUUID u=d->getServiceUUID(i);
    if(u==NimBLEUUID((uint16_t)0xFEED))return T_TILE;
    if(u==NimBLEUUID((uint16_t)0xFD5A)||u==NimBLEUUID((uint16_t)0xFD59))return T_SMARTTAG; }
  return T_NONE;
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
static void wifiScanStep(){ static uint32_t st=0; int n=WiFi.scanComplete();
  if(n>=0){ lastWifiMs=millis();
    for(int i=0;i<n;i++) observe('W',WiFi.BSSIDstr(i).c_str(),WiFi.SSID(i).c_str(),WiFi.RSSI(i),
      WiFi.channel(i),WiFi.encryptionType(i)==WIFI_AUTH_OPEN?0:1,0);
    WiFi.scanDelete(); st=0;
  } else if(n==WIFI_SCAN_FAILED && millis()-st>5000){ st=millis(); WiFi.scanNetworks(true,true,true,110); }
}
static void IRAM_ATTR promiscCB(void*buf, wifi_promiscuous_pkt_type_t type){
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

// banded sprite
static TFT_eSPI *G=&tft; static int OY=0, bandH=0;
#define Y(v) ((v)+OY)
static void tt(const char*s,int x,int y,uint16_t c,uint8_t f,uint8_t d){G->setTextFont(f);G->setTextColor(c);G->setTextDatum(d);G->drawString(s,x,Y(y));}
static void ff(const char*s,int x,int y,uint16_t c,const GFXfont*f,uint8_t d,bool bold=false){G->setFreeFont(f);G->setTextColor(c);G->setTextDatum(d);G->drawString(s,x,Y(y));if(bold)G->drawString(s,x+1,Y(y));}
static int rssiLvl(int r){return r>-55?5:r>-65?4:r>-75?3:r>-85?2:1;}
static void bars(int x,int y,int lvl,uint16_t on,int w,int gap,int mh){for(int i=0;i<5;i++){int h=mh*(i+1)/5;G->fillRect(x+i*(w+gap),Y(y+mh-h),w,h,i<lvl?on:C_LINE);}}
static void fmtAgo(char*b,size_t n,uint32_t ms){uint32_t s=ms/1000;if(s<3)snprintf(b,n,"live");else if(s<60)snprintf(b,n,"%lus",(unsigned long)s);else snprintf(b,n,"%lum",(unsigned long)(s/60));}
static uint32_t hashStr(const char*s){uint32_t h=5381;while(*s)h=h*33+(uint8_t)*s++;return h;}

// animated radar with blips pulled live from dev[]
static void radar(int cx,int cy,int R,uint32_t now,int filterTrk,int filterCat){
  for(int r=R/3;r<=R;r+=R/3)G->drawCircle(cx,Y(cy),r,C_LINE);
  G->drawFastHLine(cx-R,Y(cy),2*R+1,C_LINE); G->drawFastVLine(cx,Y(cy)-R,2*R+1,C_LINE);
  float a=(now%2600)/2600.0f*TWO_PI;
  for(int k=6;k>=0;k--){ float b=a-k*0.09f; uint8_t v=200-k*26;
    uint16_t tc=G->color565((ACC>>11<<3)*v/255,((ACC>>5&0x3F)<<2)*v/255,((ACC&0x1F)<<3)*v/255);
    G->drawLine(cx,Y(cy),cx+cosf(b)*R,Y(cy)+sinf(b)*R,tc); }
  portENTER_CRITICAL(&mux); int dc=devCount; static Dev snap[MAX_DEV]; memcpy(snap,dev,sizeof(Dev)*dc); portEXIT_CRITICAL(&mux);
  for(int i=0;i<dc;i++){ Dev&d=snap[i];
    if(now-d.lastSeen>30000)continue;
    if(filterTrk>=0 && d.tracker==0)continue;
    if(filterCat>=0 && d.cat>=CAT_COUNT)continue;
    float ang=(hashStr(d.mac)%360)*DEG_TO_RAD;
    int rr=map(constrain(d.rssi,-100,-40),-100,-40,R-3,5);
    uint16_t bc = d.tracker?0xF81F : d.cat<CAT_COUNT?CAT_COL[d.cat] : ACC;
    int bx=cx+cosf(ang)*rr, by=cy+sinf(ang)*rr;
    bool near=(a<ang+0.12f&&a>ang-0.12f);
    G->fillCircle(bx,Y(by),near?3:2,bc);
    if(near)G->drawCircle(bx,Y(by),5,bc);
  }
  G->fillCircle(cx,Y(cy),2,ACC);
}

// ======================================================================
//  Touch input
// ======================================================================
enum View { V_HOME, V_TRACK, V_SCANNER, V_WIFI, V_BT, V_SET, V_COUNT };
static uint8_t view=V_HOME; static int scroll[V_COUNT]={0};
static bool pressed=false, moved=false; static int pressX,pressY,lastTY; static uint32_t pressMs;
static int tapX=-1, tapY=-1; static bool gDown=false; static int gX=0,gY=0;
static int maxScroll=0; static bool settingsDirty=false;

static bool readTouch(int&sx,int&sy){ if(!ts.touched())return false; TS_Point p=ts.getPoint();
  if(p.z<200)return false;
  sx=constrain((int)map(p.x,T_MINX,T_MAXX,0,320),0,319);
  sy=constrain((int)map(p.y,T_MINY,T_MAXY,0,240),0,239); return true; }
static void handleTouch(){ int x,y; bool down=readTouch(x,y); uint32_t now=millis();
  gDown=down; if(down){gX=x;gY=y;}
  if(down){ if(!pressed){pressed=true;moved=false;pressX=x;pressY=lastTY=y;pressMs=now;}
    int dy=y-lastTY; if(abs(y-pressY)>6||abs(x-pressX)>6)moved=true;
    if(moved)scroll[view]-=dy; lastTY=y;
  } else if(pressed){ pressed=false;
    if(!moved&&now-pressMs<600){tapX=pressX;tapY=pressY;}
    if(view==V_SET)settingsDirty=true; }
  if(scroll[view]<0)scroll[view]=0; if(scroll[view]>maxScroll)scroll[view]=maxScroll;
}
static bool tapIn(int x,int y,int w,int h){return tapX>=0&&tapX>=x&&tapX<x+w&&tapY>=y&&tapY<y+h;}

// ======================================================================
//  Header + home
// ======================================================================
struct App{const char*name;const char*sub;View view;uint16_t col;char icon;};
static const App APPS[]={
  {"Defense","Tracker counter-surveillance",V_TRACK,0xF81F,'D'},
  {"Scanner","Police / EMS / Fire radar",V_SCANNER,0xFC00,'S'},
  {"Wi-Fi","APs, rogue & deauth watch",V_WIFI,0x05FF,'W'},
  {"Bluetooth","Nearby BLE devices",V_BT,0x4D9F,'B'},
  {"Settings","Colour, light, sound",V_SET,0x8430,'G'},
};
static const int NAPPS=sizeof(APPS)/sizeof(APPS[0]);

static void header(const char*title,bool back){
  G->fillRect(0,0,320,30,C_PANEL); G->drawFastHLine(0,Y(30),320,ACC);
  if(back){ ff("<",15,15,ACC,&FreeSansBold12pt7b,MC_DATUM,true); ff(title,40,15,C_TXT,&FreeSansBold9pt7b,ML_DATUM,true); }
  else { ff("PHANTOM",10,15,ACC,&FreeSansBold12pt7b,ML_DATUM,true); ff("defense",152,16,C_MUTED,&FreeSans9pt7b,ML_DATUM); }
  uint32_t now=millis(); bool ble=now-lastBleMs<3000, wf=now-lastWifiMs<15000;
  G->fillCircle(298,Y(15),4,ble?ACC:C_DIM); G->fillCircle(312,Y(15),4,wf?ACC:C_DIM);
}

static void drawHome(uint32_t now){
  ff("PHANTOM",160,50,ACC,&FreeSansBold18pt7b,MC_DATUM,true);
  tt("COUNTER-SURVEILLANCE",160,76,C_MUTED,2,MC_DATUM);
  int trk=0,wifi=0,bt=0;
  portENTER_CRITICAL(&mux); int dc=devCount;
  for(int i=0;i<dc;i++){if(now-dev[i].lastSeen>30000)continue; if(dev[i].tracker)trk++; if(dev[i].src=='W')wifi++;else bt++;}
  portEXIT_CRITICAL(&mux);
  const int top=96,rowH=46,pad=10;
  maxScroll=(NAPPS*rowH)-(240-top)+8; if(maxScroll<0)maxScroll=0; int sc=scroll[V_HOME];
  for(int i=0;i<NAPPS;i++){ int y=top+i*rowH-sc; if(y>240||y<top-rowH)continue;
    bool tp=tapIn(pad,y,300,rowH-8); uint16_t col=APPS[i].col;
    G->fillRoundRect(pad,Y(y),300,rowH-8,8,tp?C_PANEL2:C_PANEL);
    G->fillRoundRect(pad,Y(y),4,rowH-8,2,col);
    G->fillRoundRect(pad+12,Y(y+6),26,26,6,C_BG);
    char ic[2]={APPS[i].icon,0}; ff(ic,pad+25,y+19,col,&FreeSansBold12pt7b,MC_DATUM,true);
    ff(APPS[i].name,pad+48,y+13,C_TXT,&FreeSansBold9pt7b,ML_DATUM,true);
    tt(APPS[i].sub,pad+48,y+29,C_MUTED,1,ML_DATUM);
    int cnt=APPS[i].view==V_TRACK?trk:APPS[i].view==V_WIFI?wifi:APPS[i].view==V_BT?bt:-1;
    if(cnt>=0){char b[8];snprintf(b,sizeof(b),"%d",cnt);ff(b,296,y+19,cnt&&APPS[i].view==V_TRACK?0xF81F:col,&FreeSansBold12pt7b,MR_DATUM,true);}
    else ff(">",296,y+19,C_MUTED,&FreeSansBold9pt7b,MR_DATUM);
    if(tp){view=APPS[i].view;scroll[view]=0;beepTap();}
  }
}

// ======================================================================
//  App: Defense (trackers)
// ======================================================================
static void appDefense(uint32_t now){
  static Dev t[MAX_DEV]; int tn=0,follow=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].tracker&&now-dev[i].lastSeen<60000) t[tn++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<tn;i++)for(int j=i+1;j<tn;j++)if(t[j].rssi>t[i].rssi){Dev x=t[i];t[i]=t[j];t[j]=x;}
  for(int i=0;i<tn;i++) if((now-t[i].firstSeen)/1000>90) follow++;

  // status banner
  bool threat=follow>0;
  G->fillRoundRect(8,Y(36),304,34,8, threat?0x3000:0x0320);
  G->drawRoundRect(8,Y(36),304,34,8, threat?C_RED:C_GREENOK);
  if(threat){ ff("THREAT",18,53,C_RED,&FreeSansBold12pt7b,ML_DATUM,true);
    char s[32];snprintf(s,sizeof(s),"%d tag%s trailing you",follow,follow>1?"s":"");
    tt(s,304,53,C_RED,2,MR_DATUM);
  } else { ff("SECURE",18,53,C_GREENOK,&FreeSansBold12pt7b,ML_DATUM,true);
    char s[32];snprintf(s,sizeof(s),"%d tag%s nearby",tn,tn==1?"":"s");
    tt(s,304,53,C_MUTED,2,MR_DATUM); }

  // radar on left, list on right
  radar(76,148,56,now,1,-1);
  tt("TRACKERS",76,212,C_MUTED,1,MC_DATUM);

  const int lx=146,lw=168,top=78,rowH=42;
  if(!tn){ tt("No trackers detected",lx+lw/2,150,C_MUTED,2,MC_DATUM); maxScroll=0; return; }
  maxScroll=tn*rowH-(240-top)+6; if(maxScroll<0)maxScroll=0;
  for(int i=0;i<tn;i++){ int y=top+i*rowH-scroll[V_TRACK]; if(y>240||y<top-rowH)continue;
    Dev&d=t[i]; uint32_t dur=(now-d.firstSeen)/1000; bool fol=dur>90;
    G->fillRoundRect(lx,Y(y),lw,rowH-6,6, fol?0x3000:C_PANEL);
    if(fol)G->drawRoundRect(lx,Y(y),lw,rowH-6,6,C_RED);
    G->fillRoundRect(lx,Y(y),4,rowH-6,2, fol?C_RED:0xF81F);
    ff(TRK_NAME[d.tracker],lx+10,y+5,fol?C_RED:C_TXT,&FreeSansBold9pt7b,TL_DATUM,fol);
    bars(lx+lw-28,y+6,rssiLvl(d.rssi),fol?C_RED:0xF81F,4,2,15);
    char s[40]; if(dur<60)snprintf(s,sizeof(s),"%lus near you",(unsigned long)dur);
    else snprintf(s,sizeof(s),"%lum%lus near you",(unsigned long)(dur/60),(unsigned long)(dur%60));
    tt(s,lx+10,y+24,fol?C_RED:C_MUTED,1,TL_DATUM);
  }
}

// ======================================================================
//  App: Scanner (emergency) with radar
// ======================================================================
static void appScanner(uint32_t now){
  static Dev h[MAX_DEV]; int hn=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].cat<CAT_COUNT&&now-dev[i].lastSeen<60000) h[hn++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<hn;i++)for(int j=i+1;j<hn;j++)if(h[j].lastSeen>h[i].lastSeen){Dev x=h[i];h[i]=h[j];h[j]=x;}

  radar(76,128,58,now,-1,1);
  tt("EMERGENCY",76,194,C_MUTED,1,MC_DATUM);
  // category key
  for(int c=0;c<CAT_COUNT;c++){int cnt=0;for(int i=0;i<hn;i++)if(h[i].cat==c)cnt++;
    int y=40+c*13; G->fillCircle(150,Y(y+4),4,CAT_COL[c]);
    char s[20];snprintf(s,sizeof(s),"%s %d",CAT_TILE[c],cnt);
    tt(s,160,y,cnt?C_TXT:C_DIM,1,TL_DATUM);}

  const int lx=146,lw=168,top=100,rowH=40;
  if(!hn){ tt("No emergency gear",lx+lw/2,150,C_MUTED,1,MC_DATUM); maxScroll=0; return; }
  maxScroll=hn*rowH-(240-top)+6; if(maxScroll<0)maxScroll=0;
  for(int i=0;i<hn;i++){ int y=top+i*rowH-scroll[V_SCANNER]; if(y>240||y<top-rowH)continue;
    Dev&d=h[i]; bool stale=now-d.lastSeen>60000; uint16_t cc=stale?C_DIM:CAT_COL[d.cat];
    G->fillRoundRect(lx,Y(y),lw,rowH-6,6,C_PANEL); G->fillRoundRect(lx,Y(y),4,rowH-6,2,cc);
    ff(d.name[0]?d.name:"(unnamed)",lx+10,y+5,stale?C_MUTED:C_TXT,&FreeSans9pt7b,TL_DATUM);
    char ago[12];fmtAgo(ago,sizeof(ago),now-d.lastSeen);
    char s[40];snprintf(s,sizeof(s),"%s %s",CAT_TILE[d.cat],ago);
    tt(s,lx+10,y+24,C_MUTED,1,TL_DATUM);
    bars(lx+lw-28,y+8,rssiLvl(d.rssi),cc,4,2,15);
  }
}

// ======================================================================
//  App: Wi-Fi
// ======================================================================
static void appWifi(uint32_t now){
  static Dev a[MAX_DEV]; int an=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].src=='W'&&now-dev[i].lastSeen<30000) a[an++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<an;i++)for(int j=i+1;j<an;j++)if(a[j].rssi>a[i].rssi){Dev x=a[i];a[i]=a[j];a[j]=x;}
  bool deauth=now-lastDeauthMs<4000&&deauthWindow>8; int evil=0;for(int i=0;i<an;i++)if(a[i].evilTwin)evil++;
  const int top=(deauth||evil)?66:40;
  if(deauth||evil){ G->fillRoundRect(8,Y(36),304,24,6,0x3000); G->drawRoundRect(8,Y(36),304,24,6,C_RED);
    char w[48]; if(deauth)snprintf(w,sizeof(w),"DEAUTH ATTACK  %lu/s",(unsigned long)deauthWindow);
    else snprintf(w,sizeof(w),"EVIL TWIN: %d duplicate SSID",evil);
    ff(w,160,48,C_RED,&FreeSansBold9pt7b,MC_DATUM,true); }
  if(!an){tt("Scanning Wi-Fi...",160,120,C_MUTED,2,MC_DATUM);maxScroll=0;return;}
  const int rowH=40; maxScroll=an*rowH-(240-top)+8; if(maxScroll<0)maxScroll=0;
  for(int i=0;i<an;i++){int y=top+i*rowH-scroll[V_WIFI];if(y>240||y<top-rowH)continue;Dev&d=a[i];
    G->fillRoundRect(8,Y(y),304,rowH-7,7,C_PANEL);
    uint16_t sd=d.evilTwin?C_RED:d.enc?ACC:C_AMBER; G->fillRoundRect(8,Y(y),4,rowH-7,2,sd);
    ff(d.name[0]?d.name:"(hidden)",18,y+6,d.name[0]?C_TXT:C_MUTED,&FreeSans9pt7b,TL_DATUM);
    char s[48];snprintf(s,sizeof(s),"ch%-3d %s %s",d.chan,d.enc?"secured":"OPEN",d.mac);
    tt(s,18,y+24,d.enc?C_MUTED:C_AMBER,1,TL_DATUM);
    bars(272,y+14,rssiLvl(d.rssi),sd,5,3,16);
    if(d.evilTwin)tt("TWIN",300,y+24,C_RED,1,TR_DATUM);}
}

// ======================================================================
//  App: Bluetooth
// ======================================================================
static void appBt(uint32_t now){
  static Dev ds[MAX_DEV]; int dn=0;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].src=='B'&&now-dev[i].lastSeen<30000) ds[dn++]=dev[i];
  portEXIT_CRITICAL(&mux);
  for(int i=0;i<dn;i++)for(int j=i+1;j<dn;j++)if(ds[j].rssi>ds[i].rssi){Dev x=ds[i];ds[i]=ds[j];ds[j]=x;}
  if(!dn){tt("Scanning Bluetooth...",160,120,C_MUTED,2,MC_DATUM);maxScroll=0;return;}
  const int top=40,rowH=38; maxScroll=dn*rowH-(240-top)+8; if(maxScroll<0)maxScroll=0;
  for(int i=0;i<dn;i++){int y=top+i*rowH-scroll[V_BT];if(y>240||y<top-rowH)continue;Dev&d=ds[i];
    G->fillRoundRect(8,Y(y),304,rowH-7,7,C_PANEL); G->fillRoundRect(8,Y(y),4,rowH-7,2,d.tracker?0xF81F:ACC);
    ff(d.name[0]?d.name:"(no name)",18,y+5,d.name[0]?C_TXT:C_MUTED,&FreeSans9pt7b,TL_DATUM);
    tt(d.mac,18,y+23,C_MUTED,1,TL_DATUM);
    if(d.tracker)tt(TRK_NAME[d.tracker],300,y+23,0xF81F,1,TR_DATUM);
    bars(272,y+14,rssiLvl(d.rssi),d.tracker?0xF81F:ACC,5,3,14);}
}

// ======================================================================
//  App: Settings
// ======================================================================
static void appSettings(uint32_t now){
  maxScroll=0; const int x=10,w=300; int y=42;
  // colour order
  G->fillRoundRect(x,Y(y),w,46,8,C_PANEL);
  ff("Colour order",x+14,y+15,C_TXT,&FreeSans9pt7b,ML_DATUM);
  tt("Reds look blue? Switch this.",x+14,y+32,C_MUTED,1,ML_DATUM);
  for(int i=0;i<2;i++){ bool on=(i==1)==colorBGR; int bx=x+w-120+i*56;
    G->fillRoundRect(bx,Y(y+12),52,22,6,on?ACC:C_LINE);
    tt(i?"BGR":"RGB",bx+26,y+23,on?C_BG:C_MUTED,2,MC_DATUM);
    if(tapIn(bx,y+10,54,28)){ colorBGR=i; applyColorOrder(); settingsDirty=true; beepTap(); } }
  y+=56;
  // invert (white background -> turn this ON/OFF)
  G->fillRoundRect(x,Y(y),w,46,8,C_PANEL);
  ff("Invert display",x+14,y+15,C_TXT,&FreeSans9pt7b,ML_DATUM);
  tt("Background white? Flip this.",x+14,y+32,C_MUTED,1,ML_DATUM);
  G->fillRoundRect(x+w-66,Y(y+12),52,22,11,invertOn?ACC:C_LINE);
  G->fillCircle(invertOn?x+w-26:x+w-52,Y(y+23),8,C_BG);
  if(tapIn(x+w-66,y+10,58,28)){ invertOn=!invertOn; tft.invertDisplay(invertOn); settingsDirty=true; beepTap(); }
  y+=56;
  // brightness (live drag)
  G->fillRoundRect(x,Y(y),w,48,8,C_PANEL);
  ff("Brightness",x+14,y+16,C_TXT,&FreeSans9pt7b,ML_DATUM);
  int bx=x+14,bw=w-28,by=y+32;
  G->fillRoundRect(bx,Y(by),bw,8,4,C_LINE);
  if(gDown && gX>=bx-10 && gX<=bx+bw+10 && gY>=y+18 && gY<=y+44){
    brightness=constrain((int)map(gX,bx,bx+bw,25,255),25,255); setBright(brightness); settingsDirty=true; }
  int fw=map(brightness,25,255,10,bw); G->fillRoundRect(bx,Y(by),fw,8,4,ACC);
  G->fillCircle(bx+fw,Y(by+4),9,ACC);
  y+=58;
  // sound
  G->fillRoundRect(x,Y(y),w,40,8,C_PANEL);
  ff("Sound",x+14,y+20,C_TXT,&FreeSans9pt7b,ML_DATUM);
  G->fillRoundRect(x+w-66,Y(y+9),52,22,11,soundOn?ACC:C_LINE);
  G->fillCircle(soundOn?x+w-26:x+w-52,Y(y+20),8,C_BG);
  if(tapIn(x+w-66,y+6,58,28)){soundOn=!soundOn;settingsDirty=true;beepTap();}
  y+=50;
  // accent
  G->fillRoundRect(x,Y(y),w,46,8,C_PANEL);
  ff("Accent",x+14,y+16,C_TXT,&FreeSans9pt7b,ML_DATUM);
  tt(ACCENT_NAME[accentIdx],x+14,y+33,C_MUTED,1,ML_DATUM);
  for(int i=0;i<5;i++){int cx=x+w-28-i*30,cy=y+23; G->fillCircle(cx,Y(cy),10,ACCENTS[i]);
    if(i==accentIdx)G->drawCircle(cx,Y(cy),13,C_TXT);
    if(tapIn(cx-13,cy-13,26,26)){accentIdx=i;settingsDirty=true;beepTap();}}
  y+=56;
  // clear
  G->fillRoundRect(x,Y(y),w,40,8,C_PANEL);
  ff("Clear all detections",x+14,y+20,C_RED,&FreeSans9pt7b,ML_DATUM);
  ff(">",x+w-16,y+20,C_RED,&FreeSansBold9pt7b,MR_DATUM);
  if(tapIn(x,y,w,40)){portENTER_CRITICAL(&mux);devCount=0;portEXIT_CRITICAL(&mux);beepTap();}
  y+=50;
  G->fillRoundRect(x,Y(y),w,44,8,C_PANEL);
  tt("PHANTOM v3.6  -  receive only",x+14,y+15,C_MUTED,1,TL_DATUM);
  tt("No deauth / jam / spam. Passive RX.",x+14,y+30,C_MUTED,1,TL_DATUM);
}

// ======================================================================
//  Frame
// ======================================================================
static void drawView(uint32_t now){
  if(view==V_HOME){header("",false);drawHome(now);}
  else{ header(APPS[view-1].name,true);
    switch(view){case V_TRACK:appDefense(now);break;case V_SCANNER:appScanner(now);break;
      case V_WIFI:appWifi(now);break;case V_BT:appBt(now);break;case V_SET:appSettings(now);break;}
    if(tapIn(0,0,56,30)){view=V_HOME;beepTap();} }
}
static void render(uint32_t now){
  if(bandH){G=&spr; for(int y0=0;y0<240;y0+=bandH){OY=-y0;spr.fillSprite(C_BG);drawView(now);spr.pushSprite(0,y0);} }
  else{G=&tft;OY=0;tft.fillScreen(C_BG);drawView(now);}
  tapX=tapY=-1;
}
static void splash(){
  tft.fillScreen(C_BG); tft.setTextDatum(MC_DATUM); tft.setTextColor(ACC);
  tft.setFreeFont(&FreeSansBold18pt7b); tft.drawString("PHANTOM",160,108); tft.drawString("PHANTOM",161,108);
  tft.setTextFont(2); tft.setTextColor(C_MUTED); tft.drawString("counter-surveillance  -  booting",160,150);
}

// ======================================================================
//  Settings persistence
// ======================================================================
static void loadSettings(){ prefs.begin("phantom",true);
  soundOn=prefs.getBool("snd",true); brightness=prefs.getUChar("brt",230);
  accentIdx=prefs.getUChar("acc",0); if(accentIdx>4)accentIdx=0;
  colorBGR=prefs.getBool("bgr",false); invertOn=prefs.getBool("inv",invertOn); prefs.end(); }
static void saveSettings(){ prefs.begin("phantom",false);
  prefs.putBool("snd",soundOn); prefs.putUChar("brt",brightness);
  prefs.putUChar("acc",accentIdx); prefs.putBool("bgr",colorBGR);
  prefs.putBool("inv",invertOn); prefs.end(); }

// ======================================================================
//  Setup / loop
// ======================================================================
void setup(){
  Serial.begin(115200);
  pinMode(LED_R,OUTPUT);pinMode(LED_G,OUTPUT);pinMode(LED_B,OUTPUT);pinMode(BTN_BOOT,INPUT_PULLUP);
  setLed(false,false,false);
  ledcSetup(0,2000,8);ledcAttachPin(SPEAKER,0);
  ledcSetup(1,5000,8);ledcAttachPin(TFT_BL,1);
  loadSettings(); setBright(brightness);

  tft.init(); tft.setRotation(1);
  tft.invertDisplay(invertOn);
  applyColorOrder();
  tsSPI.begin(T_CLK,T_MISO,T_MOSI,T_CS); ts.begin(tsSPI); ts.setRotation(1);
  splash();
  spr.setColorDepth(16);
  for(int h:{120,80,60,48,40}) if(spr.createSprite(320,h)){bandH=h;break;}

  WiFi.mode(WIFI_STA); WiFi.disconnect();
  esp_wifi_set_promiscuous(true); esp_wifi_set_promiscuous_rx_cb(&promiscCB);

  NimBLEDevice::init("");
  bleScan=NimBLEDevice::getScan();
  bleScan->setAdvertisedDeviceCallbacks(new BleCB(),true);
  bleScan->setActiveScan(false); bleScan->setInterval(160); bleScan->setWindow(80);
  bleScan->setMaxResults(0); bleScan->start(0,nullptr,false);
  delay(600);
  Serial.println("PHANTOM 3.5 up");
}

void loop(){
  static uint32_t lastDraw=0,lastWin=0,chanHop=0,lastSave=0; static uint8_t ch=1; static bool alerting=false,trkAl=false;
  uint32_t now=millis();
  handleTouch();

  if(now-chanHop>250){chanHop=now;ch=ch%13+1;esp_wifi_set_channel(ch,WIFI_SECOND_CHAN_NONE);}
  if(now-lastWin>1000){lastWin=now;deauthWindow=deauthCount;deauthCount=0;}
  wifiScanStep();

  // tracker-follow alarm
  bool follow=false;
  portENTER_CRITICAL(&mux);
  for(int i=0;i<devCount;i++) if(dev[i].tracker&&now-dev[i].lastSeen<60000&&(now-dev[i].firstSeen)>120000){
    follow=true; if(!dev[i].alarmed){dev[i].alarmed=true;trkAlarmUntil=now+6000;} }
  portEXIT_CRITICAL(&mux);
  if(now<trkAlarmUntil){ if(!trkAl){trkAl=true;trackerAlarm();} bool p=(now/200)%2; setLed(p,false,p);}
  else if(trkAl){trkAl=false;setLed(false,false,false);}

  // emergency alert
  int pa=pendingAlert;
  if(pa>=0){pendingAlert=-1; if(!(now<alertUntil&&alertCat<pa))alertCat=pa; alertUntil=now+6000;
    if(view==V_HOME)view=V_SCANNER; alertSound(alertCat); lastDraw=0;}
  bool a=now<alertUntil;
  if(a!=alerting){alerting=a; if(!a&&!trkAl)setLed(false,false,false); lastDraw=0;}
  if(alerting&&!trkAl){bool ph=(now/220)%2; switch(alertCat){case CAT_POLICE:setLed(ph,0,!ph);break;
    case CAT_EMS:setLed(1,!ph,!ph);break;case CAT_FIRE:setLed(ph,0,0);break;default:setLed(ph,ph,0);}}

  if(settingsDirty&&now-lastSave>400){saveSettings();settingsDirty=false;lastSave=now;}

  bool anim=(view==V_HOME||view==V_TRACK||view==V_SCANNER);
  uint32_t every=bandH?(pressed?33:(anim?70:150)):400;
  if(!lastDraw||now-lastDraw>=every||tapX>=0){lastDraw=now;render(now);}

  if(!bleScan->isScanning())bleScan->start(0,nullptr,false);
  delay(4);
}
