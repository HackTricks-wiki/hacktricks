# Мобільний Фішинг та Розповсюдження Шкідливих Додатків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка охоплює техніки, які використовують загрози для розповсюдження **шкідливих Android APK** та **профілів мобільної конфігурації iOS** через фішинг (SEO, соціальна інженерія, фейкові магазини, додатки для знайомств тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025) та інших публічних досліджень.

## Потік Атаки

1. **Інфраструктура SEO/Фішингу**
* Зареєструвати десятки доменів, що схожі (знайомства, хмарний обмін, автомобільні послуги…).
– Використовувати ключові слова та емодзі місцевою мовою в елементі `<title>`, щоб піднятися в Google.
– Розмістити *обидва* інструкції з установки Android (`.apk`) та iOS на одній цільовій сторінці.
2. **Перший Етап Завантаження**
* Android: пряме посилання на *недодаткований* або “сторону третьої особи” APK.
* iOS: `itms-services://` або просте HTTPS посилання на шкідливий **mobileconfig** профіль (див. нижче).
3. **Соціальна Інженерія Після Встановлення**
* При першому запуску додаток запитує **код запрошення / перевірки** (ілюзія ексклюзивного доступу).
* Код **POSTиться через HTTP** на Командний та Контрольний (C2).
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
5. **Фасадний UI та Збір Даних у Фоновому Режимі**
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
* **Порівняння Маніфесту та Часу Виконання** – Порівняйте `aapt dump permissions` з `PackageManager#getRequestedPermissions()` під час виконання; відсутність небезпечних дозволів є червоним прапором.
* **Мережева Канарка** – Налаштуйте `iptables -p tcp --dport 80 -j NFQUEUE`, щоб виявити непостійні сплески POST після введення коду.
* **Перевірка mobileconfig** – Використовуйте `security cms -D -i profile.mobileconfig` на macOS, щоб перерахувати `PayloadContent` і виявити надмірні права.

## Ідеї для Виявлення Блакитної Команди

* **Прозорість Сертифікатів / DNS Аналітика** для виявлення раптових сплесків доменів з багатими ключовими словами.
* **User-Agent та Regex Шляхів**: `(?i)POST\s+/(check|upload)\.php` з клієнтів Dalvik поза Google Play.
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
## Посилання

- [Темна сторона романтики: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – бібліотека стиснення зображень для Android](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
