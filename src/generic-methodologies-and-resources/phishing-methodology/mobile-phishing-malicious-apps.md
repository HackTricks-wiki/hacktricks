# モバイルフィッシングと悪意のあるアプリ配布 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽のストア、出会い系アプリなど）を通じて**悪意のあるAndroid APK**と**iOSモバイル構成プロファイル**を配布するために使用する技術をカバーしています。
> この資料は、Zimperium zLabsによって暴露されたSarangTrapキャンペーン（2025年）およびその他の公的研究から適応されています。

## 攻撃フロー

1. **SEO/フィッシングインフラ**
* 類似ドメイン（出会い系、クラウド共有、車サービスなど）を多数登録します。
– Googleでランク付けするために、`<title>`要素に現地の言語のキーワードと絵文字を使用します。
– Android（`.apk`）とiOSのインストール手順の両方を同じランディングページにホストします。
2. **第一段階のダウンロード**
* Android: *署名されていない*または「サードパーティストア」のAPKへの直接リンク。
* iOS: 悪意のある**mobileconfig**プロファイルへの`itms-services://`または通常のHTTPSリンク（下記参照）。
3. **インストール後のソーシャルエンジニアリング**
* 初回起動時にアプリが**招待/確認コード**を要求します（排他的アクセスの幻想）。
* コードは**HTTP経由でPOST**され、コマンド＆コントロール（C2）に送信されます。
* C2は`{"success":true}`と応答 ➜ マルウェアが続行します。
* 有効なコードを提出しないサンドボックス/AVの動的分析は**悪意のある動作を見ない**（回避）。
4. **ランタイム権限の悪用** (Android)
* 危険な権限は**C2の肯定的な応答の後にのみ要求されます**：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- 古いビルドではSMS権限も要求されていました -->
```
* 最近のバリアントは**`AndroidManifest.xml`からSMSのための`<uses-permission>`を削除**しますが、リフレクションを通じてSMSを読み取るJava/Kotlinコードパスは残します ⇒ 権限を`AppOps`の悪用や古いターゲットを通じて付与するデバイスでは機能し続けるため、静的スコアが低下します。
5. **ファサードUIとバックグラウンド収集**
* アプリは無害なビュー（SMSビューワー、ギャラリーピッカー）をローカルに実装して表示します。
* 同時に以下を外部流出させます：
- IMEI / IMSI、電話番号
- 完全な`ContactsContract`ダンプ（JSON配列）
- `/sdcard/DCIM`から圧縮されたJPEG/PNG（サイズを減らすために[Luban](https://github.com/Curzibn/Luban)を使用）
- オプションのSMS内容（`content://sms`）
ペイロードは**バッチ圧縮**され、`HTTP POST /upload.php`経由で送信されます。
6. **iOS配信技術**
* 単一の**モバイル構成プロファイル**は、`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration`などを要求して、デバイスを「MDM」のような監視に登録できます。
* ソーシャルエンジニアリングの指示：
1. 設定を開く ➜ *プロファイルがダウンロードされました*。
2. *インストール*を3回タップします（フィッシングページのスクリーンショット）。
3. 署名されていないプロファイルを信頼する ➜ 攻撃者は*連絡先*と*写真*の権限をApp Storeのレビューなしで取得します。
7. **ネットワーク層**
* 通常のHTTP、しばしばポート80で、`api.<phishingdomain>.com`のようなHOSTヘッダーを使用します。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に見つけられます）。

## 防御テスト / レッドチームのヒント

* **動的分析の回避** – マルウェア評価中に、Frida/Objectionを使用して招待コードフェーズを自動化し、悪意のあるブランチに到達します。
* **マニフェストとランタイムの差分** – `aapt dump permissions`とランタイムの`PackageManager#getRequestedPermissions()`を比較します；危険な権限が欠けているのは赤信号です。
* **ネットワークカナリア** – `iptables -p tcp --dport 80 -j NFQUEUE`を設定して、コード入力後の不正なPOSTバーストを検出します。
* **mobileconfig検査** – macOSで`security cms -D -i profile.mobileconfig`を使用して`PayloadContent`をリストし、過剰な権限を特定します。

## ブルーチームの検出アイデア

* **証明書の透明性 / DNS分析**で、キーワードが豊富なドメインの突然のバーストをキャッチします。
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php`をGoogle Play外のDalvikクライアントから取得します。
* **招待コードのテレメトリ** – APKインストール後すぐに6〜8桁の数値コードのPOSTは、ステージングを示す可能性があります。
* **MobileConfig署名** – MDMポリシーを通じて署名されていない構成プロファイルをブロックします。

## 有用なFridaスニペット: 招待コードの自動バイパス
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
## インジケーター (一般)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## 参考文献

- [ロマンスの暗い側面: SarangTrap恐喝キャンペーン](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android画像圧縮ライブラリ](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
