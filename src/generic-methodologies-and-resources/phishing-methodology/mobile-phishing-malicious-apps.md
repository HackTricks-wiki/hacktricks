# 移动钓鱼与恶意应用分发（Android 和 iOS）

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> 本页涵盖了威胁行为者通过钓鱼（SEO、社交工程、假商店、约会应用等）分发**恶意 Android APK**和**iOS 移动配置文件**的技术。
> 材料改编自 Zimperium zLabs（2025）曝光的 SarangTrap 活动和其他公开研究。

## 攻击流程

1. **SEO/钓鱼基础设施**
* 注册数十个相似域名（约会、云分享、汽车服务等）。
– 在 `<title>` 元素中使用本地语言关键词和表情符号以在 Google 中排名。
– 在同一着陆页上托管 *Android*（`.apk`）和 *iOS* 安装说明。
2. **第一阶段下载**
* Android：直接链接到 *未签名* 或“第三方商店”APK。
* iOS：`itms-services://` 或普通 HTTPS 链接到恶意 **mobileconfig** 配置文件（见下文）。
3. **安装后的社交工程**
* 应用首次运行时要求输入 **邀请/验证代码**（独占访问幻觉）。
* 代码通过 **HTTP POST** 发送到指挥与控制（C2）。
* C2 回复 `{"success":true}` ➜ 恶意软件继续。
* 沙箱/AV 动态分析未提交有效代码时不会看到 **恶意行为**（规避）。
4. **运行时权限滥用**（Android）
* 危险权限仅在 **C2 正面响应后** 请求：
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- 较旧版本也请求 SMS 权限 -->
```
* 最近的变种 **从 `AndroidManifest.xml` 中移除 SMS 的 `<uses-permission>`**，但保留通过反射读取 SMS 的 Java/Kotlin 代码路径 ⇒ 降低静态评分，同时在通过 `AppOps` 滥用或旧目标授予权限的设备上仍然有效。
5. **外观 UI 和后台收集**
* 应用显示无害视图（SMS 查看器、图库选择器）在本地实现。
* 同时它提取：
- IMEI / IMSI，电话号码
- 完整的 `ContactsContract` 转储（JSON 数组）
- 从 `/sdcard/DCIM` 压缩的 JPEG/PNG，使用 [Luban](https://github.com/Curzibn/Luban) 减小大小
- 可选 SMS 内容（`content://sms`）
有效载荷通过 `HTTP POST /upload.php` **批量压缩**并发送。
6. **iOS 交付技术**
* 单个 **移动配置文件** 可以请求 `PayloadType=com.apple.sharedlicenses`，`com.apple.managedConfiguration` 等，以将设备注册到“MDM”类监督中。
* 社交工程指令：
1. 打开设置 ➜ *配置文件已下载*。
2. 点击 *安装* 三次（钓鱼页面上的截图）。
3. 信任未签名的配置文件 ➜ 攻击者获得 *联系人* 和 *照片* 权限，无需 App Store 审核。
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
## 指标（通用）
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## 参考

- [浪漫的黑暗面：SarangTrap 敲诈活动](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android 图像压缩库](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
