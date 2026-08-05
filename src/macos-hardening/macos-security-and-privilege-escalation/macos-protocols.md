# macOS 网络服务与协议

{{#include ../../banners/hacktricks-training.md}}

## 远程访问服务

以下是常见的 macOS 远程访问服务。\
你可以在 `System Settings` --> `Sharing` 中启用或禁用这些服务。

- **VNC**，称为“Screen Sharing”（tcp:5900）
- **SSH**，称为“Remote Login”（tcp:22）
- **Apple Remote Desktop**（ARD），或称为“Remote Management”（tcp:3283, tcp:5900）
- **AppleEvent**，称为“Remote Apple Event”（tcp:3031）

运行以下命令检查是否有服务已启用：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### 在本地枚举 sharing 配置

当你已经在 Mac 上获得 local code execution 时，**检查已配置的状态**，而不只是检查 listening sockets。`systemsetup` 和 `launchctl` 通常会告知你该服务是否已由管理员启用，而 `kickstart` 和 `system_profiler` 有助于确认实际生效的 ARD/Sharing 配置：
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) 是针对 macOS 定制的增强版 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)，提供了额外功能。ARD 中一个值得注意的 vulnerability 是其 control screen password 的 authentication method：该方法只使用 password 的前 8 个字符，因此容易受到使用 Hydra 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 等工具发起的 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) 攻击，因为不存在默认的 rate limits。<sup>[[3]](#references)</sup>

可以使用 **nmap** 的 `vnc-info` script 识别 vulnerable instances。支持 `VNC Authentication (2)` 的 services 尤其容易受到 brute force attacks 的影响，因为 password 会被截断为 8 个字符。

要启用 ARD 以执行 privilege escalation、GUI access 或 user monitoring 等各种 administrative tasks，请使用以下 command：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD 提供灵活的控制级别，包括观察、共享控制和完全控制，并且即使用户更改密码，session 仍会持续存在。它允许直接发送 Unix commands，并以 root 身份为管理员用户执行这些 commands。任务 scheduling 和 Remote Spotlight search 是值得注意的功能，可在多台机器上远程执行低影响的敏感文件搜索。

从 operator 的角度来看，**Monterey 12.1+ 改变了受管 fleet 中的远程启用工作流**。如果你已经控制了受害者的 MDM，Apple 的 `EnableRemoteDesktop` command 通常是在较新系统上激活 remote desktop 功能的最简洁方式。如果你已经在主机上建立 foothold，`kickstart` 仍可用于从 command line 检查或重新配置 ARD 权限。

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

近期对 `screensharingd` 的研究表明，Apple Screen Sharing 并不总是仅使用经典的 VNC auth：较新的 build 使用 **RFB `003.889`**，并公布 **security type `36`**，其中先由 **SRP** 完成 auth，只有在 `ccsrp_server_verify_session` 成功后才会安装 **ChaCha20-Poly1305**。公开披露指出，该 bug 已在 **macOS Tahoe 26.6**（**2026 年 7 月 27 日**）中修复。<sup>[[8]](#references)[[9]](#references)</sup>

需要记住的一个实用模式是 **stale-status parser bypass**：成功读取 4-byte length 后，每个 oversized/error 分支都必须返回新的 error。在受影响的 build 中，大端序 SRP frame length **`>= 32768`** 会使 rejection path 重用之前的 `NetBufferRead` success（`0`），因此 caller 会将 session 设置为已 authenticated，尽管没有执行 password proof，也没有安装 transport crypto。由于未读取的 bytes 会保留在共享 socket buffer 中，攻击者可以在同一个 TCP burst 中 **pipeline malformed SRP data 和 post-auth RFB messages**，并使其被解析为 **cleartext authenticated traffic**。<sup>[[8]](#references)</sup>

绕过该限制后，Apple 专有的 **file-copy** message **`0x22`** 会变成 **root file read/write primitive**，因为 `screensharingd` 以 root 身份运行：<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`：任意文件读取
- `kind=2` / `StartFileReceive`：任意文件写入
- 不同的 `sid` 值允许你在一个连接中 pipeline 多个事务
- 在 `kind=101`（`NewItem`）中，将 byte `14` / `arg[0]` 设置为 `0x01` 表示常规文件，将 payload offset `+42` 设置为**非零**的大端文件大小，并将 payload offset `+0x5a` 设置为所需的 Unix mode（如果目标是 crontab，则设置为 `0600`）

可写路径上有趣的 post-write pivots 包括 **`/etc/sudoers.d/`**、**`/etc/zshenv`**、**`/Library/LaunchDaemons/`** 和 **`/var/root/.ssh/authorized_keys`**。**SIP 不会阻止 auth bypass 或 root file read**，但它会阻止某些写入目标，例如 **`/var/at`**，因此基于 cron 的执行只有在禁用 SIP 时才有效。在默认启用 SIP 的主机上，应当将其理解为**“向特权自动消费文件中进行 root file write”**，而不是立即执行代码。<sup>[[8]](#references)</sup>

同一研究还指出了另一个 SRP 陷阱：服务器必须验证 **`A mod N != 0`**（依据 RFC 5054），而不能只验证 **`A > 0`**。接受 **`A = N`** 可能会将共享 secret 强制设为零，从而破坏 password verification。<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- Security type `36` 会话中，第一条 SRP frame length **`>= 32768`**
- 在任何成功的 SRP proof / cipher install 之前，就开始处理明文 **`0x22`** file-copy traffic 的会话
- 针对 **TCP/5900** 的重复短时 retries，以及同一 burst 中的多个 file-copy `sid` 值
- 在暴露 Screen Sharing 后，意外创建 **`/etc/zshenv`**、**`/etc/sudoers.d/*`**、**`/Library/LaunchDaemons/*.plist`** 或 **`/var/root/.ssh/authorized_keys`**

### Pentesting Remote Apple Events (RAE / EPPC)

Apple 在现代 System Settings 中将此功能称为 **Remote Application Scripting**。在底层，它通过 **TCP/3031** 上的 `com.apple.AEServer` service，通过 **EPPC** 远程暴露 **Apple Event Manager**。Palo Alto Unit 42 再次强调了它作为实用 **macOS lateral movement** primitive 的作用，因为有效 credentials 加上启用的 RAE service 后，operator 就可以驱动远程 Mac 上支持 scripting 的 applications。<sup>[[6]](#references)</sup>

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
如果你已经在目标系统上拥有 admin/root 权限，并希望启用它：
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
来自另一台 Mac 的基本连通性测试：
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
在实践中，这种滥用场景并不局限于 Finder。任何接受所需 Apple events 的 **scriptable application** 都会成为远程攻击面，因此在 macOS 内部网络中凭据被窃取后，RAE 尤其值得关注。

#### 近期 Screen-Sharing / ARD 漏洞（2023-2025）

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|错误的会话渲染可能导致传输 *错误的* 桌面或窗口，从而造成敏感信息泄露|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|由于状态管理问题，拥有 Screen Sharing 访问权限的用户可能能够查看 **其他用户的屏幕**|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* 在不严格需要时，禁用 *Screen Sharing*/*Remote Management*。
* 保持 macOS 完全打好补丁（Apple 通常会为最近的三个 major releases 提供 security fixes）。
* 使用 **Strong Password**，并在可能的情况下确保禁用 *“VNC viewers may control screen with password”* 选项。
* 将该服务置于 VPN 后，而不是将 TCP 5900/3283 暴露到 Internet。
* 添加 Application Firewall 规则，将 `ARDAgent` 限制到本地子网：

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour 协议

Bonjour 是 Apple 设计的一项技术，允许 **同一网络中的设备检测彼此提供的服务**。它也被称为 Rendezvous、**Zero Configuration** 或 Zeroconf，能够让设备加入 TCP/IP 网络、**自动选择 IP 地址**，并向其他网络设备广播其服务。

由 Bonjour 提供的 Zero Configuration Networking 确保设备能够：

- **自动获取 IP Address**，即使不存在 DHCP server。
- 执行**名称到地址的转换**，而无需 DNS server。
- **发现**网络上可用的服务。

使用 Bonjour 的设备会为自己分配一个**来自 169.254/16 范围的 IP 地址**，并验证该地址在网络中的唯一性。Mac 会为此子网维护一条 routing table 条目，可通过 `netstat -rn | grep 169` 验证。

对于 DNS，Bonjour 使用 **Multicast DNS (mDNS) protocol**。mDNS 通过 **port 5353/UDP** 运行，采用**标准 DNS queries**，但目标地址为**multicast address 224.0.0.251**。这种方式确保网络中所有正在监听的设备都能接收并响应 queries，从而便于更新其记录。

加入网络后，每台设备都会自行选择一个名称，通常以 **.local** 结尾，该名称可能源自 hostname，也可能是随机生成的。

网络中的服务发现通过 **DNS Service Discovery (DNS-SD)** 实现。DNS-SD 利用 DNS SRV records 的格式，并使用 **DNS PTR records** 来支持列出多个服务。寻找特定服务的 client 会请求 `<Service>.<Domain>` 的 PTR record；如果该服务由多个 host 提供，则会返回格式为 `<Instance>.<Service>.<Domain>` 的 PTR records 列表。

`dns-sd` utility 可用于**发现和广播网络服务**。以下是一些使用示例：

### 搜索 SSH Services

要在网络中搜索 SSH services，可使用以下 command：
```bash
dns-sd -B _ssh._tcp
```
此命令会开始浏览 \_ssh.\_tcp 服务，并输出时间戳、标志、接口、域、服务类型和实例名称等详细信息。

### Advertising an HTTP Service

要发布 HTTP 服务，可以使用：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
此命令会在端口 80 上注册一个名为“Index”、路径为 `/index.html` 的 HTTP 服务。

随后搜索网络中的 HTTP 服务：
```bash
dns-sd -B _http._tcp
```
当一项 service 启动时，它会通过 multicast 宣布自身的可用性，使子网中的所有设备都能发现它。对这些 services 感兴趣的设备无需发送请求，只需监听这些公告即可。

为了提供更加 user-friendly 的界面，Apple App Store 中提供的 **Discovery - DNS-SD Browser** app 可以可视化本地网络上提供的 services。

或者，也可以使用 `python-zeroconf` library 编写 custom scripts 来浏览和发现 services。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script 演示了如何为 `_http._tcp.local.` services 创建 service browser，并打印已添加或已移除的 services：
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### macOS 特有的 Bonjour hunting

在 macOS 网络中，Bonjour 通常是在不直接接触目标的情况下查找**远程管理界面**的最简单方式。Apple Remote Desktop 本身可以通过 Bonjour 发现客户端，因此相同的发现数据对攻击者也很有用。
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
对于更广泛的 **mDNS spoofing、impersonation 和 cross-subnet discovery** 技术，请查看专门页面：

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### 在网络中枚举 Bonjour

* **Nmap NSE** – 发现单个主机所 advertise 的 services：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` script 会发送 `_services._dns-sd._udp.local` query，然后枚举每种 advertise 的 service type。

* **mdns_recon** – 用于扫描整个范围、查找会响应 unicast queries 的 *misconfigured* mDNS responders 的 Python tool（可用于发现跨 subnet/WAN 可访问的设备）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

这将返回通过 Bonjour 在 local link 之外暴露 SSH 的主机。

### 安全注意事项与近期 vulnerabilities（2024-2025）

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* 中的 logic error 允许 crafted packet 触发 **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* 中的 correctness issue 可能被利用进行 **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. 将 UDP 5353 限制在 *link-local* scope 内 – 在 wireless controllers、routers 和 host-based firewalls 上 block 或 rate-limit 它。
2. 在不需要 service discovery 的系统上完全 disable Bonjour：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. 对于内部需要 Bonjour、但绝不能跨越 network boundaries 的环境，使用 *AirPlay Receiver* profile restrictions（MDM）或 mDNS proxy。
4. 启用 **System Integrity Protection (SIP)** 并保持 macOS up to date – 上述两个 vulnerabilities 均已快速 patched，但要获得完整保护，必须启用 SIP。

### 禁用 Bonjour

如果出于 security concerns 或其他原因需要 disable Bonjour，可以使用以下 command：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考资料

- [1] [Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [Mac Malware 的艺术，第一卷：分析 - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206：ARD（Apple Remote Desktop Protocol）](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD - CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD - CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - macOS 上的 Lateral Movement：独特且常见的技术及真实案例](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - 关于 macOS Sonoma 14.7.2 的安全内容](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - 关于 macOS Tahoe 26.6 的安全内容](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - 使用 Secure Remote Password（SRP）Protocol 进行 TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
