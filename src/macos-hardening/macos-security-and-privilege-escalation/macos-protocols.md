# macOS 网络服务与协议

{{#include ../../banners/hacktricks-training.md}}

## 远程访问服务

以下是常见的 macOS 远程访问服务。\
你可以在 `System Settings` --> `Sharing` 中启用或禁用这些服务<sup>[[1]](#references)</sup>

- **VNC**，称为“Screen Sharing”（tcp:5900）
- **SSH**，称为“Remote Login”（tcp:22）
- **Apple Remote Desktop**（ARD），或“Remote Management”（tcp:3283、tcp:5900）
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
### 在本地枚举共享配置

当你已经在 Mac 上获得本地 code execution 时，**检查已配置的状态**，而不只是监听的 sockets。`systemsetup` 和 `launchctl` 通常会告诉你该 service 是否已由管理员启用，而 `kickstart` 和 `system_profiler` 则有助于确认实际生效的 ARD/Sharing 配置：
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) 是针对 macOS 定制的增强版 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)，提供了额外功能。ARD 中一个值得注意的漏洞在于其控制屏幕密码的认证方式：只使用密码的前 8 个字符，因此容易受到使用 Hydra 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 等工具进行的 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) 攻击，因为默认没有速率限制。<sup>[[2]](#references)</sup>

可以使用 **nmap** 的 `vnc-info` script 识别存在漏洞的实例。支持 `VNC Authentication (2)` 的服务尤其容易受到 brute force attacks 的影响，因为密码会被截断为 8 个字符。

要启用 ARD 以执行各种管理任务，例如 privilege escalation、GUI 访问或用户监控，请使用以下命令：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD 提供灵活的控制级别，包括观察、共享控制和完全控制，并且即使用户密码发生更改，会话仍会持续。它允许直接发送 Unix 命令，并可对管理员用户以 root 身份执行这些命令。任务调度和 Remote Spotlight 搜索是其显著功能，可在多台机器上远程执行低影响的敏感文件搜索。

从 operator 的角度来看，**Monterey 12.1+ 更改了受管 fleet 中的 remote-enablement 工作流**。如果你已经控制了受害者的 MDM，Apple 的 `EnableRemoteDesktop` 命令通常是在较新系统上启用远程桌面功能的最简洁方式。如果你已经在主机上获得 foothold，`kickstart` 仍可用于从命令行检查或重新配置 ARD 权限。

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

最近对 `screensharingd` 的研究表明，Apple Screen Sharing 并不总是使用经典的 VNC auth：较新的 build 使用 **RFB `003.889`**，并公布 **security type `36`**，其中首先由 **SRP** 完成 auth，只有在 `ccsrp_server_verify_session` 成功后才会安装 **ChaCha20-Poly1305**。公开 write-up 报告称，该 bug 已在 **macOS Tahoe 26.6**（**2026 年 7 月 27 日**）中修复。<sup>[[8]](#references)[[9]](#references)</sup>

需要记住的一个有用模式是 **stale-status parser bypass**：成功读取 4 字节长度后，每个 oversized/error 分支都必须返回新的 error。在受影响的 build 中，大端序 SRP frame length **`>= 32768`** 会使 rejection path 重用之前的 `NetBufferRead` success（`0`），因此 caller 会将 session 设置为 authenticated，尽管没有执行 password proof，也没有安装 transport crypto。由于未读取的字节仍保留在共享 socket buffer 中，攻击者可以在同一个 TCP burst 中 **pipeline malformed SRP data 和 post-auth RFB messages**，并使它们被解析为**明文 authenticated traffic**。<sup>[[8]](#references)</sup>

绕过后，Apple 专有的 **file-copy** message **`0x22`** 会变成一个**root 文件读写 primitive**，因为 `screensharingd` 以 root 身份运行：<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`：任意文件读取
- `kind=2` / `StartFileReceive`：任意文件写入
- 不同的 `sid` 值允许你在一个连接中 pipeline 多个 transaction
- 在 `kind=101` (`NewItem`) 中，将字节 `14` / `arg[0]` 设置为 `0x01` 以表示普通文件，将 payload offset `+42` 设置为**非零**的大端序文件大小，并将 payload offset `+0x5a` 设置为所需的 Unix mode（如果目标是 crontab，则设置为 `0600`）

可利用的 writable paths 包括 **`/etc/sudoers.d/`**、**`/etc/zshenv`**、**`/Library/LaunchDaemons/`** 和 **`/var/root/.ssh/authorized_keys`**。**SIP 不会阻止 auth bypass 或 root file read**，但会阻止某些 write targets，例如 **`/var/at`**，因此基于 cron 的执行只有在禁用 SIP 时才有效。在默认启用 SIP 的主机上，应考虑 **“将 root file write 写入特权自动消费的文件”**，而不是立即执行 code。<sup>[[8]](#references)</sup>

同一研究还指出了另一个 SRP 陷阱：服务器必须验证 **`A mod N != 0`**（依据 RFC 5054），而不能只验证 `A > 0`。接受 **`A = N`** 可能会将 shared secret 强制为零，并破坏 password verification。<sup>[[8]](#references)[[10]](#references)</sup>

**Detection ideas**

- Security type `36` sessions，其中第一个 SRP frame length 为 **`>= 32768`**
- 在任何成功的 SRP proof / cipher install 之前，就开始处理明文 **`0x22`** file-copy traffic 的 sessions
- 针对 **TCP/5900** 的反复短生命周期 retries，以及单次 burst 中出现多个 file-copy `sid` 值
- 在暴露 Screen Sharing 后，意外创建 **`/etc/zshenv`**、**`/etc/sudoers.d/*`**、**`/Library/LaunchDaemons/*.plist`** 或 **`/var/root/.ssh/authorized_keys`**

### Pentesting Remote Apple Events (RAE / EPPC)

Apple 在现代 System Settings 中将此功能称为 **Remote Application Scripting**。在底层，它通过 **EPPC** 在 **TCP/3031** 上远程暴露 **Apple Event Manager**，并使用 `com.apple.AEServer` service。Palo Alto Unit 42 再次强调了它作为实用 **macOS lateral movement** primitive 的价值，因为有效 credentials 加上已启用的 RAE service，可让 operator 驱动远程 Mac 上支持 scripting 的 applications。<sup>[[6]](#references)</sup>

Useful checks：
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
如果你已经在目标系统上拥有 admin/root 权限，并希望启用它：
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
从另一台 Mac 进行基本连接测试：
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
实际上，这种滥用场景并不局限于 Finder。任何接受所需 Apple events 的 **可编写脚本的应用程序** 都会成为远程攻击面，这使得 RAE 在 macOS 内部网络中发生凭据窃取后尤其值得关注。

#### 近期 Screen-Sharing / ARD vulnerabilities（2023-2025）

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|错误的会话渲染可能导致传输*错误的*桌面或窗口，从而造成敏感信息泄露|macOS Sonoma 14.2.1（2023 年 12 月） <sup>[[3]](#references)</sup>|
|2024|CVE-2024-44248|Screen Sharing Server|由于状态管理问题，拥有 Screen Sharing 访问权限的用户可能能够查看**其他用户的屏幕**|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1（2024 年 10 月至 12 月） <sup>[[7]](#references)</sup>|

**Hardening tips**

* 不严格需要时，禁用 *Screen Sharing*/*Remote Management*。
* 保持 macOS 完全更新（Apple 通常会为最近三个主要版本发布安全修复）。
* 使用 **Strong Password**，并在可能的情况下禁用 *“VNC viewers may control screen with password”* 选项。
* 将该服务置于 VPN 后方，而不是将 TCP 5900/3283 暴露到 Internet。
* 添加 Application Firewall 规则，将 `ARDAgent` 限制在本地子网内：

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour 协议

Bonjour 是 Apple 设计的一项技术，允许**同一网络中的设备发现彼此提供的服务**。它也被称为 Rendezvous、**Zero Configuration** 或 Zeroconf，使设备能够加入 TCP/IP 网络、**自动选择 IP 地址**，并向其他网络设备广播自身服务。

Bonjour 提供的 Zero Configuration Networking 可确保设备能够：

- 即使没有 DHCP server，也能**自动获取 IP Address**。
- 无需 DNS server 即可执行**名称到地址的转换**。
- **发现**网络上可用的服务。

使用 Bonjour 的设备会从 **169.254/16 范围**中为自身分配一个 **IP address**，并验证该地址在网络中的唯一性。Mac 会为此子网维护一个路由表条目，可通过 `netstat -rn | grep 169` 验证。

对于 DNS，Bonjour 使用 **Multicast DNS（mDNS）protocol**。mDNS 通过 **5353/UDP port** 工作，采用**标准 DNS 查询**，但目标地址为**多播地址 224.0.0.251**。这样可确保网络中所有正在监听的设备都能接收并响应查询，从而便于更新其记录。

加入网络后，每台设备都会自行选择一个名称，通常以 **.local** 结尾；该名称可能源自 hostname，也可能是随机生成的。

网络内的 service discovery 通过 **DNS Service Discovery（DNS-SD）** 实现。DNS-SD 借助 DNS SRV records 的格式，使用 **DNS PTR records** 来支持列出多个服务。请求特定服务的 client 会请求 `<Service>.<Domain>` 的 PTR record；如果该服务由多个 host 提供，则会收到格式为 `<Instance>.<Service>.<Domain>` 的 PTR records 列表。

`dns-sd` utility 可用于**发现和发布 network services**。以下是一些使用示例：

### Searching for SSH Services

要搜索网络中的 SSH services，可使用以下 command：
```bash
dns-sd -B _ssh._tcp
```
此命令会开始浏览 \_ssh.\_tcp 服务，并输出时间戳、标志、接口、域、服务类型和实例名称等详细信息。

### Advertising an HTTP Service

要发布 HTTP 服务，可以使用：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
此命令会在端口 80 上注册一个名为 "Index"、路径为 `/index.html` 的 HTTP 服务。

然后搜索网络中的 HTTP 服务：
```bash
dns-sd -B _http._tcp
```
当某个服务启动时，它会通过 multicast 在 subnet 上向所有设备宣布其可用性。对这些服务感兴趣的设备不需要发送请求，只需监听这些公告即可。

为了提供更友好的界面，可以使用 Apple App Store 上提供的 **Discovery - DNS-SD Browser** app，直观显示本地网络中提供的服务。

或者，也可以使用 `python-zeroconf` library 编写自定义 scripts 来浏览和发现服务。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script 演示了如何为 `_http._tcp.local.` services 创建 service browser，并打印已添加或已移除的 services：
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
### macOS 专属 Bonjour 探测

在 macOS 网络中，Bonjour 通常是发现**远程管理接口**的最简单方式，且无需直接接触目标。Apple Remote Desktop 本身可以通过 Bonjour 发现客户端，因此攻击者也可以利用相同的发现数据。
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
对于更广泛的 **mDNS spoofing、impersonation 和跨子网发现** 技术，请查看专门页面：

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### 在网络上枚举 Bonjour

* **Nmap NSE** – 发现单个主机所发布的服务：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` 脚本会发送 `_services._dns-sd._udp.local` 查询，然后枚举每种已发布的服务类型。

* **mdns_recon** – 一个扫描整个地址范围的 Python 工具，用于查找会响应单播查询的*配置错误* mDNS responders（可用于发现跨子网/WAN 可访问的设备）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

该命令会返回通过 Bonjour 在本地链路之外暴露 SSH 的主机。

### 安全注意事项与近期漏洞（2024-2025）

| 年份 | CVE | 严重性 | 问题 | 修复版本 |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|中|*mDNSResponder* 中的逻辑错误允许构造的数据包触发**拒绝服务**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0（2024 年 9 月） <sup>[[4]](#references)</sup>|
|2025|CVE-2025-31222|高|*mDNSResponder* 中的正确性问题可能被利用进行**本地权限提升**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5（2025 年 5 月） <sup>[[5]](#references)</sup>|

**缓解措施**

1. 将 UDP 5353 限制在*链路本地*范围内 – 在无线控制器、路由器和基于主机的防火墙上阻止或限制其速率。
2. 在不需要服务发现的系统上完全禁用 Bonjour：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. 对于内部需要 Bonjour、但绝不能跨越网络边界的环境，使用 *AirPlay Receiver* 配置文件限制（MDM）或 mDNS proxy。
4. 启用 **System Integrity Protection (SIP)** 并及时更新 macOS – 上述两个漏洞均已快速修复，但要获得完整保护，仍依赖于 SIP 处于启用状态。

### 禁用 Bonjour

如果出于安全考虑或其他原因需要禁用 Bonjour，可以使用以下命令将其关闭：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考资料

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [3] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [4] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [5] [NVD – CVE-2025-31222](https://nvd.nist.gov/vuln/detail/CVE-2025-31222)
- [6] [Palo Alto Unit 42 - macOS Lateral Movement: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - About the security content of macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)
- [11] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)

{{#include ../../banners/hacktricks-training.md}}
