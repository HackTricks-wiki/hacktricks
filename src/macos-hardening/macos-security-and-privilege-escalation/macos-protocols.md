# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

这些是用于远程访问 macOS 的常见服务。\
你可以在 `System Settings` --> `Sharing` 中启用/禁用这些服务

- **VNC**, known as “Screen Sharing” (tcp:5900)
- **SSH**, called “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), or “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, known as “Remote Apple Event” (tcp:3031)

检查是否有任何一个已启用并运行：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### 枚举本地共享配置

当你已经在 Mac 上拥有本地 code execution 时，**检查已配置状态**，而不只是监听中的 sockets。`systemsetup` 和 `launchctl` 通常会告诉你该服务是否被管理员启用，而 `kickstart` 和 `system_profiler` 有助于确认实际生效的 ARD/Sharing configuration：
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) 是 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) 的增强版，专为 macOS 定制，提供了额外功能。ARD 的一个显著漏洞在于其控制屏幕密码的认证方式：它只使用密码的前 8 个字符，因此很容易受到使用 Hydra 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 等工具进行的 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html)，因为默认情况下没有速率限制。

可以使用 **nmap** 的 `vnc-info` 脚本识别存在漏洞的实例。支持 `VNC Authentication (2)` 的服务尤其容易受到 brute force attacks，因为密码会被截断为 8 个字符。

要启用 ARD 以执行各种管理任务，例如 privilege escalation、GUI 访问或用户监控，请使用以下命令：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD 提供多种控制级别，包括 observation、shared control 和 full control，即使用户密码更改后，session 也会继续保持。它允许直接发送 Unix commands，并且可对 administrative users 以 root 身份执行这些命令。Task scheduling 和 Remote Spotlight search 是其显著功能，便于在多台机器上远程、低影响地搜索敏感文件。

从 operator 的角度看，**Monterey 12.1+ 改变了 managed fleets 中的 remote-enablement workflows**。如果你已经控制了受害者的 MDM，Apple 的 `EnableRemoteDesktop` command 通常是为较新系统启用 remote desktop 功能最干净的方法。如果你已经在主机上获得了 foothold，`kickstart` 仍然有助于从命令行检查或重新配置 ARD privileges。

### Pentesting Remote Apple Events (RAE / EPPC)

Apple 在现代 System Settings 中将此功能称为 **Remote Application Scripting**。其底层通过 `com.apple.AEServer` service 在 **TCP/3031** 上远程暴露 **Apple Event Manager**，使用的是 **EPPC**。Palo Alto Unit 42 再次强调，它是一个实用的 **macOS lateral movement** primitive，因为有效凭据加上已启用的 RAE service，允许 operator 远程驱动可脚本化应用程序。

Useful checks:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
如果你已经在目标主机上拥有 admin/root，并且想启用它：
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
来自另一台 Mac 的基本连通性测试：
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
实际上，滥用场景并不局限于 Finder。任何接受所需 Apple events 的**scriptable application** 都会成为远程攻击面，这使得在内部 macOS 网络上发生凭证窃取后，RAE 尤其有意思。

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Incorrect session rendering could cause the *wrong* desktop or window to be transmitted, resulting in leakage of sensitive information|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|A user with screen sharing access may be able to view **another user's screen** because of a state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* when not strictly required.
* Keep macOS fully patched (Apple generally ships security fixes for the last three major releases).
* Use a **Strong Password** *and* enforce the *“VNC viewers may control screen with password”* option **disabled** when possible.
* Put the service behind a VPN instead of exposing TCP 5900/3283 to the Internet.
* Add an Application Firewall rule to limit `ARDAgent` to the local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Bonjour，一项由 Apple 设计的技术，允许**同一网络上的设备检测彼此提供的服务**。它也称为 Rendezvous、**Zero Configuration** 或 Zeroconf，可让设备接入 TCP/IP 网络，**自动选择一个 IP 地址**，并向其他网络设备广播其服务。

Zero Configuration Networking，由 Bonjour 提供，确保设备可以：

- 即使在没有 DHCP server 的情况下也能**自动获取 IP Address**。
- 在不需要 DNS server 的情况下执行**name-to-address translation**。
- **发现**网络上可用的 services。

使用 Bonjour 的设备会为自己分配一个来自 **169.254/16 范围**的 **IP address**，并在网络上验证其唯一性。Mac 会为该子网维护一条 routing table 项，可通过 `netstat -rn | grep 169` 验证。

对于 DNS，Bonjour 使用 **Multicast DNS (mDNS) protocol**。mDNS 运行在 **port 5353/UDP** 上，使用**标准 DNS queries**，但目标是**multicast address 224.0.0.251**。这种方式确保网络中所有正在监听的设备都能接收并响应这些 queries，从而便于更新它们的 records。

接入网络后，每个设备会自选一个 name，通常以 **.local** 结尾，该 name 可能来源于 hostname，或随机生成。

网络内的 service discovery 由 **DNS Service Discovery (DNS-SD)** 提供。借助 DNS SRV records 的格式，DNS-SD 使用 **DNS PTR records** 来列出多个 services。寻求某项特定 service 的 client 会请求 `<Service>.<Domain>` 的 PTR record；如果该 service 可由多个 hosts 提供，则会返回一个格式为 `<Instance>.<Service>.<Domain>` 的 PTR records 列表。

`dns-sd` utility 可用于**发现和广播 network services**。以下是一些用法示例：

### Searching for SSH Services

要搜索网络中的 SSH services，使用如下 command：
```bash
dns-sd -B _ssh._tcp
```
此命令会开始浏览 \_ssh.\_tcp 服务，并输出诸如时间戳、标志、接口、域、服务类型和实例名称等详细信息。

### Advertising an HTTP Service

要 advertise 一个 HTTP service，你可以使用：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
该命令会在端口 80 上注册一个名为 "Index" 的 HTTP service，路径为 `/index.html`。

然后要在网络上搜索 HTTP services：
```bash
dns-sd -B _http._tcp
```
当一个服务启动时，它会通过多播向子网中的所有设备宣布其可用性。对这些服务感兴趣的设备不需要发送请求，只需监听这些公告即可。

为了提供更友好的界面，Apple App Store 上提供的 **Discovery - DNS-SD Browser** app 可以可视化本地网络中提供的服务。

或者，也可以使用 `python-zeroconf` 库编写自定义脚本来浏览和发现服务。[**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) 脚本演示了如何为 `_http._tcp.local.` 服务创建一个 service browser，并打印新增或移除的服务：
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
### macOS-specific Bonjour hunting

在 macOS 网络中，Bonjour 往往是发现 **remote administration surfaces** 的最简单方式，而且无需直接接触目标。Apple Remote Desktop 本身也可以通过 Bonjour 发现客户端，因此同样的发现数据对攻击者也很有用。
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

### 枚举网络中的 Bonjour

* **Nmap NSE** – 发现单个主机公布的 services：

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

`dns-service-discovery` 脚本会发送 `_services._dns-sd._udp.local` 查询，然后枚举每一种公布的 service type。

* **mdns_recon** – 一个 Python 工具，用于扫描整个范围，查找会响应 unicast queries 的 *misconfigured* mDNS responders（适用于发现可跨 subnets/WAN 访问的设备）：

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

这将返回通过 Bonjour 在本地 link 之外暴露 SSH 的 hosts。

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|*mDNSResponder* 中的一个 logic error 允许 crafted packet 触发 **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|*mDNSResponder* 中的一个 correctness issue 可能被滥用实现 **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. 将 UDP 5353 限制在 *link-local* 范围内 – 在无线控制器、路由器和基于主机的防火墙上阻止它，或对其进行 rate-limit。
2. 在不需要 service discovery 的系统上完全禁用 Bonjour：

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. 对于内部需要 Bonjour、但绝不能跨 network boundaries 的环境，使用 *AirPlay Receiver* profile restrictions（MDM）或 mDNS proxy。
4. 启用 **System Integrity Protection (SIP)** 并保持 macOS 更新到最新 – 上述两个漏洞都在很短时间内完成修补，但要获得完整保护仍依赖于启用 SIP。

### 禁用 Bonjour

如果出于安全或其他原因需要禁用 Bonjour，可以使用以下命令将其关闭：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - macOS 上的横向移动：独特且流行的技术及真实世界示例**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - 关于 macOS Sonoma 14.7.2 的安全内容**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
