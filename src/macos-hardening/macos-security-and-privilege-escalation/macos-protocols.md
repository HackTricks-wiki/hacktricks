# macOS 网络服务与协议

{{#include ../../banners/hacktricks-training.md}}

## 远程访问服务

这些是常见的 macOS 服务，用于远程访问它们。\
您可以在 `系统设置` --> `共享` 中启用/禁用这些服务。

- **VNC**，称为“屏幕共享”（tcp:5900）
- **SSH**，称为“远程登录”（tcp:22）
- **Apple Remote Desktop** (ARD)，或称为“远程管理”（tcp:3283, tcp:5900）
- **AppleEvent**，称为“远程 Apple 事件”（tcp:3031）

检查是否启用了任何服务，运行：
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) 是一个增强版的 [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing)，专为 macOS 量身定制，提供额外功能。ARD 中一个显著的漏洞是其控制屏幕密码的认证方法，仅使用密码的前 8 个字符，使其容易受到 [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) 的攻击，使用像 Hydra 或 [GoRedShell](https://github.com/ahhh/GoRedShell/) 这样的工具，因为没有默认的速率限制。

可以使用 **nmap** 的 `vnc-info` 脚本识别易受攻击的实例。支持 `VNC Authentication (2)` 的服务由于 8 字符密码截断而特别容易受到暴力攻击。

要启用 ARD 进行各种管理任务，如权限提升、GUI 访问或用户监控，请使用以下命令：
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD 提供多种控制级别，包括观察、共享控制和完全控制，且会话在用户密码更改后仍然持续。它允许直接发送 Unix 命令，并以 root 身份执行这些命令，适用于管理用户。任务调度和远程 Spotlight 搜索是显著特性，便于在多台机器上进行远程、低影响的敏感文件搜索。

## Bonjour 协议

Bonjour 是一项由苹果设计的技术，允许 **同一网络上的设备检测彼此提供的服务**。也称为 Rendezvous、**零配置**或 Zeroconf，它使设备能够加入 TCP/IP 网络，**自动选择 IP 地址**，并将其服务广播给其他网络设备。

Bonjour 提供的零配置网络确保设备可以：

- **自动获取 IP 地址**，即使在没有 DHCP 服务器的情况下。
- 执行 **名称到地址的转换**，而无需 DNS 服务器。
- **发现**网络上可用的服务。

使用 Bonjour 的设备将从 **169.254/16 范围**中自我分配一个 IP 地址，并验证其在网络上的唯一性。Mac 维护此子网的路由表条目，可以通过 `netstat -rn | grep 169` 验证。

对于 DNS，Bonjour 利用 **多播 DNS (mDNS) 协议**。mDNS 在 **port 5353/UDP** 上运行，采用 **标准 DNS 查询**，但目标是 **多播地址 224.0.0.251**。这种方法确保网络上所有监听设备都能接收并响应查询，从而促进其记录的更新。

加入网络后，每个设备自我选择一个名称，通常以 **.local** 结尾，该名称可能源自主机名或随机生成。

网络内的服务发现由 **DNS 服务发现 (DNS-SD)** 促进。利用 DNS SRV 记录的格式，DNS-SD 使用 **DNS PTR 记录** 来启用多个服务的列出。寻求特定服务的客户端将请求 `<Service>.<Domain>` 的 PTR 记录，如果该服务在多个主机上可用，则返回格式为 `<Instance>.<Service>.<Domain>` 的 PTR 记录列表。

可以使用 `dns-sd` 工具来 **发现和广告网络服务**。以下是其用法的一些示例：

### 搜索 SSH 服务

要在网络上搜索 SSH 服务，可以使用以下命令：
```bash
dns-sd -B _ssh._tcp
```
此命令启动对 \_ssh.\_tcp 服务的浏览，并输出详细信息，如时间戳、标志、接口、域、服务类型和实例名称。

### 广播 HTTP 服务

要广播 HTTP 服务，您可以使用：
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
此命令在端口 80 上注册一个名为 "Index" 的 HTTP 服务，路径为 `/index.html`。

然后在网络上搜索 HTTP 服务：
```bash
dns-sd -B _http._tcp
```
当服务启动时，它通过多播其存在向子网中的所有设备宣布其可用性。对这些服务感兴趣的设备无需发送请求，只需监听这些公告。

为了提供更友好的界面，可以在苹果应用商店中使用 **Discovery - DNS-SD Browser** 应用程序可视化您本地网络上提供的服务。

或者，可以编写自定义脚本使用 `python-zeroconf` 库浏览和发现服务。 [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) 脚本演示了如何为 `_http._tcp.local.` 服务创建服务浏览器，打印添加或移除的服务：
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
### 禁用 Bonjour

如果出于安全考虑或其他原因需要禁用 Bonjour，可以使用以下命令将其关闭：
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## 参考文献

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
