# macOS 常用命令

{{#include ../banners/hacktricks-training.md}}

### macOS 自动化枚举工具

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### macOS 专用命令

使用 `sw_vers` 获取 macOS 版本和构建信息。<sup>[[2]](#references)</sup> 使用 `sysctl` 查询硬件值，并使用 `vm_stat` 查询内存页统计信息，而不要使用仅适用于 Linux 的 `/proc/cpuinfo`、`/proc/meminfo` 和 `free` 命令。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
#System info
date
cal
uptime #show time from starting
w #list users
whoami #this user
finger username #info about user
uname -a #Darwin kernel information
sw_vers #macOS version and build
sysctl -n hw.model #Hardware model identifier
sysctl -n hw.memsize #Physical memory in bytes
vm_stat #Memory statistics in pages
df #check disk

launchctl list #List services
atq #List "at" tasks for the user
sysctl -a #List kernel configuration
diskutil list #List connected hard drives
nettop #Monitor network usage of processes in top style

system_profiler SPSoftwareDataType #System info
system_profiler SPPrintersDataType #Printer
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
system_profiler SPDeveloperToolsDataType #Developer tools info
system_profiler SPStartupItemDataType #Startup Items
system_profiler SPNetworkDataType #Network Capabilities
system_profiler SPFirewallDataType #Firewall Status
system_profiler SPNetworkLocationDataType #Known Network
system_profiler SPBluetoothDataType #Bluetooth Info
system_profiler SPEthernetDataType #Ethernet Info
system_profiler SPUSBDataType #USB info
system_profiler SPAirPortDataType #Airport Info


#Searches
mdfind password #Show all the files that contains the word password
mdfind -name password #Search indexed file names for password


#Open any app
open -a <Application Name> --hide #Open app hidden
open some.doc -a TextEdit #Open a file in one application


#Computer doesn't go to sleep
caffeinate &


#Screenshot
# May prompt for Screen Recording permission; -x does not bypass it
screencapture -x /tmp/ss.png #Save screenshot; -x only suppresses the sound


#Get clipboard info
pbpaste


#system_profiler
system_profiler --help #This command without arguments take lot of memory and time.
system_profiler -listDataTypes
system_profiler SPSoftwareDataType SPNetworkDataType


#Network
arp -i en0 -l -a #Print the macOS device's ARP table
lsof -i -P -n | grep LISTEN
smbutil statshares -a #View smb shares mounted to the hard drive

#networksetup - set or view network options: Proxies, FW options and more
networksetup -listallnetworkservices #List network services
networksetup -listallhardwareports #Hardware ports
networksetup -getinfo Wi-Fi #Wi-Fi info
networksetup -getautoproxyurl Wi-Fi #Get proxy URL for Wifi
networksetup -getwebproxy Wi-Fi #Wifi Web proxy
networksetup -getftpproxy Wi-Fi #Wifi ftp proxy
scutil --proxy #Current system proxy configuration
scutil --dns #Current DNS resolver configuration
scutil --nc list #Configured VPN services


#Brew
brew list #List installed
brew search <text> #Search package
brew info <formula>
brew install <formula>
brew uninstall <formula>
brew cleanup #Remove older versions of installed formulae.
brew cleanup <formula> #Remove older versions of specified formula.


#Make the machine talk
say hello -v diego
#spanish: diego, Jorge, Monica
#mexican: Juan, Paulina
#french: Thomas, Amelie

########### High privileges actions
sudo purge #purge RAM
#Sharing preferences
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist (enable ssh)
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist (disable ssh)
#Start apache
sudo apachectl (start|status|restart|stop)
 ##Web folder: /Library/WebServer/Documents/
#Remove DNS cache
dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

`mdfind` 查询 Spotlight 元数据索引，因此没有找到结果并不能证明文件不存在。<sup>[[5]](#references)</sup> 若要搜索可访问路径中的文件系统，请使用 `find "$HOME" -iname '*password*' 2>/dev/null`。<sup>[[11]](#references)</sup> 调用进程仍可能无法访问受 TCC 保护的目录。<sup>[[9]](#references)</sup>

进行网络侦察时，可将 `networksetup` 中存储的服务代理设置与 `scutil` 显示的当前代理、DNS 和 VPN 状态进行对比。<sup>[[6]](#references)[[12]](#references)</sup> VPN 可以推送代理配置，该配置可通过 `scutil --proxy` 查看。<sup>[[13]](#references)</sup> 网络扩展可以过滤流量，但不会显示为传统代理。<sup>[[10]](#references)</sup> 在假定可以直接出站连接之前，请参阅 [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling)。

### 从 SSH 会话进行屏幕捕获

远程 shell 不会自动处于已登录用户的 GUI bootstrap 中。如果你拥有所需权限且有活动的 GUI 会话，请找到该会话对应的 `loginwindow` PID，并使用 `launchctl bsexec` 在其 bootstrap 中运行 `screencapture`。<sup>[[7]](#references)</sup> 这会采用 Mach bootstrap 和审计会话上下文，**但不会**采用进程 UID 或 TCC Screen Recording 授权。<sup>[[8]](#references)</sup> 捕获操作仍可能被拒绝或触发授权提示；请参阅[屏幕捕获权限](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture)。<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### 快速反分析 / 虚拟化检查

一些 macOS stealer 会调用 `system_profiler` 来检测 VM，并以特定退出代码（例如 100）中止运行，以避免在 sandbox 中引爆<sup>[[1]](#references)</sup>：

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### 已安装的软件和服务

检查已安装的**可疑**应用程序，以及对已安装资源的**权限**：

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### 用户进程

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### 创建用户

不提示

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025：信息窃取程序之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers 手册](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl 手册](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple：查看虚拟内存使用情况](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind 手册](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil 手册](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture 手册](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl 手册](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple 平台安全性](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa 网络扩展部署文档](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find 手册](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup 手册](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client 管理员指南](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
