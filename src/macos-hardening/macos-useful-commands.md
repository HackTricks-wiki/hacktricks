# macOS 유용한 명령어

{{#include ../banners/hacktricks-training.md}}

### macOS 자동 열거 도구

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### macOS 전용 명령어

macOS 릴리스와 빌드를 확인하려면 `sw_vers`를 사용합니다.<sup>[[2]](#references)</sup> 하드웨어 값은 `sysctl`로, 메모리 페이지 통계는 Linux 전용 명령어인 `/proc/cpuinfo`, `/proc/meminfo`, `free` 대신 `vm_stat`로 조회합니다.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind`는 Spotlight metadata index를 검색하므로, 결과가 없다고 해서 파일이 존재하지 않는 것은 아닙니다.<sup>[[5]](#references)</sup> 접근 가능한 경로를 파일시스템에서 검색하려면 `find "$HOME" -iname '*password*' 2>/dev/null`을 사용하세요.<sup>[[11]](#references)</sup> TCC로 보호되는 디렉터리는 호출 프로세스에서 계속 접근할 수 없을 수 있습니다.<sup>[[9]](#references)</sup>

네트워크 정찰에서는 `networksetup`에 저장된 서비스의 proxy 설정과 `scutil`로 확인한 현재 proxy, DNS, VPN 상태를 비교하세요.<sup>[[6]](#references)[[12]](#references)</sup> VPN은 `scutil --proxy`에서 확인할 수 있는 proxy 구성을 적용할 수 있습니다.<sup>[[13]](#references)</sup> network extension은 일반적인 proxy로 나타나지 않으면서 트래픽을 필터링할 수 있습니다.<sup>[[10]](#references)</sup> 직접 egress가 가능하다고 가정하기 전에 [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling)을 확인하세요.

### SSH 세션에서 화면 캡처

원격 셸이 로그인한 사용자의 GUI bootstrap에 자동으로 포함되는 것은 아닙니다. 필요한 권한이 있고 활성 GUI 세션이 있다면, 해당 세션의 올바른 `loginwindow` PID를 확인하고 `launchctl bsexec`를 사용해 그 세션의 bootstrap에서 `screencapture`를 실행하세요.<sup>[[7]](#references)</sup> 이 방법은 Mach bootstrap 및 audit-session 컨텍스트를 사용하지만, **프로세스 UID나 TCC Screen Recording 권한을 가져오지는 않습니다**.<sup>[[8]](#references)</sup> 캡처가 거부되거나 동의를 요청할 수 있습니다. [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture)를 참조하세요.<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### 빠른 anti-analysis / virtualization 검사

일부 macOS stealer는 VM을 탐지하기 위해 `system_profiler`를 호출하고, sandbox detonation을 피하려고 **고유한 종료 코드(예: 100)로 종료합니다**<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### 설치된 소프트웨어 및 서비스

설치된 애플리케이션 중 **의심스러운** 항목이 있는지 확인하고, 설치된 리소스에 대한 **권한**을 확인합니다:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### 사용자 프로세스

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### 사용자 생성

프롬프트 없이

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025년, Infostealer의 해](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers 매뉴얼](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl 매뉴얼](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple 가상 메모리 사용량 확인](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind 매뉴얼](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil 매뉴얼](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture 매뉴얼](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl 매뉴얼](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple 플랫폼 보안](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa network extension 배포 문서](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find 매뉴얼](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup 매뉴얼](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client 관리자 가이드](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
