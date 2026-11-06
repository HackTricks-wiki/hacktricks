# Các lệnh hữu ích trên macOS

{{#include ../banners/hacktricks-training.md}}

### Công cụ liệt kê tự động trên macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Các lệnh macOS cụ thể

Dùng `sw_vers` để xem phiên bản phát hành và bản dựng macOS.<sup>[[2]](#references)</sup> Truy vấn thông tin phần cứng bằng `sysctl` và số liệu thống kê về trang bộ nhớ bằng `vm_stat` thay vì các lệnh chỉ có trên Linux như `/proc/cpuinfo`, `/proc/meminfo` và `free`.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` truy vấn chỉ mục metadata của Spotlight, vì vậy không tìm thấy kết quả không chứng minh rằng tệp không tồn tại.<sup>[[5]](#references)</sup> Để tìm kiếm trong hệ thống tệp ở các đường dẫn có thể truy cập, hãy dùng `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Các thư mục được TCC bảo vệ vẫn có thể không truy cập được từ tiến trình gọi lệnh.<sup>[[9]](#references)</sup>

Để trinh sát mạng, hãy so sánh cài đặt proxy được lưu cho một dịch vụ từ `networksetup` với trạng thái proxy, DNS và VPN hiện tại từ `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> VPN có thể đẩy một cấu hình proxy hiển thị qua `scutil --proxy`.<sup>[[13]](#references)</sup> Network extension có thể lọc lưu lượng mà không xuất hiện như một proxy thông thường.<sup>[[10]](#references)</sup> Xem [công cụ phòng thủ macOS](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) trước khi cho rằng có thể kết nối trực tiếp ra ngoài.

### Chụp màn hình từ phiên SSH

Một shell từ xa không tự động thuộc GUI bootstrap của người dùng đang đăng nhập. Nếu có đủ quyền và một phiên GUI đang hoạt động, hãy xác định PID `loginwindow` chính xác của phiên đó rồi chạy `screencapture` trong bootstrap của phiên bằng `launchctl bsexec`.<sup>[[7]](#references)</sup> Cách này sử dụng ngữ cảnh Mach bootstrap và audit-session, **không** sử dụng UID của tiến trình hay quyền TCC Screen Recording.<sup>[[8]](#references)</sup> Việc chụp màn hình vẫn có thể bị từ chối hoặc yêu cầu xác nhận; xem [quyền chụp màn hình](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Kiểm tra nhanh chống phân tích / ảo hóa

Một số stealer trên macOS gọi `system_profiler` để phát hiện VM và **thoát với mã thoát riêng biệt (ví dụ: 100)** nhằm tránh bị kích hoạt trong sandbox<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Phần mềm & Dịch vụ đã cài đặt

Kiểm tra các ứng dụng **đáng ngờ** đã cài đặt và **quyền hạn** đối với các tài nguyên đã cài đặt:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Tiến trình người dùng

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Tạo người dùng

Không cần lời nhắc

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, năm của Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Tài liệu hướng dẫn Apple sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Tài liệu hướng dẫn Apple sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: Xem mức sử dụng bộ nhớ ảo](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Tài liệu hướng dẫn Apple mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Tài liệu hướng dẫn Apple scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Tài liệu hướng dẫn Apple screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Tài liệu hướng dẫn Apple launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Bảo mật nền tảng Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Tài liệu triển khai tiện ích mở rộng mạng Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Tài liệu hướng dẫn Apple find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Tài liệu hướng dẫn Apple networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Hướng dẫn quản trị Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
