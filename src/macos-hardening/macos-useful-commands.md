# macOS の便利なコマンド

{{#include ../banners/hacktricks-training.md}}

### macOS の自動列挙ツール

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### macOS 固有のコマンド

macOS のリリースとビルドを確認するには `sw_vers` を使用します。<sup>[[2]](#references)</sup> ハードウェアの値は `sysctl` で、メモリページの統計情報は `vm_stat` で確認します。Linux 専用の `/proc/cpuinfo`、`/proc/meminfo`、`free` コマンドは使用しません。<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` は Spotlight メタデータインデックスを検索するため、結果が見つからなくてもファイルが存在しない証明にはなりません。<sup>[[5]](#references)</sup> アクセス可能なパスをファイルシステム上で検索するには、`find "$HOME" -iname '*password*' 2>/dev/null` を使用します。<sup>[[11]](#references)</sup> TCC で保護されたディレクトリは、呼び出し元のプロセスから引き続きアクセスできない場合があります。<sup>[[9]](#references)</sup>

ネットワークの偵察では、`networksetup` に保存されたサービスのプロキシ設定と、`scutil` で確認できる現在のプロキシ、DNS、VPN の状態を比較します。<sup>[[6]](#references)[[12]](#references)</sup> VPN によってプッシュされたプロキシ設定は、`scutil --proxy` で確認できる場合があります。<sup>[[13]](#references)</sup> ネットワーク拡張機能は、従来型のプロキシとして表示されずにトラフィックをフィルタリングすることがあります。<sup>[[10]](#references)</sup> 直接の外部通信が可能だと決めつける前に、[macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) を参照してください。

### SSH セッションからの画面キャプチャ

リモートシェルが、ログイン中のユーザーの GUI bootstrap に自動的に属するわけではありません。必要な権限があり、アクティブな GUI セッションもある場合は、そのセッションに対応する正しい `loginwindow` PID を特定し、`launchctl bsexec` を使って、その bootstrap 内で `screencapture` を実行します。<sup>[[7]](#references)</sup> これは Mach bootstrap と監査セッションのコンテキストを引き継ぐものであり、**プロセスの UID や TCC の Screen Recording 許可を引き継ぐものではありません**。<sup>[[8]](#references)</sup> それでもキャプチャが拒否されたり、許可を求められたりすることがあります。[画面キャプチャのアクセス許可](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture)を参照してください。<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### 簡易 anti-analysis / 仮想化チェック

一部の macOS stealer は、VM を検出するために `system_profiler` を呼び出し、sandbox detonation を回避するために固有の終了コード（例: 100）で終了します<sup>[[1]](#references)</sup>：

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### インストール済みソフトウェアとサービス

インストール済みの**疑わしい**アプリケーションと、インストール済みリソースに対する**権限**を確認します。

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### ユーザープロセス

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### ユーザーを作成

プロンプトを表示せずに

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers マニュアル](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl マニュアル](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple 仮想メモリ使用状況の確認](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind マニュアル](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil マニュアル](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture マニュアル](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl マニュアル](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa network extension の導入ドキュメント](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find マニュアル](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup マニュアル](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client 管理者ガイド](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
