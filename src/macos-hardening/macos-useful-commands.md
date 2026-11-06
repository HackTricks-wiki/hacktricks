# macOS के उपयोगी कमांड

{{#include ../banners/hacktricks-training.md}}

### MacOS के स्वचालित Enumeration टूल

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### MacOS के विशिष्ट कमांड

macOS रिलीज़ और बिल्ड की जानकारी के लिए `sw_vers` का उपयोग करें।<sup>[[2]](#references)</sup> हार्डवेयर मानों के लिए `sysctl` और memory-page के आँकड़ों के लिए `vm_stat` से पूछताछ करें। Linux-केवल `/proc/cpuinfo`, `/proc/meminfo` और `free` कमांड के बजाय इनका उपयोग करें।<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` Spotlight metadata index को query करता है, इसलिए कोई परिणाम न मिलना यह साबित नहीं करता कि फ़ाइल मौजूद नहीं है।<sup>[[5]](#references)</sup> उपलब्ध paths में filesystem search के लिए, `find "$HOME" -iname '*password*' 2>/dev/null` का उपयोग करें।<sup>[[11]](#references)</sup> TCC-संरक्षित directories फिर भी calling process के लिए अनुपलब्ध हो सकती हैं।<sup>[[9]](#references)</sup>

Network reconnaissance के लिए, `networksetup` से किसी service की stored proxy settings की तुलना `scutil` से मिली मौजूदा proxy, DNS और VPN state से करें।<sup>[[6]](#references)[[12]](#references)</sup> VPN ऐसी proxy configuration लागू कर सकता है जो `scutil --proxy` के ज़रिए दिखाई देती है।<sup>[[13]](#references)</sup> Network extension, पारंपरिक proxy के रूप में दिखाई दिए बिना traffic filter कर सकता है।<sup>[[10]](#references)</sup> यह मानने से पहले कि direct egress उपलब्ध है, [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) देखें।

### SSH session से screen capture

Remote shell अपने-आप logged-in user के GUI bootstrap में शामिल नहीं होता। यदि आपके पास आवश्यक privilege और एक active GUI session है, तो उस session के लिए सही `loginwindow` PID पहचानें और `launchctl bsexec` से उसके bootstrap में `screencapture` चलाएँ।<sup>[[7]](#references)</sup> इससे Mach bootstrap और audit-session context अपनाया जाता है, **न कि** process UID या TCC Screen Recording grant।<sup>[[8]](#references)</sup> फिर भी capture अस्वीकार हो सकता है या consent के लिए prompt दिख सकता है; [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture) देखें।<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### त्वरित anti-analysis / virtualization जाँच

कुछ macOS stealers VMs का पता लगाने के लिए `system_profiler` चलाते हैं और sandbox detonation से बचने के लिए **एक अलग exit code (जैसे, 100) के साथ abort कर देते हैं**<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### इंस्टॉल किए गए सॉफ़्टवेयर और सेवाएँ

इंस्टॉल किए गए **संदिग्ध** एप्लिकेशन और इंस्टॉल किए गए संसाधनों पर **विशेषाधिकारों** की जाँच करें:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### उपयोगकर्ता प्रक्रियाएँ

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### उपयोगकर्ता बनाएँ

बिना प्रॉम्प्ट के

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers मैनुअल](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl मैनुअल](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: वर्चुअल मेमोरी के उपयोग को देखना](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind मैनुअल](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil मैनुअल](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture मैनुअल](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl मैनुअल](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa network extension परिनियोजन दस्तावेज़](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find मैनुअल](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup मैनुअल](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client प्रशासक मार्गदर्शिका](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
