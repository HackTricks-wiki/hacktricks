# macOS Useful Commands

{{#include ../banners/hacktricks-training.md}}

### MacOS Automatic Enumeration Tools

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Specific MacOS Commands

Use `sw_vers` for the macOS release and build.<sup>[[2]](#references)</sup> Query hardware values with `sysctl` and memory-page statistics with `vm_stat` instead of the Linux-only `/proc/cpuinfo`, `/proc/meminfo`, and `free` commands.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` queries the Spotlight metadata index, so a missing result does not prove a file is absent.<sup>[[5]](#references)</sup> For a filesystem search of accessible paths, use `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> TCC-protected directories can still be unavailable to the calling process.<sup>[[9]](#references)</sup>

For network reconnaissance, compare a service's stored proxy settings from `networksetup` with the current proxy, DNS, and VPN state from `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> A VPN can push a proxy configuration that is visible through `scutil --proxy`.<sup>[[13]](#references)</sup> A network extension can filter traffic without appearing as a conventional proxy.<sup>[[10]](#references)</sup> See [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) before assuming direct egress is available.

### Screen capture from an SSH session

A remote shell is not automatically in the logged-in user's GUI bootstrap. If you have the required privilege and an active GUI session, identify the correct `loginwindow` PID for that session and run `screencapture` in its bootstrap with `launchctl bsexec`.<sup>[[7]](#references)</sup> This adopts the Mach bootstrap and audit-session context, **not** the process UID or TCC Screen Recording grant.<sup>[[8]](#references)</sup> A capture can still be denied or prompt for consent; see [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Quick anti-analysis / virtualization check

Some macOS stealers call `system_profiler` to detect VMs and **abort with a distinct exit code (e.g., 100)** to avoid sandbox detonation<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Installed Software & Services

Check for **suspicious** applications installed and **privileges** over the.installed resources:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### User Processes

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Create a user

Without prompts

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers manual](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl manual](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple Viewing Virtual Memory Usage](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind manual](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil manual](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture manual](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl manual](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa network extension deployment documentation](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find manual](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup manual](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client Administrator Guide](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
