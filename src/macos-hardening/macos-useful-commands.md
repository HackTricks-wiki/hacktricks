# Nuttige macOS-opdragte

{{#include ../banners/hacktricks-training.md}}

### Outomatiese enumerasiehulpmiddels vir macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Spesifieke macOS-opdragte

Gebruik `sw_vers` vir die macOS-weergawe en bou.<sup>[[2]](#references)</sup> Raadpleeg hardewarewaardes met `sysctl` en geheuebladsystatistieke met `vm_stat` in plaas van die opdragte `/proc/cpuinfo`, `/proc/meminfo` en `free`, wat slegs vir Linux is.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` raadpleeg die Spotlight-metadata-indeks, dus bewys ’n ontbrekende resultaat nie dat ’n lêer afwesig is nie.<sup>[[5]](#references)</sup> Gebruik `find "$HOME" -iname '*password*' 2>/dev/null` om toeganklike paaie in die lêerstelsel te deursoek.<sup>[[11]](#references)</sup> TCC-beskermde gidse kan steeds ontoeganklik wees vir die aanroepende proses.<sup>[[9]](#references)</sup>

Vergelyk vir netwerkverkenning ’n diens se gestoorde proxy-instellings van `networksetup` met die huidige proxy-, DNS- en VPN-toestand van `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> ’n VPN kan ’n proxy-konfigurasie stoot wat via `scutil --proxy` sigbaar is.<sup>[[13]](#references)</sup> ’n Netwerkuitbreiding kan verkeer filter sonder om as ’n konvensionele proxy voor te kom.<sup>[[10]](#references)</sup> Raadpleeg [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) voordat jy aanvaar dat direkte uitgaande verkeer beskikbaar is.

### Skermvaslegging vanaf ’n SSH-sessie

’n Afgeleë shell is nie outomaties deel van die aangemelde gebruiker se GUI-bootstrap nie. As jy die vereiste voorreg en ’n aktiewe GUI-sessie het, identifiseer die korrekte `loginwindow`-PID vir daardie sessie en voer `screencapture` in sy bootstrap met `launchctl bsexec` uit.<sup>[[7]](#references)</sup> Dit neem die Mach-bootstrap- en oudit-sessiekonteks oor, **nie** die proses-UID of TCC Screen Recording-toestemming nie.<sup>[[8]](#references)</sup> ’n Vaslegging kan steeds geweier word of om toestemming vra; sien [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Vinnige anti-analise-/virtualiseringskontrole

Sommige macOS-stealers roep `system_profiler` aan om VM's op te spoor en **staak met 'n kenmerkende uitgangskode (bv. 100)** om sandbox-detonasie te vermy<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Geïnstalleerde sagteware en dienste

Kyk vir **verdagte** geïnstalleerde toepassings en **voorregte** oor die geïnstalleerde hulpbronne:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Gebruikersprosesse

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Skep 'n gebruiker

Sonder aanporings

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers-handleiding](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl-handleiding](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: Bekyk gebruik van virtuele geheue](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind-handleiding](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil-handleiding](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture-handleiding](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl-handleiding](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple-platformsekuriteit](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Santa-dokumentasie vir ontplooiing van netwerkuitbreidings](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find-handleiding](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup-handleiding](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client-administrateurgids](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
