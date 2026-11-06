# Nützliche macOS-Befehle

{{#include ../banners/hacktricks-training.md}}

### Automatische Enumeration-Tools für macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Spezifische macOS-Befehle

Verwenden Sie `sw_vers` für die macOS-Version und den Build.<sup>[[2]](#references)</sup> Fragen Sie Hardwarewerte mit `sysctl` und Statistiken zu Speicherseiten mit `vm_stat` ab, anstatt die nur unter Linux verfügbaren Befehle `/proc/cpuinfo`, `/proc/meminfo` und `free` zu verwenden.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` fragt den Spotlight-Metadatenindex ab, daher beweist ein fehlender Treffer nicht, dass eine Datei nicht vorhanden ist.<sup>[[5]](#references)</sup> Für eine Dateisystemsuche in zugänglichen Pfaden verwenden Sie `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> TCC-geschützte Verzeichnisse können für den aufrufenden Prozess weiterhin nicht verfügbar sein.<sup>[[9]](#references)</sup>

Vergleichen Sie bei der Netzwerkaufklärung die gespeicherten Proxy-Einstellungen eines Dienstes aus `networksetup` mit dem aktuellen Proxy-, DNS- und VPN-Status aus `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> Ein VPN kann eine Proxy-Konfiguration übertragen, die über `scutil --proxy` sichtbar ist.<sup>[[13]](#references)</sup> Eine Network Extension kann den Datenverkehr filtern, ohne als herkömmlicher Proxy aufzutreten.<sup>[[10]](#references)</sup> Lesen Sie [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling), bevor Sie davon ausgehen, dass direkter Egress verfügbar ist.

### Bildschirmaufnahme aus einer SSH-Sitzung

Eine Remote-Shell befindet sich nicht automatisch im GUI-bootstrap des angemeldeten Benutzers. Wenn Sie über die erforderlichen Berechtigungen und eine aktive GUI-Sitzung verfügen, ermitteln Sie die richtige `loginwindow`-PID für diese Sitzung und führen Sie `screencapture` mit `launchctl bsexec` in deren Bootstrap aus.<sup>[[7]](#references)</sup> Dadurch werden der Mach-bootstrap- und Audit-Session-Kontext übernommen, **nicht** die Prozess-UID oder die TCC-Berechtigung für Screen Recording.<sup>[[8]](#references)</sup> Eine Aufnahme kann weiterhin verweigert werden oder eine Einwilligungsabfrage auslösen; siehe [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Schnelle Anti-Analyse-/Virtualisierungsprüfung

Einige macOS-Stealer rufen `system_profiler` auf, um VMs zu erkennen, und brechen mit einem eindeutigen Exit-Code (z. B. 100) ab, um eine Detonation in der Sandbox zu vermeiden<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Installierte Software & Dienste

Prüfen Sie, ob **verdächtige** Anwendungen installiert sind und welche **Berechtigungen** für die installierten Ressourcen bestehen:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Benutzerprozesse

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Benutzer erstellen

Ohne Eingabeaufforderungen

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers-Handbuch](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl-Handbuch](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: Anzeige der Nutzung des virtuellen Speichers](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind-Handbuch](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil-Handbuch](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture-Handbuch](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl-Handbuch](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple-Plattformsicherheit](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Dokumentation zur Bereitstellung der Santa-Netzwerkerweiterung](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find-Handbuch](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup-Handbuch](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Cisco Secure Client-Administratorhandbuch](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
