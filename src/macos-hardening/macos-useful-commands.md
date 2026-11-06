# Korisne macOS komande

{{#include ../banners/hacktricks-training.md}}

### Alati za automatsku enumeraciju na macOS-u

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Specifične macOS komande

Koristite `sw_vers` za izdanje i verziju builda macOS-a.<sup>[[2]](#references)</sup> Vrednosti hardvera proverite pomoću `sysctl`, a statistiku memorijskih stranica pomoću `vm_stat`, umesto komandi `/proc/cpuinfo`, `/proc/meminfo` i `free`, koje su dostupne samo na Linuxu.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` pretražuje Spotlight indeks metapodataka, pa izostanak rezultata ne dokazuje da datoteka ne postoji.<sup>[[5]](#references)</sup> Za pretragu dostupnih putanja u sistemu datoteka koristite `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Direktorijumi zaštićeni putem TCC-a i dalje mogu biti nedostupni procesu koji pokreće komandu.<sup>[[9]](#references)</sup>

Za izviđanje mreže uporedite sačuvana proxy podešavanja usluge, koja prikazuje `networksetup`, sa trenutnim stanjem proxy-ja, DNS-a i VPN-a, koje prikazuje `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> VPN može da nametne proxy konfiguraciju vidljivu putem `scutil --proxy`.<sup>[[13]](#references)</sup> Mrežno proširenje može da filtrira saobraćaj, a da se ne prikazuje kao uobičajeni proxy.<sup>[[10]](#references)</sup> Pre nego što pretpostavite da je direktan izlaz na mrežu dostupan, pogledajte [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling).

### Snimanje ekrana iz SSH sesije

Udaljena ljuska se ne pokreće automatski u GUI bootstrap okruženju prijavljenog korisnika. Ako imate potrebne privilegije i aktivnu GUI sesiju, pronađite odgovarajući PID procesa `loginwindow` za tu sesiju i pokrenite `screencapture` u njenom bootstrap okruženju pomoću `launchctl bsexec`.<sup>[[7]](#references)</sup> Time se preuzima kontekst Mach bootstrap-a i audit sesije, **ali ne** UID procesa niti TCC dozvola za snimanje ekrana.<sup>[[8]](#references)</sup> Snimanje i dalje može biti odbijeno ili može biti zatražen pristanak; pogledajte [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Brza anti-analysis / provera virtuelizacije

Neki macOS stealers pozivaju `system_profiler` da bi otkrili VM-ove i **prekinuli izvršavanje uz poseban izlazni kod (npr. 100)** kako bi izbegli detonaciju u sandbox-u<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Instalirani softver i usluge

Proverite da li su instalirane **sumnjive** aplikacije i da li postoje **privilegije** nad instaliranim resursima:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Korisnički procesi

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Kreiranje korisnika

Bez upita

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, godina infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Apple sw_vers priručnik](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Apple sysctl priručnik](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: Pregled upotrebe virtuelne memorije](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Apple mdfind priručnik](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Apple scutil priručnik](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Apple screencapture priručnik](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Apple launchctl priručnik](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Apple Platform Security](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Dokumentacija za primenu Santa mrežnog proširenja](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Apple find priručnik](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Apple networksetup priručnik](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Vodič za administratore Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
