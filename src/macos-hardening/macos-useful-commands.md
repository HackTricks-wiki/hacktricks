# Przydatne polecenia macOS

{{#include ../banners/hacktricks-training.md}}

### Narzędzia do automatycznej enumeracji w macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Konkretne polecenia macOS

Użyj `sw_vers`, aby sprawdzić wydanie i kompilację macOS.<sup>[[2]](#references)</sup> Pobieraj wartości sprzętowe za pomocą `sysctl`, a statystyki stron pamięci za pomocą `vm_stat`, zamiast używać dostępnych wyłącznie w systemie Linux poleceń `/proc/cpuinfo`, `/proc/meminfo` i `free`.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` odpytuje indeks metadanych Spotlight, więc brak wyników nie dowodzi, że plik nie istnieje.<sup>[[5]](#references)</sup> Aby przeszukać dostępne ścieżki w systemie plików, użyj `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Katalogi chronione przez TCC mogą nadal być niedostępne dla wywołującego procesu.<sup>[[9]](#references)</sup>

W ramach rozpoznania sieciowego porównaj zapisane ustawienia proxy usługi z `networksetup` z bieżącym stanem proxy, DNS i VPN odczytanym za pomocą `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> VPN może narzucić konfigurację proxy widoczną przez `scutil --proxy`.<sup>[[13]](#references)</sup> Rozszerzenie sieciowe może filtrować ruch, nie będąc widoczne jako konwencjonalne proxy.<sup>[[10]](#references)</sup> Zobacz [narzędzia obronne macOS](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling), zanim założysz, że bezpośrednie połączenia wychodzące są dostępne.

### Zrzut ekranu z sesji SSH

Zdalna powłoka nie jest automatycznie częścią GUI bootstrap zalogowanego użytkownika. Jeśli masz wymagane uprawnienia i aktywną sesję GUI, znajdź poprawny PID procesu `loginwindow` dla tej sesji i uruchom `screencapture` w jego bootstrapie za pomocą `launchctl bsexec`.<sup>[[7]](#references)</sup> Spowoduje to przejęcie kontekstu Mach bootstrap i sesji audytu, **ale nie** UID procesu ani uprawnienia TCC do nagrywania ekranu.<sup>[[8]](#references)</sup> Zrzut ekranu może nadal zostać zablokowany lub wywołać prośbę o zgodę; zobacz [uprawnienia do przechwytywania ekranu](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Szybkie sprawdzenie anti-analysis / wirtualizacji

Niektóre stealery dla macOS wywołują `system_profiler`, aby wykrywać maszyny wirtualne i **przerywają działanie z odrębnym kodem wyjścia (np. 100)**, by uniknąć detonacji w sandboxie<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Zainstalowane oprogramowanie i usługi

Sprawdź, czy zainstalowane aplikacje są **podejrzane**, oraz sprawdź **uprawnienia** do zainstalowanych zasobów:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Procesy użytkownika

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Utwórz użytkownika

Bez monitów

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025 — rok Infostealera](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Podręcznik Apple sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Podręcznik Apple sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: wyświetlanie wykorzystania pamięci wirtualnej](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Podręcznik Apple mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Podręcznik Apple scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Podręcznik Apple screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Podręcznik Apple launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Bezpieczeństwo platform Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Dokumentacja wdrażania rozszerzenia sieciowego Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Podręcznik Apple find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Podręcznik Apple networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Podręcznik administratora Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
