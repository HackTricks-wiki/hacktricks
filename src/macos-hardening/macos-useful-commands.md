# Comandi utili di macOS

{{#include ../banners/hacktricks-training.md}}

### Strumenti di enumerazione automatica per macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Comandi specifici per macOS

Usa `sw_vers` per conoscere la release e la build di macOS.<sup>[[2]](#references)</sup> Interroga i valori hardware con `sysctl` e le statistiche sulle pagine di memoria con `vm_stat`, anziché usare i comandi disponibili solo su Linux `/proc/cpuinfo`, `/proc/meminfo` e `free`.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` interroga l'indice dei metadati di Spotlight, quindi l'assenza di un risultato non prova che un file non esista.<sup>[[5]](#references)</sup> Per cercare nel filesystem tra i percorsi accessibili, usa `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Le directory protette da TCC potrebbero comunque non essere accessibili al processo chiamante.<sup>[[9]](#references)</sup>

Per la ricognizione di rete, confronta le impostazioni proxy memorizzate per un servizio da `networksetup` con lo stato corrente di proxy, DNS e VPN riportato da `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> Una VPN può applicare una configurazione proxy visibile con `scutil --proxy`.<sup>[[13]](#references)</sup> Un'estensione di rete può filtrare il traffico senza apparire come un proxy convenzionale.<sup>[[10]](#references)</sup> Consulta [macOS defensive tooling](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) prima di presumere che sia disponibile l'uscita diretta verso la rete.

### Acquisizione dello schermo da una sessione SSH

Una shell remota non si trova automaticamente nel bootstrap GUI dell'utente connesso. Se disponi dei privilegi necessari e di una sessione GUI attiva, individua il PID `loginwindow` corretto per quella sessione ed esegui `screencapture` nel suo bootstrap con `launchctl bsexec`.<sup>[[7]](#references)</sup> In questo modo adotti il contesto bootstrap Mach e quello della sessione di audit, **non** l'UID del processo né l'autorizzazione TCC per la registrazione dello schermo.<sup>[[8]](#references)</sup> L'acquisizione può comunque essere negata o richiedere il consenso; consulta [screen-capture permissions](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Controllo rapido anti-analisi / virtualizzazione

Alcuni stealer per macOS chiamano `system_profiler` per rilevare le VM e **terminano con un codice di uscita specifico (ad es. 100)** per evitare la detonazione nella sandbox<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Software e servizi installati

Controlla le applicazioni **sospette** installate e i **privilegi** sulle risorse installate:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Processi utente

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Crea un utente

Senza richieste di conferma

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, l’anno dell’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Manuale Apple di sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Manuale Apple di sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: visualizzazione dell’uso della memoria virtuale](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Manuale Apple di mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Manuale Apple di scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Manuale Apple di screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Manuale Apple di launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Sicurezza delle piattaforme Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Documentazione per la distribuzione dell’estensione di rete di Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Manuale Apple di find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Manuale Apple di networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Guida per gli amministratori di Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
