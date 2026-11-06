# Commandes utiles de macOS

{{#include ../banners/hacktricks-training.md}}

### Outils d’énumération automatique de macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Commandes spécifiques à macOS

Utilisez `sw_vers` pour obtenir la version et le numéro de build de macOS.<sup>[[2]](#references)</sup> Interrogez les valeurs matérielles avec `sysctl` et les statistiques des pages mémoire avec `vm_stat`, plutôt qu’avec les commandes Linux uniquement `/proc/cpuinfo`, `/proc/meminfo` et `free`.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` interroge l'index de métadonnées Spotlight ; l'absence de résultat ne prouve donc pas qu'un fichier est absent.<sup>[[5]](#references)</sup> Pour rechercher dans les chemins du système de fichiers auxquels vous avez accès, utilisez `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Les répertoires protégés par TCC peuvent tout de même être indisponibles pour le processus appelant.<sup>[[9]](#references)</sup>

Pour la reconnaissance réseau, comparez les paramètres de proxy enregistrés d'un service, obtenus avec `networksetup`, à l'état actuel du proxy, du DNS et du VPN, obtenu avec `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> Un VPN peut imposer une configuration de proxy visible avec `scutil --proxy`.<sup>[[13]](#references)</sup> Une extension réseau peut filtrer le trafic sans apparaître comme un proxy classique.<sup>[[10]](#references)</sup> Consultez [les outils de défense de macOS](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) avant de supposer qu'une sortie directe du trafic est possible.

### Capture d'écran depuis une session SSH

Un shell distant ne se trouve pas automatiquement dans le bootstrap GUI de l'utilisateur connecté. Si vous disposez des privilèges requis et qu'une session GUI est active, identifiez le PID `loginwindow` correspondant à cette session et exécutez `screencapture` dans son bootstrap avec `launchctl bsexec`.<sup>[[7]](#references)</sup> Cela adopte le contexte bootstrap Mach et celui de la session d'audit, **mais pas** l'UID du processus ni l'autorisation TCC d'enregistrement de l'écran.<sup>[[8]](#references)</sup> Une capture peut tout de même être refusée ou nécessiter un consentement ; consultez [les autorisations de capture d'écran](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Vérification rapide anti-analyse / virtualisation

Certains infostealers macOS appellent `system_profiler` pour détecter les machines virtuelles et **interrompre leur exécution avec un code de sortie distinct (p. ex., 100)** afin d’éviter la détonation dans un sandbox<sup>[[1]](#references)</sup> :

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Logiciels et services installés

Vérifiez les applications **suspectes** installées et les **privilèges** sur les ressources installées :

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Processus utilisateur

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Créer un utilisateur

Sans invite

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Manuel Apple sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Manuel Apple sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple : consultation de l’utilisation de la mémoire virtuelle](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Manuel Apple mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Manuel Apple scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Manuel Apple screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Manuel Apple launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Sécurité des plateformes Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Documentation de déploiement de l’extension réseau Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Manuel Apple find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Manuel Apple networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Guide de l’administrateur Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
