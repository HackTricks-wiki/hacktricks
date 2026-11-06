# Comandos útiles de macOS

{{#include ../banners/hacktricks-training.md}}

### Herramientas automáticas de enumeración para MacOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Comandos específicos de MacOS

Usa `sw_vers` para consultar la versión y la compilación de macOS.<sup>[[2]](#references)</sup> Consulta los valores de hardware con `sysctl` y las estadísticas de páginas de memoria con `vm_stat`, en lugar de los comandos `/proc/cpuinfo`, `/proc/meminfo` y `free`, exclusivos de Linux.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` consulta el índice de metadatos de Spotlight, por lo que la ausencia de resultados no demuestra que un archivo no exista.<sup>[[5]](#references)</sup> Para buscar en el sistema de archivos las rutas accesibles, usa `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Los directorios protegidos por TCC aún pueden no estar disponibles para el proceso que realiza la llamada.<sup>[[9]](#references)</sup>

Para el reconocimiento de red, compara la configuración de proxy almacenada de un servicio, obtenida con `networksetup`, con el estado actual del proxy, DNS y VPN, obtenido con `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> Una VPN puede aplicar una configuración de proxy visible mediante `scutil --proxy`.<sup>[[13]](#references)</sup> Una extensión de red puede filtrar el tráfico sin aparecer como un proxy convencional.<sup>[[10]](#references)</sup> Consulta [herramientas defensivas de macOS](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) antes de asumir que hay salida directa disponible.

### Captura de pantalla desde una sesión SSH

Un shell remoto no forma parte automáticamente del bootstrap de la GUI del usuario que inició sesión. Si tienes los privilegios necesarios y hay una sesión de GUI activa, identifica el PID de `loginwindow` correcto para esa sesión y ejecuta `screencapture` en su bootstrap con `launchctl bsexec`.<sup>[[7]](#references)</sup> Esto adopta el contexto de bootstrap de Mach y de la sesión de auditoría, **no** el UID del proceso ni el permiso de grabación de pantalla de TCC.<sup>[[8]](#references)</sup> Aun así, la captura puede denegarse o puede solicitarse consentimiento; consulta [permisos de captura de pantalla](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Comprobación rápida de anti-análisis / virtualización

Algunos stealers de macOS llaman a `system_profiler` para detectar máquinas virtuales y **se abortan con un código de salida específico (p. ej., 100)** para evitar la detonación en sandbox<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Software y servicios instalados

Comprueba si hay aplicaciones **sospechosas** instaladas y los **privilegios** sobre los recursos instalados:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Procesos de usuario

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Crear un usuario

Sin indicaciones

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, el año del Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Manual de Apple sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Manual de Apple sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: visualización del uso de la memoria virtual](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Manual de Apple mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Manual de Apple scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Manual de Apple screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Manual de Apple launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Seguridad de la plataforma Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Documentación de implementación de la extensión de red de Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Manual de Apple find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Manual de Apple networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Guía del administrador de Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
