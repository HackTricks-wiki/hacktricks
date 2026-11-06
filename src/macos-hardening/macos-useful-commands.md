# Comandos úteis do macOS

{{#include ../banners/hacktricks-training.md}}

### Ferramentas de enumeração automática do macOS

- **MacPEAS**: [https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- **Metasploit**: [https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/post/osx/gather/enum_osx.rb)
- **SwiftBelt**: [https://github.com/cedowens/SwiftBelt](https://github.com/cedowens/SwiftBelt)

### Comandos específicos do macOS

Use `sw_vers` para consultar a versão e o build do macOS.<sup>[[2]](#references)</sup> Consulte os valores de hardware com `sysctl` e as estatísticas de páginas de memória com `vm_stat`, em vez dos comandos `/proc/cpuinfo`, `/proc/meminfo` e `free`, que são exclusivos do Linux.<sup>[[3]](#references)[[4]](#references)</sup>

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

`mdfind` consulta o índice de metadados do Spotlight, portanto, a ausência de resultados não prova que um arquivo não exista.<sup>[[5]](#references)</sup> Para pesquisar no sistema de arquivos os caminhos acessíveis, use `find "$HOME" -iname '*password*' 2>/dev/null`.<sup>[[11]](#references)</sup> Os diretórios protegidos pelo TCC ainda podem estar indisponíveis para o processo que faz a chamada.<sup>[[9]](#references)</sup>

Para reconhecimento de rede, compare as configurações de proxy armazenadas de um serviço, obtidas com `networksetup`, com o estado atual do proxy, DNS e VPN, obtido com `scutil`.<sup>[[6]](#references)[[12]](#references)</sup> Uma VPN pode aplicar uma configuração de proxy visível por meio de `scutil --proxy`.<sup>[[13]](#references)</sup> Uma extensão de rede pode filtrar o tráfego sem aparecer como um proxy convencional.<sup>[[10]](#references)</sup> Consulte [ferramentas defensivas do macOS](macos-security-and-privilege-escalation/macos-defensive-apps.md#quick-triage-of-defensive-tooling) antes de presumir que a saída direta para a rede esteja disponível.

### Captura de tela de uma sessão SSH

Um shell remoto não está automaticamente no bootstrap da GUI do usuário conectado. Se você tiver o privilégio necessário e houver uma sessão GUI ativa, identifique o PID correto de `loginwindow` para essa sessão e execute `screencapture` no bootstrap dela com `launchctl bsexec`.<sup>[[7]](#references)</sup> Isso adota o contexto de bootstrap do Mach e da sessão de auditoria, **não** o UID do processo nem a permissão de Gravação de Tela do TCC.<sup>[[8]](#references)</sup> A captura ainda pode ser negada ou solicitar consentimento; consulte [permissões de captura de tela](macos-security-and-privilege-escalation/macos-security-protections/macos-input-monitoring-screen-capture-accessibility.md#screen-capture-ktccservicescreencapture).<sup>[[9]](#references)</sup>

```bash
pgrep -fl loginwindow # Identify the loginwindow PID for the target GUI session
LOGINWINDOW_PID=1234 # Replace with that PID
sudo launchctl bsexec "$LOGINWINDOW_PID" /usr/sbin/screencapture -x /tmp/ss.png
```

### Verificação rápida de anti-analysis / virtualização

Alguns stealers para macOS chamam `system_profiler` para detectar VMs e **encerrar com um código de saída distinto (por exemplo, 100)** para evitar a detonação em sandbox<sup>[[1]](#references)</sup>:

```bash
if system_profiler SPHardwareDataType SPDisplaysDataType | grep -Eiq 'qemu|kvm|vmware|virtualbox'; then
  exit 100
fi
```

### Software e serviços instalados

Verifique se há aplicativos **suspeitos** instalados e **privilégios** sobre os recursos instalados:

```
system_profiler SPApplicationsDataType #Installed Apps
system_profiler SPFrameworksDataType #Installed framework
lsappinfo list #Installed Apps
launchctl list #Services
```

### Processos do usuário

```bash
# will print all the running services under that particular user domain.
launchctl print gui/<users UID>

# will print all the running services under root
launchctl print system

# will print detailed information about the specific launch agent. And if it’s not running or you’ve mistyped, you will get some output with a non-zero exit code: Could not find service “com.company.launchagent.label” in domain for login
launchctl print gui/<user's UID>/com.company.launchagent.label
```

### Criar um usuário

Sem prompts

<figure><img src="../images/image (79).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Manual do Apple sw_vers](https://keith.github.io/xcode-man-pages/sw_vers.1.html)
- [3] [Manual do Apple sysctl](https://keith.github.io/xcode-man-pages/sysctl.8.html)
- [4] [Apple: Visualização do uso da memória virtual](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/VMPages.html)
- [5] [Manual do Apple mdfind](https://keith.github.io/xcode-man-pages/mdfind.1.html)
- [6] [Manual do Apple scutil](https://keith.github.io/xcode-man-pages/scutil.8.html)
- [7] [Manual do Apple screencapture](https://keith.github.io/xcode-man-pages/screencapture.1.html)
- [8] [Manual do Apple launchctl](https://keith.github.io/xcode-man-pages/launchctl.1.html)
- [9] [Segurança da Plataforma Apple](https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf)
- [10] [Documentação de implantação da extensão de rede do Santa](https://github.com/northpolesec/santa/blob/main/docs/docs/deployment/profile-network-extension.md)
- [11] [Manual do Apple find](https://keith.github.io/xcode-man-pages/find.1.html)
- [12] [Manual do Apple networksetup](https://keith.github.io/xcode-man-pages/networksetup.8.html)
- [13] [Guia do administrador do Cisco Secure Client](https://www.cisco.com/c/en/us/td/docs/security/vpn_client/anyconnect/Cisco-Secure-Client-5/admin/guide/b-cisco-secure-client-admin-guide-5-1.pdf)
{{#include ../banners/hacktricks-training.md}}
