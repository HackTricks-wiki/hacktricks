# Início

[Você precisa compilá-lo](https://github.com/GhostPack/Seatbelt) ou [usar binários pré-compilados \(por mim\)](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)
```text
SeatbeltNet3.5x64.exe all
SeatbeltNet3.5x64.exe all full #Without filtering
```
Eu realmente gostei da filtragem realizada.

# Verificação

Esta ferramenta é mais orientada para coleta de informações do que para escalonamento de privilégios, mas possui algumas verificações muito boas e procura por algumas senhas.

**SeatBelt.exe system** coleta os seguintes dados do sistema:
```text
BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
UACSystemPolicies     -   UAC system policies via the registry
PowerShellSettings    -   PowerShell versions and security settings
AuditSettings         -   Audit settings via the registry
WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
LSASettings           -   LSA settings (including auth packages)
UserEnvVariables      -   Current user environment variables
SystemEnvVariables    -   Current system environment variables
UserFolders           -   Folders in C:\Users\
NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
InternetSettings      -   Internet settings including proxy configs
LapsSettings          -   LAPS settings, if installed
LocalGroupMembers     -   Members of local admins, RDP, and DCOM
MappedDrives          -   Mapped drives
RDPSessions           -   Current incoming RDP sessions
WMIMappedDrives       -   Mapped drives via WMI
NetworkShares         -   Network shares
FirewallRules         -   Deny firewall rules, "full" dumps all
AntiVirusWMI          -   Registered antivirus (via WMI)
InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
RegistryAutoRuns      -   Registry autoruns
RegistryAutoLogon     -   Registry autologon information
DNSCache              -   DNS cache entries (via WMI)
ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
AllTcpConnections     -   Lists current TCP connections and associated processes
AllUdpConnections     -   Lists current UDP connections and associated processes
NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
  *  If the user is in high integrity, the following additional actions are run:
SysmonConfig          -   Sysmon configuration from the registry
```
**SeatBelt.exe user** coleta os seguintes dados do usuário:
```text
SavedRDPConnections   -   Saved RDP connections
TriageIE              -   Internet Explorer bookmarks and history (last 7 days)
DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
RecentRunCommands     -   Recent "run" commands
PuttySessions         -   Interesting settings from any saved Putty configurations
PuttySSHHostKeys      -   Saved putty SSH host keys
CloudCreds            -   AWS/Google/Azure cloud credential files (SharpCloud)
RecentFiles           -   Parsed "recent files" shortcuts (last 7 days)
MasterKeys            -   List DPAPI master keys
CredFiles             -   List Windows credential DPAPI blobs
RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
  *  If the user is in high integrity, this data is collected for ALL users instead of just the current user
```
Opções de coleção não padrão:
```text
CurrentDomainGroups   -   The current user's local and domain groups
Patches               -   Installed patches via WMI (takes a bit on some systems)
LogonSessions         -   User logon session data
KerberosTGTData       -   ALL TEH TGTZ!
InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
IETabs                -   Open Internet Explorer tabs
TriageChrome          -   Chrome bookmarks and history
TriageFirefox         -   Firefox history (no bookmarks)
RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
4624Events            -   4624 logon events from the security event log
4648Events            -   4648 explicit logon events from the security event log
KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
